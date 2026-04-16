import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const port = Number(process.env.PORT || 3080);
const host = process.env.HOST || "127.0.0.1";

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".pdf": "application/pdf",
  ".txt": "text/plain; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

    if (request.method === "POST" && url.pathname === "/api/graphql") {
      await handleGraphqlProxy(request, response);
      return;
    }

    if (request.method === "GET" && url.pathname === "/health") {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }

    const filePath = resolveStaticPath(url.pathname);
    const file = await readFile(filePath);
    const extension = path.extname(filePath).toLowerCase();

    response.writeHead(200, {
      "Content-Type": mimeTypes[extension] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    response.end(file);
  } catch (error) {
    const message = error?.code === "ENOENT" ? "File not found." : error.message || "Internal server error.";
    const status = error?.code === "ENOENT" ? 404 : 500;
    sendJson(response, status, { error: message });
  }
})
  .listen(port, host, () => {
    console.log(`Cato AI visibility app running at http://${host}:${port}`);
  })
  .on("error", (error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  });

function resolveStaticPath(pathname) {
  const normalized = pathname === "/" ? "/index.html" : pathname;
  const safePath = path.normalize(normalized).replace(/^(\.\.(\/|\\|$))+/, "");
  return path.join(__dirname, safePath);
}

async function handleGraphqlProxy(request, response) {
  const body = await readRequestBody(request);
  const { endpoint, apiKey, query, variables } = JSON.parse(body || "{}");

  if (!endpoint || !apiKey || !query) {
    sendJson(response, 400, { error: "endpoint, apiKey, and query are required." });
    return;
  }

  const url = new URL(endpoint);
  if (url.protocol !== "https:" || !/^api(?:\.[a-z0-9-]+)?\.catonetworks\.com$/i.test(url.hostname)) {
    sendJson(response, 400, { error: "Only Cato API HTTPS endpoints are allowed." });
    return;
  }

  const upstream = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
    },
    body: JSON.stringify({
      query,
      variables,
    }),
  });

  const payloadText = await upstream.text();
  response.writeHead(upstream.status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(payloadText);
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";

    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large."));
      }
    });

    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}
