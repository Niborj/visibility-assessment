# Publishing And Runtime Notes

This repository is publishable as a normal GitHub source repository, but it is not a GitHub Pages site.

The dashboard uses the local Node proxy in `server.mjs` to forward GraphQL requests to Cato securely from the browser session. Because of that, the project should be treated as a small Node application rather than a static site.

## Publish To GitHub

1. Initialize the repository if needed.
2. Review `.gitignore` to confirm only the product files are included.
3. Push the repository to GitHub as a normal source repo.

## Run Locally

```bash
npm start
```

Then open:

```text
http://localhost:3080
```

## Host Beyond Local Use

If you ever want to host this outside your laptop, deploy it to a platform that can run a small Node process, then keep the same request flow through `server.mjs`.

Examples:

- Render
- Railway
- Fly.io
- A small internal VM or container

## Do Not Use Static Hosting

Do not publish this app to GitHub Pages, Netlify Drop, or other static-only hosting unless you first replace the local proxy with a proper server-side API layer.
