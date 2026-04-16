# Cato AI Security Visibility Assessment

This is a local internal tool for running a one-account-at-a-time AI Security visibility assessment for Cato customers.

It accepts a customer-specific read-only Cato API key, pulls the relevant analytics through GraphQL, and turns the results into an executive-style dashboard that is friendly to print-to-PDF workflows.

## What it does

- Runs locally with a tiny built-in Node proxy and no external dependencies
- Lets you change the API key per customer account without editing code
- Supports custom assessment date ranges
- Builds a customer-facing report with optional anonymization for users and devices
- Separates setup and report output into dedicated `Configure` and `Dashboard Report` tabs
- Includes a copy-ready PowerShell collector so internal users can pull the core assessment datasets directly outside the UI, with interactive prompts and per-dataset JSON output
- Highlights:
  - detected AI applications across all visible AI variants, not only a narrow prompt-tool subset
  - free, paid, enterprise, and API or platform editions when the application name exposes that split
  - web assistants, AI-enabled coding tools, and managed AI platform or API activity
  - top users, devices, and access locations
  - AI traffic and interaction volume
  - shadow AI based on the approved-app list plus sanctioning signals
  - action-level AI security evidence from `events`, including allowed or blocked decisions where the tenant exposes them
  - optional prompt topic or intent signals when the public API exposes them for the selected timeframe
  - a more CISO-oriented PDF-friendly layout with visual KPI cards, executive proof points, and clearer plain-English access-pattern framing
- Exports the current assessment as JSON and is styled for browser `Print / PDF` in a landscape, print-friendly layout

## Run it

From this folder:

```bash
npm start
```

Then open:

```text
http://localhost:3080
```

## Inputs you need

- Customer label
- CMA account ID
- Customer-specific read-only API key
- Optional CMA prefix if the account uses a regional endpoint such as `us1`
  - In most cases the shared endpoint `https://api.catonetworks.com/api/v1/graphql2` works fine. The app and PowerShell collector both retry that shared endpoint automatically if an override fails.
- Start and end dates
- Approved AI applications for the customer

## Notes

- The API key is not persisted to local storage. You add it per session.
- The app uses a local proxy route so the browser does not have to call the Cato API directly.
- Some Cato analytics fields are Beta and can vary by account. The UI surfaces partial results with warnings instead of failing silently.
- Prompt-level visibility is best-effort in this MVP. The strongest public-API story is usually AI app discovery, user and location spread, governance gaps, and action-level security evidence.
- Raw prompt text is not assumed to be available. The app prioritizes topic, intent, detection name, and policy metadata where the public API exposes them, but some tenants only return application plus action-level evidence.
- The generated PowerShell collector writes separate JSON files for config, summary, applications, timeseries, snapshot, users, devices, sites, locations, detections, prompt metadata, and the combined assessment export.
- AI discovery is broader than the editable hint list: the app also uses AI-related categories and name heuristics so it can capture more than a hand-curated subset of tools.
- AI proxy visibility is inferred from detected application labels such as API, Bedrock, Vertex AI, Azure OpenAI, OpenRouter, and similar patterns.
- Access location coverage is best-effort and depends on which location-oriented dimensions the account exposes through `appStats`.
- `Claude Code` and similar tools may still be classified under broader application labels depending on how the account sees the traffic, so the tracked AI app list remains editable.

## Cato references used

- [Cato GraphQL API Reference](https://api.catonetworks.com/documentation/)
- [What is the Cato API](https://support.catonetworks.com/hc/en-us/articles/20564679978397-What-is-the-Cato-API)
- [Cato Read Only API - appStats](https://support.catonetworks.com/hc/en-us/articles/9086167606045-Cato-Read-Only-API-appStats)
- [Cato Read Only API - events](https://support.catonetworks.com/hc/en-us/articles/9797533882653-Cato-Read-Only-API-events)
- [AI You Use - Monitoring and Analytics](https://support.catonetworks.com/hc/en-us/articles/34808518412445-AI-You-Use-Monitoring-and-Analytics)
