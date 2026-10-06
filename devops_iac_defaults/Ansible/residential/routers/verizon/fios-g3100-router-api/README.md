# Verizon Fios G3100 API (100% UI backend via `/ui/*`)

This service wraps the G3100 local web UI.

## Auth

Send your API key in `X-API-Key`.

## High-level routes (already implemented)

- `GET /health`
- `GET /router/info`
- `GET /auth/status`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /status`
- `GET /devices`
- `GET /wifi`
- `GET /network`
- `GET /dns`, `POST /dns`, `DELETE /dns/{hostname}`
- `GET /port-forward`, `POST /port-forward`, `DELETE /port-forward/{rule_id}`
- `GET /cgi` and `GET /cgi/{name}` (raw CGI data used by the web UI)

## 100% capability: execute the router UI backend

These endpoints let you run the same backend operations the web UI sends:

- `GET /ui/apply-token`
  - Returns the apply token used by the router.
- `POST /ui/db`
  - Calls `/db.cgi` with an arbitrary UI payload (type/to/body).
  - Safety: **requires** `confirm: true`.
- `POST /ui/apply-abstract`
  - Calls `/apply_abstract.cgi` with arbitrary form fields (cmd/cmdparam/token/etc).
  - Safety: **requires** `confirm: true`.

### Example safety guard

`confirm: false` returns `400`.
`confirm: true` runs the backend call.

