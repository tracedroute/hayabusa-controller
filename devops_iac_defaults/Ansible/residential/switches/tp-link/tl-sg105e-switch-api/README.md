# TP-Link TL-SG105E Switch API (100% via `/rpc`)

This service uses `tplink-tool` (Easy Smart / Easy Smart Configuration) to access the switch management web UI.

## Auth

- Send `X-API-Key` on protected routes.

## Implemented read endpoints

- `GET /health`
- `GET /system`
- `GET /ports`, `GET /ports/statistics`
- `GET /vlans/dot1q`, `GET /vlans/port`
- `GET /igmp`, `GET /qos`
- `GET /mirror`

## 100% capability: method RPC

`POST /rpc`

Request:

- `method`: a `tplink_tool` method name (e.g. `set_pvid`, `set_port`, `add_dot1q_vlan`, `save_config`, ...)
- `params`: JSON object of keyword arguments
- `confirm`: required for mutating/destructive calls (e.g. `factory_reset`, `reboot`, `save_config`, ...)

Safety rules:

- Read-style calls (`get_*`, `list_*`) are allowed with `confirm: false`.
- Mutating calls are blocked unless `confirm: true`.

