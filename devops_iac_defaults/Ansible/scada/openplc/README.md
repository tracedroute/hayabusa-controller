# OpenPLC workspace

Tenant-scoped OpenPLC Editor project files live here. This directory is separate for each Hayabusa user and each organization workspace.

- `programs/`: IEC 61131-3 Structured Text / Ladder project sources you edit in the Graphical View or console.
- `generated/`: generated build artifacts or exports from OpenPLC Editor.
- `libraries/`: reusable function blocks and vendor libraries.

OpenPLC Editor is installed in the container at `/opt/openplc-editor` with a launcher at `/usr/local/bin/openplc-editor`.
