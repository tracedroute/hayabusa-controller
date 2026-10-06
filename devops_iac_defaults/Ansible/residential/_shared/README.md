# Residential API shared dependencies

Device API folders keep a local `requirements.txt` path (tools expect it).
Identical generic API stacks are **symlinks** into this directory so one edit
updates every vendor. Vendor-specific stacks (Verizon, TP-Link switch tool)
use their own shared files.

Do not delete per-device API scripts when changing dependencies — only retarget
the symlink or edit the shared file.
