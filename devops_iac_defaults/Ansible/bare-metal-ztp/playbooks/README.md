# Bare metal ZTP — playbooks

PXE / iPXE / image-stage playbooks for hosts with **no OS yet**. Use Fleet **Incoming** to pick MAC/IP and a catalog recipe, then extend scripts here.

Recipe snippets live in `../recipes/`.

## Pixiecore + Fleet intent
Fleet **Record intent** writes `bare_metal_intents.json` (see `PEREGRINE_BARE_METAL_INTENTS_FILE`). On `/api/ztp/pixie/v1/boot/<mac>`, Peregrine picks the Pixie profile whose `recipe_id`, `id`, or `name` matches that intent **before** falling back to per-MAC `macs` lists or `default_profile`. Optional: set `append_recipe_to_cmdline: true` under `pixie` (or on a profile) to append `peregrine_ztp_recipe=<id>` to the kernel cmdline.

## Windows with Cloudbase-Init
Use cloud-ready Windows images with Cloudbase-Init; provision metadata via config drive / user-data, then first boot applies network, users, and scripts.
Typical lab flow: PXE into WinPE or a small Linux rescue image, pull a cloud-ready `.qcow2` / `.raw` image to disk, attach a **ConfigDrive** (ISO or partition) with `unattend.xml` / metadata, reboot; Cloudbase-Init applies settings on first boot.
Pre-built trial images exist from Cloudbase Solutions; Azure/AWS marketplace images may include Cloudbase-Init; golden images via Cloudbase Imaging Tools + Sysprep are common for repeatability.
