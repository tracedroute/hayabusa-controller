# modules/example

Generic, credential-free example module that demonstrates the project
conventions:

- Inputs: project / environment / region / node_count / tags
- Uses only `null_resource` and `local_file` -- no cloud calls
- Renders a simple inventory file to `./out/` in the calling root

Replace this module with a real one (network, vm, k8s, etc.) when you
wire the project to infrastructure.
