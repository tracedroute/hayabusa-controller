# templates/

Drop OpenTofu / cloud-init / config templates here. Reference them from
modules with:

```hcl
data "local_file" "user_data" {
  filename = "${path.root}/../../templates/cloud-init.user-data.yaml.tpl"
}
```

or render with `templatefile()` for variable substitution.
