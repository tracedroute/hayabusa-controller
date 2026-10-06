# environments/dev

Self-contained OpenTofu root for the **dev** environment.

## Run

```sh
cd environments/dev
tofu init
tofu plan -var-file=../../common.tfvars
tofu apply -var-file=../../common.tfvars
```

`terraform.tfvars` in this directory is loaded automatically by OpenTofu.
`../../common.tfvars` carries values shared with other envs.

State lives in this directory at `./terraform.tfstate` unless you uncomment
the remote backend block in `backend.tf`.

## What's wired up

The default scaffold only uses the `null` + `local` providers, so it can
run end-to-end with no cloud credentials. The `module "example"` call
writes a rendered inventory file under `./out/` for inspection.
