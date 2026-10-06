# Residential device API skeleton

Reference FastAPI layout for **new** router/switch APIs. Existing `*-router-api` / `*-switch-api`
trees are working scaffolds — do not overwrite them with this skeleton.

Use:

```bash
python3 scripts/scaffold_residential_api.py \
  --kind routers --vendor example-co --slug example-widget-router-api \
  --title "Example Co Widget"
```
