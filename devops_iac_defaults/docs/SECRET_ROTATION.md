# Secret rotation (residential API keys)

## What happened

Residential device API `.env` files (including `API_KEY` values) were briefly present in this
repository’s git history. They were:

1. Removed from the `main` tip
2. Purged from git history (`git filter-repo` on `**/.env`)
3. Blocked from returning via `.gitignore` + CI (`check_iac_tree` fails on tracked `.env`)

## What you should do

Treat any `API_KEY` that ever lived in those `.env` files as **compromised**:

1. Regenerate keys for each residential API you actually run (new random value in local `.env`).
2. Prefer copying from `.env.example` (secrets blank) then fill locally — never commit `.env`.
3. If a key was reused outside this lab, rotate it there too.
4. After cloning freshly, confirm history is clean:

```bash
git log --all --full-history -- '**/.env' | head
# expect empty
```

## Local files

Operator machines may still have `.env` on disk (gitignored). That is fine for lab use;
rotate the `API_KEY` values anyway if this repo was ever shared or public.
