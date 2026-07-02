# zorro-adv-vuln-code

⚠️ **Intentionally vulnerable. Do NOT deploy.** For [Zorro Security](https://zorrosecurity.com) scan validation only.

All secrets are FAKE/example values. Malicious patterns are inert fixtures.

**Source:** `testdata/adversarial/vuln-code` in [zorrosecurity/zorro](https://github.com/zorrosecurity/zorro)

## CI — Zorro PR Guard + Pipeline Agent

Every push/PR runs:

- **Supply Agent** — zorrod scan + zorro.yml policy + evidence upload
- **Pipeline Agent** — in-CI redacted scan

Workflows call [zorro-github-actions](https://github.com/public-zorro-security-org-vulnerability/zorro-github-actions).

```bash
# Org secrets (Settings → Secrets → Actions):
#   ZORRO_API_KEY          — required
#   ZORRO_SDK_TOKEN        — if zorrosecurity/zorro is private
#   ZORRO_AGENT_TOKEN      — optional pipeline ingest
```

## Scan me locally

```bash
go run ./cmd/zorrod scan --target . --profile deep
```

## Org

Part of [public-zorro-security-org-vulnerability](https://github.com/public-zorro-security-org-vulnerability) public vulnerability corpus.
