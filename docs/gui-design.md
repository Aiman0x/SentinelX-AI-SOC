# SentinelX — GUI Design & Status

## 1. Goal

A professional dark SOC interface (black / red / gold) for monitoring security findings, investigating incidents, reviewing evidence, managing assets and rules, configuring defensive tools, and eventually receiving verified AI-assisted guidance.

The GUI supports two modes:
- **Demo mode:** local sample data, clearly labelled.
- **Backend mode:** authenticated read data through the Cloudflare Worker and ActivePieces workflows. This mode becomes available only after the Worker is deployed and `VITE_API_BASE_URL` is configured.

## 2. Palette

| Token | Hex | Use |
|---|---|---|
| Background | `#090909` | App background |
| Sidebar | `#0D0D0D` | Navigation |
| Panel / Elevated | `#141414` / `#1B1B1B` | Cards, inputs |
| Border | `#292929` | Dividers |
| Red / Dark red | `#E53935` / `#8F1D1D` | Critical, key actions, selected nav |
| Gold | `#D4AF37` | Identity, accents, demo labels |
| Text / Secondary | `#F3F3F3` / `#969696` | Typography |
| Green / Amber | `#43B581` / `#F0A83C` | Verified-healthy / warning only |

No blue theme, no white backgrounds. Colours live in `tailwind.config.js` under `sx.*`.

## 3. Structure

```text
src/
  components/{layout,dashboard,alerts,cases,investigation,common}
  pages/            one file per screen
  data/             sample data used only through services
  services/         API client, data mappers and data-access services
  hooks/            useData, useAlerts, useCases, useLocalStore
  context/          app state and analyst authentication
  types/ utils/
cloudflare-worker/
  src/index.ts      authenticated API gateway and encrypted integration config
  wrangler.toml     rate-limit and Workers KV bindings
```

When `VITE_API_BASE_URL` is set, backend-aware services use the Worker API. The browser never receives ActivePieces webhook URLs, bridge credentials, or tool passwords.

## 4. Feature matrix

| Feature | Demo mode | Backend foundation |
|---|---|---|
| Navigation, responsive layout | Working | Working |
| Alerts and alert details | Sample data, local demo actions | ActivePieces findings, read-only |
| Cases | Local demo create/notes/status | ActivePieces case records, read-only |
| Investigation | Template/demo analyst assistant | Correlation records and evidence references; not an AI verdict |
| Assets | Local demo registration | Backend inventory, read-only |
| Integrations | Sample status; secret inputs disabled | Encrypted configuration save for Wazuh, Sysmon, ClamAV, YARA, Suricata and Zeek |
| ActivePieces status | Sample | Successful gateway read request can verify API reachability |
| Integration health checks | Cannot verify | Tool-specific adapters still pending |
| Detection rules | Local draft editor | Backend rule registry, read-only |
| Playbooks | Workflow designs and approval simulation | Execution not exposed |
| Audit logs | Sample records | ActivePieces audit records, read-only |
| Security trend chart | Sample chart | Live aggregation API pending |
| Authentication | Demo mode | Shared analyst password + signed HttpOnly session in Worker source; not deployed |
| RBAC / multiple analysts | Not implemented | Future work |

## 5. Backend integration foundation

- `GET /api/alerts`, `/cases`, `/investigations`, `/evidence`, `/audit`, `/assets`, `/rules`, and `/integrations` proxy to authenticated ActivePieces read workflows.
- `POST /api/integrations/{id}/config` saves allowlisted configuration encrypted with AES-256-GCM in a dedicated Workers KV namespace.
- Case, asset, and rule write endpoints are not implemented.
- Tool-specific health checks are not implemented; a saved configuration is not a connected tool.
- The Worker and GUI connection are not deployed yet.

## 6. Remaining work

1. Complete validation of the GUI build and Worker bundle.
2. Rotate the exposed development bridge key and configure the eight actual ActivePieces webhook URLs as Worker Secrets.
3. Generate and configure the analyst password hash, session signing secret, and AES encryption key.
4. Deploy the Worker and verify browser session behavior before setting `VITE_API_BASE_URL`.
5. Add tool adapters and health-check workflows.
6. Add secure write APIs for cases, assets, rules, and analyst notes.
7. Connect and verify the AI investigation service and real authorized telemetry.
8. Add approval-gated, audited response workflows.

## 7. Accessibility

Skip link, labelled controls, `aria-sort`, `aria-pressed`, `aria-current`, focus-visible outlines, Escape closes dialogs, and reduced-motion support.
