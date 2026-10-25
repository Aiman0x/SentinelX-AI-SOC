# SentinelX — GUI Design & Status

## 1. Goal
A professional, dark, cinematic SOC interface (black / red / gold) that lets an analyst monitor alerts, investigate incidents, review assets, manage rules and playbooks, and (later) receive AI-assisted guidance. The GUI is a **frontend prototype** running on demo data.

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
```
src/
  components/{layout,dashboard,alerts,cases,investigation,common}
  pages/            one file per screen (+ NotFound)
  data/             demo data ONLY (never imported by components directly except via services)
  services/         apiClient + alerts/cases/integrations/misc services (data-access layer)
  hooks/            useData, useAlerts, useCases, useLocalStore
  context/          AppContext (sidebar, toasts, alert drawer, refresh)
  types/ utils/
```
UI components never read demo files directly; they go through `services/`. When `VITE_API_BASE_URL` is set, services call the backend instead of using demo data.

## 4. Feature matrix
| Feature | Works in prototype | Needs backend |
|---|---|---|
| Navigation, collapsible sidebar, responsive layout | ✅ | |
| Alert search / filter / sort / pagination / drawer | ✅ (demo data) | Real alert feed |
| Create case, notes, status, assignee | ✅ (browser storage) | Secure database + auth |
| Investigation timeline & evidence view | ✅ (demo data) | Real correlation |
| *Generate Summary* | ✅ template-based, no AI | AI analysis service |
| *Export Report* | ✅ markdown from on-screen data | Signed/stored reports |
| Add asset | ✅ registers locally only | Verified telemetry |
| Integration config | ✅ non-secret fields only | Secrets store, health checks |
| *Test Connection* | ❌ reports "cannot verify" | Server-side health check |
| Rule validate / deploy | ❌ | Wazuh / ActivePieces deployment |
| Playbook execution / disruptive actions | ❌ simulation only | Authorised integration + approval flow |
| Audit logs | Sample records | Server-generated audit trail |
| Authentication / RBAC | ❌ | Identity provider |

## 5. Connecting a backend later (Phase 4–5)
1. Build an API (suggested endpoints: `GET /api/alerts`, `GET /api/cases`, `POST /api/integrations/:id/test`).
2. Set `VITE_API_BASE_URL` in `.env.local`.
3. Authenticate with HttpOnly session cookies; keep ActivePieces webhook secrets and Wazuh credentials on the server.
4. Replace the remaining demo services (`casesService`, `miscService`) with API calls — components do not need to change.

## 6. Accessibility
Skip link, labelled controls, `aria-sort`, `aria-pressed`, `aria-current`, focus-visible outlines, Escape closes dialogs, reduced-motion support.
