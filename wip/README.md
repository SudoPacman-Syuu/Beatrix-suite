# Work in progress

Modules that are built (or partly built) but **not yet wired into Beatrix**. They're parked here —
tracked in git so they can't get lost again — until they're finished and moved back into the package.
Nothing in this folder is imported by the suite or the CLI, and it is **not** part of the installed
package (it lives outside `beatrix/`).

| Module | What it is | Intended home | Status |
|--------|-----------|---------------|--------|
| `privilege_graph.py` | A BloodHound-inspired web-app **privilege / access-control graph engine** — models roles, sessions, and privilege-escalation paths (IDOR, role/permission misconfig, token issues). | The **IDOR / BAC scanner** (`beatrix/scanners/idor.py`) — it was meant to back that scanner but got separated and never hooked up. | Unwired; needs integration into the IDOR scanner. |
| `auto_register.py` | An **account auto-registration** helper — tries to create throwaway accounts on a target so authenticated testing can run without hand-supplied creds (email/password generators, a credential store, `AutoRegistrar`). | A pre-auth step for the engine / Auth flow, if it proves reliable. | Experimental; low confidence it's practical in the wild — may get another attempt.

**To revive one:** move the file back under `beatrix/` (e.g. `beatrix/core/` or `beatrix/scanners/`),
fix up imports, wire it into the relevant scanner/engine entry point, and add a test.
