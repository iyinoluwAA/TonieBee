# Tools

| | |
|---|---|
| `git-hooks/pre-push` | Blocks pushes to `main`; runs the website and API checks before any push. Turn on once per clone: `git config core.hooksPath tools/git-hooks` |
| `shot.sh <name> <path> [w] [h] [full]` | Screenshot the local site (http://localhost:5175) with a headless Chromium inside WSL. Default 1280×610 (AJ's laptop); `390 844` for a phone, `344 880` for the Fold's cover screen. Saves to `tools/shots/` (git-ignored). |
| `dev_admin.py [email] [password]` | Makes a **development** admin by typing into the real `create-admin`; saves its key to `tools/e2e/out/dev-admin.json` (git-ignored). `--code` prints the current authenticator code. |
| `e2e/site.mjs` | Click-through check of the real site + API (13 checks: form, email sign-in across two devices, My requests, owner sign-in with an authenticator code, status/notes, Activity). Setup once: `cd tools/e2e && npm install`. Run: `API_LOG=<the API's log file> node tools/e2e/site.mjs` with the API (`MAIL_PROVIDER=log`) and the dev site running. |
| `prod_admin.sh` | Creates the first LIVE admin (or tests live email) from the laptop — docs/DEPLOY.md. |
| `test-pages/` | Copies of `_frame.html` / `_measure.html` (phone frames, sideways-scroll check); copy into `frontend/public/_dev/` (git-ignored) to use. |

Screenshots in WSL use Playwright's Chromium already on this machine
(`~/.cache/ms-playwright`). Windows Chrome (Spectra's way) also works when WSL's Windows
interop is healthy (it wasn't on 2026-11-07: `wsl --shutdown` from Windows fixes it).
