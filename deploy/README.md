# Backend deployment runbook

**Why this exists:** `cyberdudebivash.in/api/*` is currently returning HTTP 503
`{"maintenance":true}` on every path (confirmed by live testing on 2026-08-10 —
`/api/health`, `/api/v1/intel/kev.json`, `/api/v1/intel/stix.json`, `/api/feed`
all uniform 503). The main site (`cyberdudebivash.in/`) itself returns 200.
That pattern means whatever fronts the API (very likely a Cloudflare Worker,
given the response shape matches this repo's own Worker fallback pattern
exactly) is up, but *its* upstream — the actual FastAPI process — is
unreachable. This repo has never contained that origin's deployment config
(confirmed: no Dockerfile, Procfile, systemd unit, render.yaml, railway.json,
or PM2 config anywhere in git history's file listing), and public DNS can't
reveal it either — `cyberdudebivash.in` and `army.cyberdudebivash.in` both
resolve to Cloudflare's own IP range (`2606:4700::/32`), which is what
Cloudflare-proxied ("orange cloud") domains always show, regardless of where
the real origin sits.

## Step 0 — Try to recover the existing host first

This step needs your Cloudflare dashboard access — it can't be done from a
repository or from public DNS. Two places to check, in order:

1. **Workers & Pages → your account → each Worker → Triggers/Routes tab.**
   Look for a route matching `cyberdudebivash.in/api/*`. If one exists, open
   that Worker's source (it will **not** be `worker/src/index.js` from this
   repo — this repo's Worker calls `cyberdudebivash.in` as its *upstream*,
   so serving `cyberdudebivash.in/api/*` with the same code would be a
   circular loop). Its source may reveal a `fetch()` call to a real origin
   hostname or IP — that's your backend host.
2. **DNS tab → look for any record that is *not* proxied (grey cloud, not
   orange)**, especially anything like `origin.cyberdudebivash.in` or
   similar. An unproxied A/AAAA record is the one place Cloudflare will show
   you a real IP instead of its own.

If you find a hostname or IP this way: SSH in (or use the provider's
dashboard console) and check `systemctl status`, `pm2 list`, or
`docker ps` to see what's actually running there, then compare against
Step 1 below to decide whether to repair it in place or replace it with
this deploy/ package.

If you don't find anything, or don't remember creating a VPS for this —
proceed straight to the fresh-VPS path (Step 2). Given the disorganized
deploy history visible in this repo (three separate "EMERGENCY" hotfix
commits, two different Cloudflare Worker deploy paths with mismatched
secret names — see `docs/commercial/COMMERCIAL_PRODUCTION_GAP_REGISTER.md`
GAP-005), it's entirely plausible the original host was a manually-configured
box nobody wrote down, or a trial/free-tier instance that expired.

## Step 1 — If you found and can still access the existing host

Generic runbook, adjust for what you actually find:

```bash
ssh <user>@<host>
cd <wherever the app lives>
git pull origin main   # or: git clone the repo fresh if it's not already there
pip install -r requirements.txt
# replace whatever the old entrypoint file was with cyberdudebivash_army_backend.py
# if it's systemd: sudo systemctl restart <service-name>
# if it's pm2:      pm2 restart <app-name>
# if it's docker:    docker compose up -d --build
curl http://127.0.0.1:<port>/api/health   # run ON the host, bypassing DNS/Cloudflare
```

If the existing setup is workable, consider still adopting this repo's
`deploy/systemd/` units and `deploy/nginx/` config in place of whatever's
there now — they fix a real bug (rate-limiter IP handling behind a reverse
proxy — see the comment block in `deploy/systemd/cyberdudebivash-api.service`)
that a from-scratch setup is likely to have too.

## Step 2 — Fresh VPS (DigitalOcean Mumbai / Hetzner / AWS Lightsail — any Ubuntu 22.04 box)

Recommendation: **DigitalOcean's Bangalore (`blr1`) region** or **Hetzner's
Singapore region** — both offer low-latency Ubuntu 22.04 droplets close to
an India-focused audience without the setup overhead of AWS Lightsail's IAM.
Any of the three works with the script below unmodified; it only assumes
Ubuntu 22.04 and root/sudo access.

### If you're doing this from a Windows machine

Nothing below changes — every command from step 2 onward runs *on the
Ubuntu VPS itself*, not on your local machine. Your local OS only affects
how you get an SSH session open in the first place, and Windows 10/11 ships
a native OpenSSH client for that, so no PuTTY or extra install is normally
needed. Two one-time preparation steps before you start the numbered list:

- **Confirm you have `ssh`:** open PowerShell and type `ssh`. If it's not
  found: Settings → Optional Features → check for "OpenSSH Client" → Add
  feature (or as admin PowerShell:
  `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`).
- **Generate a key pair** if you don't already have one:
  ```powershell
  ssh-keygen -t ed25519 -C "cyberdudebivash-deploy"
  ```
  Accept the default path. Then view the public half to paste into the
  provider's "SSH key" field in step 1 below:
  ```powershell
  Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub
  ```
  (Never paste the *private* key — the one without `.pub` — anywhere.)

From here on, "SSH in" means, from PowerShell: `ssh root@<vps-ip>`. That
drops you into a real Ubuntu shell on the VPS — every command below runs
there, typed at the VPS's own prompt, exactly as written, regardless of
your local OS. `scp <local-file> root@<vps-ip>:/path/` (also built into
Windows) covers copying a file over later if you ever need to.

Optional, not required: `wsl --install` (one-time, admin PowerShell) gives
you a full local Ubuntu environment inside Windows if you'd like one for
browsing the repo — the deploy itself still happens over SSH to the real
VPS either way, not inside WSL.

1. Create the VPS, note its public IP, SSH in as root (or a sudo user).
2. Copy this repo onto it, or just download the script directly:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/cyberdudebivash-pvt-ltd/CYBERDUDEBIVASH-AI-SECURITY-HUB-ARMY/main/deploy/provision-vps.sh -o provision-vps.sh
   sudo bash provision-vps.sh
   ```
   (Or clone the repo and run `sudo bash deploy/provision-vps.sh` — same
   effect. Optionally pass a different domain as the second argument if you
   don't want `api.cyberdudebivash.in`. This all runs on the VPS, inside
   the SSH session from step 1 — nothing to install on Windows itself.)
3. The script installs Python/nginx/certbot, creates a locked-down
   `cyberdudebivash` system user, sets up a venv, installs the systemd
   service (API) and timer (6-hourly real-data seeding from CISA KEV +
   FIRST.org EPSS — see `deploy/seed_kev_feed.py`), and configures nginx
   over plain HTTP. It prints exact next-step commands when done.
4. **Point DNS at the new box.** In Cloudflare: DNS tab → add an A record
   for `api.cyberdudebivash.in` (or whatever domain you chose) → the VPS's
   IP → proxy status **on** (orange cloud). Wait a minute or two.
5. On the VPS: `certbot --nginx -d api.cyberdudebivash.in` — this obtains a
   real cert and edits the nginx config to add the HTTPS server block and
   the HTTP→HTTPS redirect automatically. Answer its prompts (email, ToS).
6. In Cloudflare: SSL/TLS tab for this hostname → set mode to **Full
   (strict)**. This is not optional — "Flexible" would leave the
   Cloudflare-to-VPS hop unencrypted, and plain "Full" accepts a self-signed
   cert (weaker than it looks). Full (strict) requires the real cert from
   step 5 to already be in place, which is why the order matters.
7. Verify from *outside* the VPS: `curl https://api.cyberdudebivash.in/api/health`.

### The remaining piece: getting `cyberdudebivash.in/api/*` itself to point here

Everything above stands up a new, independent origin at
`api.cyberdudebivash.in`. It does **not**, by itself, fix
`cyberdudebivash.in/api/*` — that's routed through whatever Worker or DNS
record you found (or didn't find) in Step 0. Two ways to finish this,
depending on what Step 0 turned up:

- **If a Worker owns that route:** edit its `fetch()` upstream target to
  point at `https://api.cyberdudebivash.in` instead of whatever dead host
  it currently calls, then `wrangler deploy` (or redeploy via whichever of
  the two conflicting GitHub Actions paths is actually the live one — see
  GAP-005 in the gap register before touching this, it's fragile right now).
- **If no Worker is involved and `cyberdudebivash.in/api/*` is a direct DNS
  route:** point that route/record at the new VPS the same way you did for
  `api.cyberdudebivash.in` in step 4 above.

Either way, **this repo's own `worker/src/index.js` needs no code change**
for this fix — it already calls `https://cyberdudebivash.in/api/v1/intel/kev.json`
as a hardcoded upstream (line 42) and will start working the moment that
URL itself starts returning real data again, regardless of what's actually
serving it underneath.

## Step 3 — Verify (all four, not just the first)

```bash
curl -s https://cyberdudebivash.in/api/health
# expect: {"status":"healthy","version":"185.1",...} — not {"maintenance":true}

curl -s https://cyberdudebivash.in/api/v1/intel/kev.json
# expect: {"count": N>0, "advisories": [...]} once the seed timer has run once
# (up to 6h after provisioning, or run deploy/seed_kev_feed.py manually to
# populate immediately — the provisioning script prints this command)

curl -s https://army.cyberdudebivash.in/
# separately: this domain still needs its GitHub-Pages-vs-Worker routing
# issue fixed for the dashboard itself to work end-to-end — that's a
# different, already-diagnosed problem (see the "Threats Command ARMY
# dashboard" conversation history / GAP-000 in the gap register), not
# something this backend fix resolves by itself.
```

Zero CVSS-below-7 items will be labeled CRITICAL and zero CVE IDs will
appear in IOC tables **by construction** — `cyberdudebivash_army_backend.py`'s
`map_cvss_to_severity()` and `_is_hard_rejected()` already enforce both
(53/53 tests passing, verified in this session) — those two acceptance
criteria are a property of the code that's about to run, not something the
deployment itself has to separately get right.

## Rollback

- **VPS:** `sudo systemctl stop cyberdudebivash-api cyberdudebivash-kev-seed.timer`
  stops serving without deleting anything. To fully back out, revert the
  Cloudflare DNS/Worker change from Step 2's last section — that's the one
  step with a live blast radius beyond this VPS.
- **This repo:** everything under `deploy/` is new and additive; nothing
  existing was modified except `requirements.txt` (added `httpx`, needed by
  the seed script — purely additive) and `.github/workflows/deploy.yml`
  (see the CI template note below). Reverting the commit that added this
  directory fully undoes the repo-side change.

## CI/CD

`.github/workflows/deploy.yml`'s `deploy-backend` job currently just prints a
manual-SSH reminder — seek `deploy-backend-ssh-template.yml` in this
directory for a ready-to-enable automated version once you have a host to
point it at. It's not wired in automatically because it needs three GitHub
Secrets (`VPS_HOST`, `VPS_SSH_USER`, `VPS_SSH_KEY`) this session cannot
create on your behalf — see that file's own header comment for exact setup
steps.
