# HACKERADE — Security Scanner

A terminal-styled web console to check URLs and files against 70+ antivirus engines and to run domain recon (WHOIS, DNS, subdomains, contacts). Scanning is powered by the [VirusTotal](https://www.virustotal.com/) public API v3; recon runs directly on the server with DNS and WHOIS/RDAP.

![Next.js](https://img.shields.io/badge/Next.js-16.4-black) ![React](https://img.shields.io/badge/React-19-blue) ![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-38bdf8) ![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178c6)

## Features

### URL scan
- Paste any `http(s)` URL and get a verdict from 70+ engines
- Reuses VirusTotal's existing report when the URL has been analysed before
- Detects phishing/malware blocklist hits, page title, final URL, HTTP status and community reputation
- One-click rescan forces a fresh analysis

### File scan
- Drag and drop or browse, up to **32 MB** (VirusTotal's public API limit)
- Files are hashed first, so files VirusTotal already knows are never re-uploaded
- Files under 2 MB skip the extra lookup and go straight to the API (fewer requests)
- Shows engine-by-engine results, threat label, hashes and file metadata

### Domain recon
- **WHOIS** via the IANA → TLD → registrar chain, with automatic **RDAP** fallback
- **Subdomains** from certificate transparency logs (crt.sh), up to 1000 names
- **DNS**: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA
- **Contacts** extracted from WHOIS, SOA hostmaster, TXT records and DMARC report addresses
- Each section fails independently, so one slow source never blanks the whole report

## Tech stack

| Layer | Tech |
| --- | --- |
| Framework | Next.js 16.4 (App Router, Turbopack) |
| UI | React 19, Tailwind CSS 4, shadcn/base-ui primitives, lucide-react |
| Data fetching | SWR (polling + retries) |
| Language | TypeScript |
| Scanning | VirusTotal API v3 |
| Recon | Node `dns`, WHOIS over port 43, RDAP, crt.sh |

## Getting started

**Requirements:** Node.js 20+ (24 recommended) and a free VirusTotal API key.

```bash
git clone https://github.com/saucyXEN/security-scanner-web-app.git
cd security-scanner-web-app
npm install
```

Create `.env.local` in the project root:

```env
VIRUSTOTAL_API_KEY=your_key_here
```

Get a key from <https://www.virustotal.com/gui/my-apikey>.

Run it:

```bash
npm run dev     # http://localhost:3000
```

### Windows one-click launcher

Double-click **`start.bat`** (or run it from a terminal). It:

1. checks Node.js and installs dependencies if `node_modules` is missing
2. avoids starting a second server if one is already running
3. opens your browser automatically once the app is ready
4. retries automatically if Next.js exits early for its upgrade reminder

```bat
start.bat               :: start + open browser
start.bat --no-browser  :: start without opening a browser
```

Press `Ctrl+C` in that window to stop the server.

### Linux / macOS launcher

`start.bat` is Windows-only. Use the included shell script instead:

```bash
chmod +x start.sh     # once, if it is not executable after cloning
./start.sh            # start + open browser
./start.sh --no-browser
```

It does the same job as the `.bat`: installs dependencies if needed, reuses an already running server, opens the browser once the app is ready, and retries if Next.js stops for its upgrade reminder. On a headless VM (no desktop) it just prints the URL instead of opening a browser.

If Node.js is missing it installs Node.js 22 LTS automatically with [nvm](https://github.com/nvm-sh/nvm) (user-level, no root needed). If that is not possible it prints the options, including running the scanner on another machine and opening `http://<host-ip>:3000` from this one — that needs no Node.js on the client machine.

Or run the server directly, which is all the script really does:

```bash
npm run dev
```

### Python launcher

If you would rather not deal with bash or nvm, use the dependency-free Python 3 launcher:

```bash
python3 start.py                 # start + open browser
python3 start.py --no-browser    # start only
```

When Node.js 20+ is missing on Linux/macOS, `start.py` downloads a private Node.js 22 LTS build into `~/.cache/hackerade-node` (no root required) and uses it for this project only. Note that the app itself still runs on Node.js — Python only replaces the launcher, not the runtime.


## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the dev server |
| `npm run build` | Production build |
| `npm start` | Serve the production build |
| `start.bat` | Windows launcher (dev server + browser) |
| `./start.sh` | Linux / macOS launcher (dev server + browser) |
| `python3 start.py` | Python 3 launcher, bootstraps Node.js if missing |

There is no test or lint script configured.

## API routes

All routes use the Node.js runtime (required for DNS/WHOIS/Buffer) and expect a `VIRUSTOTAL_API_KEY` for scanning.

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/scan/url` | Scan a URL. Body: `{ url, rescan? }`. Returns a completed report or `{ status: "queued", analysisId }` |
| `GET` | `/api/scan/file?hash=<sha256>` | Look up an existing file report by SHA-256 |
| `POST` | `/api/scan/file` | Upload a file (`multipart/form-data`, field `file`, max 32 MB) |
| `GET` | `/api/scan/analysis/:id` | Poll a queued analysis until `status` is `completed` |
| `POST` | `/api/recon` | Domain recon. Body: `{ domain }` |

### Verdict logic

| Verdict | Rule |
| --- | --- |
| `malicious` | 3 or more engines flagged the target |
| `suspicious` | 1–2 malicious detections, or any suspicious detection |
| `safe` | No malicious or suspicious detections |

A single engine hit is treated as noise on popular sites, hence the 3-engine threshold.

### Polling and rate limits

The VirusTotal public API allows **4 requests/minute** and **500/day**. The app polls a queued analysis after 10 seconds and then every 20 seconds, and a `429` response is retried automatically instead of failing the scan. Requests time out after 30 seconds (120 seconds for uploads), so a stalled connection surfaces as an error instead of hanging.

## Deployment

`render.yaml` is included for [Render](https://render.com/):

- Node 24, `npm install && npm run build`, then `npm start`
- Set `VIRUSTOTAL_API_KEY` as a secret environment variable

On other hosts (Vercel, Railway, Fly.io, a VPS) the only requirements are a Node runtime and the same environment variable.

## Project structure

```
app/
  layout.tsx                  root layout, fonts, metadata
  page.tsx                    renders the scanner dashboard
  api/scan/url/route.ts       URL scanning
  api/scan/file/route.ts      file lookup + upload
  api/scan/analysis/[id]/     analysis polling
  api/recon/route.ts          domain recon
components/
  scanner/                    dashboard, URL/file/recon panels, result views
  ui/                         shadcn-style primitives
lib/
  virustotal.ts               VirusTotal client, normalization, verdicts
  recon.ts                    WHOIS/RDAP, DNS, crt.sh, contact extraction
  api-client.ts               fetch helpers, SWR hooks, polling policy
  types.ts                    shared types
start.bat                     Windows launcher
start.sh                      Linux / macOS launcher
start.py                      Python 3 launcher (bootstraps Node.js)
render.yaml                   Render deployment config
```

## Legal

Only scan URLs, files and domains you own or have permission to test. Results come from third-party feeds and can produce false positives or false negatives — use them as a signal, not a guarantee.

---

**HACKERADE** // threat intelligence console — SAUCY
