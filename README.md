# HACKERADE — Security Scanner

A terminal-styled web console to check URLs and files against 70+ antivirus engines, analyse files offline (including files larger than VirusTotal's 32 MB limit), run OSINT with Shodan, ask a local Ollama model about a report, and export any result as a PDF. URL/file scanning uses the [VirusTotal](https://www.virustotal.com/) public API v3 when a key is configured; file analysis, recon and PDF export work without it.

![Next.js](https://img.shields.io/badge/Next.js-16.4-black) ![React](https://img.shields.io/badge/React-19-blue) ![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-38bdf8) ![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178c6)

## Features

### URL scan
- Paste any `http(s)` URL and get a verdict from 70+ engines
- Reuses VirusTotal's existing report when the URL has been analysed before
- Detects phishing/malware blocklist hits, page title, final URL, HTTP status and community reputation
- One-click rescan forces a fresh analysis

### File scan
- Drag and drop or browse, up to **200 MB** — including files over the 32 MB VirusTotal limit
- **Offline static analysis** runs first: magic-byte type detection, entropy, PE structure, embedded commands/URLs/IPs, suspicious script patterns, double extensions, EICAR signature and more
- Nothing is executed: this is a *static* sandbox, so a sample can never infect the machine running the scanner
- VirusTotal multi-engine results are added on top when a key is configured, and can be switched off per scan for fully offline use
- Files over 32 MB are looked up by hash and, on API plans that allow it, uploaded through VirusTotal's large-file endpoint
- Shows engine-by-engine results, threat label, hashes and file metadata
- Every report can be downloaded as a PDF

### AI analyst (Ollama)
- Ask questions about a completed file analysis (“is this harmful?”, “explain the findings”) in English or Hinglish
- Runs against a local [Ollama](https://ollama.com/) server, so the scan report never leaves your machine
- Shows a clear hint when Ollama is offline or the model is not pulled yet
- Advisory only: it never replaces the engine results

### OSINT (Shodan)
- Host intelligence for an IP or domain: organisation, ISP, ASN, location, OS, open ports
- Exposed services with product/version and banner snippets
- Known CVEs linked to NVD, plus Shodan tags
- DNS records and subdomains from Shodan's DNS dataset
- **Deep search** across Shodan's index for matching services
- Each source fails independently; missing keys and paid-plan limits are reported clearly

### PDF reports
- One-click PDF download for URL scans, file analyses and OSINT results
- Server-side generation with `pdf-lib`, no browser printing required

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
| Scanning | VirusTotal API v3 + built-in offline static engine |
| AI | Ollama (`/api/chat`) |
| OSINT | Shodan API |
| PDF | `pdf-lib` |
| Recon | Node `dns`, WHOIS over port 43, RDAP, crt.sh |

## Getting started

**Requirements:** Node.js 20+ (24 recommended). API keys are optional — file analysis, recon and PDF export work offline, and virus-scanning features light up when keys are present.

```bash
git clone https://github.com/saucyXEN/security-scanner-web-app.git
cd security-scanner-web-app
npm install
```

Create `.env.local` in the project root (all values are optional, but see the notes):

```env
# 70+ antivirus engines for URLs and files (free key)
VIRUSTOTAL_API_KEY=your_key_here

# OSINT / deep search (free tier works; some fields need a paid plan)
SHODAN_API_KEY=your_key_here

# Local AI analyst
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2
```

- VirusTotal key: <https://www.virustotal.com/gui/my-apikey>
- Shodan key: <https://account.shodan.io/>
- Ollama: install from <https://ollama.com/download>, then run `ollama serve` and `ollama pull llama3.2`

Without `VIRUSTOTAL_API_KEY` the file scanner still performs the full offline analysis and reports that VirusTotal is skipped. Without `SHODAN_API_KEY` the OSINT tab explains how to enable it. Without Ollama the AI widget is disabled with setup instructions.

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

All routes use the Node.js runtime (required for DNS/WHOIS/Buffer). Only the VirusTotal-backed routes need `VIRUSTOTAL_API_KEY`.

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/scan/url` | Scan a URL. Body: `{ url, rescan? }`. Returns a completed report or `{ status: "queued", analysisId }` |
| `POST` | `/api/scan/deep` | Upload a file (`multipart/form-data`, field `file`, max 200 MB) for offline static analysis plus optional VirusTotal results. Send `vt=off` to skip VirusTotal entirely |
| `GET` | `/api/scan/file?hash=<sha256>` | Look up an existing file report by SHA-256 |
| `POST` | `/api/scan/file` | Upload a file directly to VirusTotal (`multipart/form-data`, field `file`, max 32 MB) |
| `GET` | `/api/scan/analysis/:id` | Poll a queued analysis until `status` is `completed` |
| `POST` | `/api/osint` | Shodan host intel + DNS + deep search. Body: `{ target }` (IP or domain) |
| `GET` | `/api/ai/analyze` | Ollama status: reachable, configured model, installed models |
| `POST` | `/api/ai/analyze` | Ask the AI analyst. Body: `{ prompt }` |
| `POST` | `/api/report/pdf` | Build a PDF. Body: `{ title, subtitle?, sections: [{ heading, rows?, text? }] }` |
| `POST` | `/api/recon` | Domain recon. Body: `{ domain }` |

### Verdict logic

| Verdict | Rule |
| --- | --- |
| `malicious` | 3 or more engines flagged the target |
| `suspicious` | 1–2 malicious detections, or any suspicious detection |
| `safe` | No malicious or suspicious detections |

A single engine hit is treated as noise on popular sites, hence the 3-engine threshold. The offline file engine uses a separate risk score: `malicious` at 10+, `suspicious` at 3+, `safe` below that.

### Offline mode

File analysis is designed to work with no internet connection and no API keys:

1. `/api/scan/deep` always runs the local static engine first and returns its verdict.
2. VirusTotal lookup/upload is attempted only when a key is configured and the user did not untick *Submit to VirusTotal*.
3. If VirusTotal is unreachable, rate-limited or rejects the file (e.g. a 40 MB sample on a free plan), the response still contains the full offline analysis and a `vtError` explaining what was skipped.

The static engine never executes the sample. “Sandbox” here means a safe, local inspection of the bytes and structure — not dynamic malware detonation.

### Polling and rate limits

The VirusTotal public API allows **4 requests/minute** and **500/day**. The app polls a queued analysis after 10 seconds and then every 20 seconds, and a `429` response is retried automatically instead of failing the scan. Requests time out after 30 seconds (120 seconds for normal uploads, 600 seconds for large-file uploads), so a stalled connection surfaces as an error instead of hanging.

## Deployment

`render.yaml` is included for [Render](https://render.com/):

- Node 24, `npm install && npm run build`, then `npm start`
- Set `VIRUSTOTAL_API_KEY` (and optionally `SHODAN_API_KEY`) as secret environment variables

On other hosts (Vercel, Railway, Fly.io, a VPS) the only requirements are a Node runtime and the same environment variables. Note that `OLLAMA_URL=http://127.0.0.1:11434` only works when Ollama runs on the same machine as the app; for a hosted deployment point it at a reachable Ollama host (and keep that endpoint private).

## Project structure

```
app/
  layout.tsx                  root layout, fonts, metadata
  page.tsx                    renders the scanner dashboard
  api/scan/url/route.ts       URL scanning
  api/scan/deep/route.ts      offline file analysis + optional VirusTotal
  api/scan/file/route.ts      file lookup + 32 MB VirusTotal upload
  api/scan/analysis/[id]/     analysis polling
  api/osint/route.ts          Shodan OSINT + deep search
  api/ai/analyze/route.ts     Ollama status + AI questions
  api/report/pdf/route.ts     PDF report generation
  api/recon/route.ts          domain recon
components/
  scanner/                    dashboard, URL/file/OSINT/recon panels, AI widget, results
  ui/                         shadcn-style primitives
lib/
  virustotal.ts               VirusTotal client, normalization, verdicts, large uploads
  static-analysis.ts          offline file engine (hashes, entropy, PE, patterns)
  osint.ts                    Shodan host/DNS/search client
  ollama.ts                   local AI client + status
  pdf.ts                      PDF layout and rendering
  report.ts                   report/PDF/AI prompt builders
  recon.ts                    WHOIS/RDAP, DNS, crt.sh, contact extraction
  api-client.ts               fetch helpers, SWR hooks, polling policy
  types.ts                    shared types
start.bat                     Windows launcher
start.sh                      Linux / macOS launcher
start.py                      Python 3 launcher (bootstraps Node.js)
render.yaml                   Render deployment config
.env.example                  documented environment variables
```

## Legal

Only scan URLs, files and domains you own or have permission to test. Results come from third-party feeds and can produce false positives or false negatives — use them as a signal, not a guarantee.

---

**HACKERADE** // threat intelligence console — SAUCY
