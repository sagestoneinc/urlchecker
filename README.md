# 🔍 Daily Malicious URL Checker + Telegram Bot Updater

A production-ready GitHub-hosted automation that checks URLs against VirusTotal every day and sends Telegram alerts only for newly malicious, suspicious, or changed results.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  GitHub Actions (daily cron / manual dispatch)                  │
│                                                                  │
│  ┌──────────┐    ┌──────────────────┐    ┌──────────────────┐   │
│  │ urls.txt │───▶│    main.py       │───▶│  Storage layer   │   │
│  └──────────┘    │  (orchestrator)  │    │  (JSON/JSONL/CSV)│   │
│                  └──────────────────┘    └──────────────────┘   │
│                         │                        │              │
│              ┌──────────┴──────────┐             │              │
│              ▼                     ▼             │              │
│  ┌───────────────────┐  ┌────────────────────┐   │              │
│  │ virustotal_client │  │ telegram_client    │   │              │
│  │  • POST /urls     │  │  • Malicious alert │   │              │
│  │  • GET /analyses  │  │  • Suspicious alert│   │              │
│  │  • GET /urls/{id} │  │  • Clean alert     │   │              │
│  │  • GET /domains/  │  │  • Domain alert    │   │              │
│  │  • Rate limiting  │  │  • Run summary     │   │              │
│  │  • Retry/backoff  │  └────────────────────┘   │              │
│  └───────────────────┘                            │              │
│                                                   ▼              │
│                                    ┌──────────────────────────┐  │
│                                    │ Artifacts (90-day retention│ │
│                                    │  latest_results.json      │  │
│                                    │  history.jsonl            │  │
│                                    │  latest_results.csv       │  │
│                                    │  run_summaries.jsonl      │  │
│                                    └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Module overview

| File | Purpose |
|------|---------|
| `main.py` | CLI entry point; orchestrates the full scan pipeline |
| `virustotal_client.py` | VirusTotal API v3 client with rate limiting and retries |
| `telegram_client.py` | Telegram Bot API client for alerts and summaries |
| `storage.py` | Reads/writes JSON, JSONL, and CSV result files |
| `models.py` | Dataclasses for `ScanResult`, `DomainResult`, `RunSummary`, `Verdict` |
| `config.py` | Centralised configuration from environment variables |
| `utils.py` | URL normalisation, domain extraction, logging setup |

---

## Project structure

```
urlchecker/
├── .github/
│   └── workflows/
│       └── daily-url-scan.yml   # GitHub Actions workflow
├── results/                     # Created at runtime; uploaded as artifact
│   ├── latest_results.json
│   ├── history.jsonl
│   ├── latest_results.csv
│   └── run_summaries.jsonl
├── config.py
├── main.py
├── models.py
├── storage.py
├── telegram_client.py
├── utils.py
├── virustotal_client.py
├── requirements.txt
├── Dockerfile
├── .env.example
├── urls.txt                     # Your URL list
└── README.md
```

---

## Quick start

### 1. Fork or create the GitHub repository

1. Create a new repository (or fork this one).
2. Clone it locally.

### 2. Add your URLs

Edit `urls.txt`, one URL per line. Lines starting with `#` and blank lines are ignored:

```
# My URLs to monitor
https://example.com
https://my-app.example.com/login
example.org          # scheme is optional – https:// will be added
```

### 3. Add GitHub repository secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Required | Description |
|--------|----------|-------------|
| `VT_API_KEY` | ✅ | Your VirusTotal API key |
| `TELEGRAM_BOT_TOKEN` | Optional | Your Telegram bot token (create via [@BotFather](https://t.me/BotFather)) |
| `TELEGRAM_CHAT_ID` | Optional | The chat / channel ID to send alerts to |

To get your Telegram chat ID:
1. Start a conversation with your bot.
2. Visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`
3. Find `"chat": {"id": <number>}` in the response.

### 4. Enable and run the workflow manually

1. Go to **Actions → Daily Malicious URL Checker**.
2. Click **Run workflow**.
3. Optionally enable **dry run** (skips VirusTotal calls – useful for testing the pipeline).
4. Click **Run workflow** to confirm.

### 5. Review results as artifacts

After each run:
1. Open the workflow run in **Actions**.
2. Scroll to **Artifacts**.
3. Download `url-scan-results-<run-number>`.
4. The archive contains `latest_results.json`, `history.jsonl`, `latest_results.csv`, and `run_summaries.jsonl`.

---

## Change the cron schedule

Edit `.github/workflows/daily-url-scan.yml`:

```yaml
on:
  schedule:
    - cron: "0 11 * * *"   # Every day at 06:00 EST (11:00 UTC)
```

Common examples:
- Every 12 hours: `"0 */12 * * *"`
- Every Monday at 08:00 UTC: `"0 8 * * 1"`

---

## CLI usage

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and edit the env file
cp .env.example .env
# Edit .env with your API keys

# Load .env automatically (python-dotenv is included)
python main.py --run-once

# Specify a custom URL file
python main.py --run-once --input my_urls.txt

# Send a Telegram summary at the end
python main.py --run-once --alert-summary

# Dry run – normalise URLs only, no VirusTotal calls
python main.py --run-once --dry-run

# Enable verbose debug output
python main.py --run-once --debug
```

---

## Storage strategy

### Default (GitHub Actions artifacts)

GitHub Actions runners are **ephemeral** – the workspace is destroyed after each run.
The workflow uploads all result files as artifacts retained for 90 days.

For a persistent history, either:
- **Download artifacts** and aggregate them locally, or
- Add a `git commit && git push` step to the workflow to store results directly in the repository (requires write permissions and a fine-grained PAT).

### Result files

| File | Format | Purpose |
|------|--------|---------|
| `results/latest_results.json` | JSON array | Full results from the most recent run |
| `results/history.jsonl` | JSONL (one record per line) | All historical scan records |
| `results/latest_results.csv` | CSV | Spreadsheet-friendly summary |
| `results/run_summaries.jsonl` | JSONL | One aggregated summary per run |

---

## Verdict logic

| Verdict | Condition |
|---------|-----------|
| `malicious` | `malicious_count > 0` |
| `suspicious` | `suspicious_count > 0` and `malicious_count == 0` |
| `clean` | `malicious == 0`, `suspicious == 0`, and at least one engine returned harmless/undetected |
| `unknown` | Analysis incomplete or no data available |

---

## Alert logic

Alerts are sent **only when something changes** (no duplicate alerts):

| Event | Alert sent |
|-------|-----------|
| URL first seen as malicious | ✅ Malicious alert |
| URL changes from clean/unknown → malicious | ✅ Malicious alert |
| Malicious engine count increases | ✅ Malicious alert |
| URL changes from clean/unknown → suspicious | ✅ Suspicious alert |
| Suspicious engine count materially increases | ✅ Suspicious alert |
| Domain reputation significantly worsens | ✅ Domain alert |
| Previously bad URL becomes clean | ✅ Clean alert (if `ALERT_ON_CLEAN=true`) |
| No change from last run | ❌ No alert |

---

## Example Telegram messages

**Malicious alert:**
```
🚨 MALICIOUS URL DETECTED

🔗 https://evil.example.com/phish
🌐 Domain: evil.example.com
🔴 Malicious engines: 42 / 90
🟡 Suspicious engines: 3
⏰ Scanned at: 2024-01-15T06:12:34+00:00
🔄 Status changed: clean → malicious
```

**Suspicious alert:**
```
⚠️ SUSPICIOUS URL DETECTED

🔗 https://dodgy.example.net/track?id=abc
🌐 Domain: dodgy.example.net
🟡 Suspicious engines: 5 / 90
🟢 Harmless engines: 72
⏰ Scanned at: 2024-01-15T06:14:01+00:00
🔄 Status changed: clean → suspicious
```

**Run summary:**
```
🛡️ Malicious URL Checks — 02/22/2026

Summary
- Sources Checked: VirusTotal
- URLs Checked: 25
- Flagged URLs: 3
- Takedowns Requested: 1
```

---

## Bot commands (issue comments)

You can run commands from an issue comment:

- `/add-link https://example.com/path`  
  Adds the URL to `urls.txt` (if missing) and queues a scan for that URL.
- `/rescan https://example.com/path`  
  Queues a scan for that URL without editing `urls.txt`.

Both commands post a confirmation comment and dispatch the scanner workflow with a single-URL input.

---

## VirusTotal rate limits

| Tier | Rate limit | Daily quota |
|------|-----------|-------------|
| Free | 4 requests/minute | 500 requests/day |
| Premium | Higher | Much higher |

The scanner enforces a `VT_RATE_LIMIT_RPM=4` default. Each URL scan requires approximately 2–3 API calls (submit + poll + domain). With the free tier you can comfortably scan **~50–80 URLs per day**.

---

## Docker usage

```bash
# Build
docker build -t urlchecker .

# Run with your .env and urls.txt
docker run --env-file .env \
  -v "$(pwd)/urls.txt:/app/urls.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  urlchecker
```

---

## Limitations

- **GitHub Actions scheduled runs** can be delayed by up to an hour during periods of high load.
- **Ephemeral runners**: results are not persisted between runs unless uploaded as artifacts or committed back to the repository.
- **VirusTotal free tier**: 500 requests/day and 4 requests/minute. Large URL lists may require a paid plan.
- **Analysis freshness**: VirusTotal may return cached results for recently scanned URLs rather than triggering a new scan.
