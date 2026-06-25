# repo-xray 🔍

**Reverse-engineer any public GitHub repository into an AI prompt + learning guide.**

Point it at a repo URL and get back: a plain-English summary, tech stack breakdown, architecture overview, key file map, learning insights, an AI rebuild prompt, quick start guide, and a fun fact — in Markdown, JSON, or plain text.

---

## Features

- **Zero dependencies** — pure Python stdlib (`urllib`, `json`, `argparse`)
- **Two output modes** — CLI tool + standalone browser web app (`web/index.html`)
- **Smart file filtering** — skips `node_modules`, `dist`, binaries; caps context at 80K chars
- **Dual AI backend** — Groq (llama-3.3-70b-versatile) primary, HuggingFace router fallback
- **3 output formats** — Markdown, JSON, plain text
- **Works with Python 3.11+**

---

## Quick Start

### CLI

```bash
# Set your API key (free at console.groq.com)
export GROQ_API_KEY=gsk_...

# Analyse any public GitHub repo
python cli.py fastapi/fastapi
python cli.py https://github.com/vercel/next.js --format markdown --output nextjs.md
python cli.py supabase/supabase --format json
python cli.py django/django --verbose
```

### Web App

Open `web/index.html` in any browser. Enter your Groq API key once (saved in localStorage) then paste any GitHub URL.

No server needed — calls GitHub API and Groq directly from the browser.

---

## Output Example

See [`examples/fastapi-report.md`](examples/fastapi-report.md) for a full sample report.

---

## CLI Reference

```
usage: repo-xray [-h] [--format {markdown,json,plain}] [--output FILE]
                 [--verbose] [--groq-key KEY] [--hf-key KEY]
                 [--github-token TOKEN]
                 repo

positional arguments:
  repo                  GitHub URL or 'owner/repo'

options:
  -h, --help            show this help message and exit
  --format, -f          Output format: markdown (default), json, plain
  --output, -o FILE     Write to file instead of stdout
  --verbose, -v         Show progress messages
  --groq-key KEY        Groq API key (overrides GROQ_API_KEY env var)
  --hf-key KEY          HuggingFace API key (overrides HF_API_TOKEN env var)
  --github-token TOKEN  GitHub token for higher rate limits
```

---

## API Keys

| Key | Source | Required |
|-----|--------|----------|
| `GROQ_API_KEY` | [console.groq.com](https://console.groq.com) — free tier: 14,400 req/day | Primary |
| `HF_API_TOKEN` | [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) | Fallback |
| `GITHUB_TOKEN` | GitHub → Settings → Developer Settings | Optional (higher rate limits) |

---

## Project Structure

```
repo-xray/
├── cli.py               # CLI entry point (argparse)
├── src/
│   ├── fetcher.py       # GitHub API + file tree fetcher
│   ├── analyzer.py      # AI analysis (Groq + HF)
│   └── formatter.py     # Markdown / JSON / plain text output
├── web/
│   └── index.html       # Self-contained browser web app
├── tests/
│   ├── test_fetcher.py
│   └── test_formatter.py
└── examples/
    └── fastapi-report.md
```

---

## Run Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## License

MIT
