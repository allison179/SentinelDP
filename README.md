# DPDP Compliance Scanner

A local-only desktop tool for scanning files on a Windows machine for personal data covered
under India's **Digital Personal Data Protection (DPDP) Act, 2023** — Aadhaar numbers, PAN,
GSTIN, mobile numbers, emails, passport numbers, voter IDs, and dates of birth.

Everything runs **fully offline**. No file content, scan result, or extracted text ever
leaves the machine — there are no network calls, no telemetry, no cloud APIs. This matters
because the tool's entire purpose is handling sensitive enterprise data.

## Why

Organizations often don't know where personal data is sitting unprotected across shared
drives, desktops, and project folders until an audit or breach forces the question. This
scans a folder tree, flags files containing detectable PII, and gives you a dashboard to
review and remediate (quarantine, not delete) flagged files — without uploading anything
anywhere.

## Features

- **Broad file coverage** — PDF, DOCX, XLSX, PPTX, CSV, TXT, JSON, XML, HTML, EML, MSG,
  and images (PNG/JPG/TIFF/BMP)
- **OCR for scanned documents and screenshots** — catches PII in photographed/scanned PDFs
  and images, not just machine-readable text (requires a local Tesseract OCR install)
- **Checksum-validated detection** — Aadhaar numbers are validated against the real
  Verhoeff checksum and PAN against its structural rule, to cut false positives instead of
  flagging every random 12-digit number
- **Resume scanning** — re-scanning a large fileset only processes new/changed files
  instead of starting over
- **Live progress** — real per-file progress bar for large folder scans, not a blind spinner
- **Safe purge** — flagged files move to a configurable quarantine folder instead of being
  permanently deleted
- **Report export** — JSON, CSV, and Excel (with a summary tab)
- **Searchable audit table** — filter the full scan log by filename, path, violation type,
  or status

## Screenshots

_Add a couple of dashboard screenshots here — drag images into a GitHub PR/issue comment
to get a hosted URL, then embed with `![Dashboard](url)`._

## Installation

```bash
git clone https://github.com/<your-org>/dpdp-scanner.git
cd dpdp-scanner
pip install -r requirements.txt
```

### OCR setup (optional but recommended)

OCR uses [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki), a standalone
binary — `pytesseract` is just a Python wrapper around it.

1. Install Tesseract for Windows (UB-Mannheim build).
2. Default install path is `C:\Program Files\Tesseract-OCR\tesseract.exe` — `scan_cli.py`
   checks this path automatically. If you installed elsewhere, set it explicitly in
   `scan_cli.py`:
   ```python
   pytesseract.pytesseract.tesseract_cmd = r"<your path>\tesseract.exe"
   ```
3. No Tesseract? Just leave "Enable OCR" unchecked in the app — everything else works
   without it; you only lose detection on scanned/photographed documents.

## Usage

### Desktop app (Streamlit UI)

```bash
streamlit run main.py
```

Or on Windows, double-click `launch.vbs` to start it silently in the background and open
your browser automatically.

### CLI (batch / scripted scans)

```bash
python scan_cli.py "C:\path\to\folder" --output report.json --workers 4 --resume
```

Useful flags:

| Flag | Purpose |
|---|---|
| `--resume` | Skip files unchanged since the last scan (uses `report.cache.json`) |
| `--no-ocr` | Disable OCR for faster scans when you don't need it |
| `--max-size-mb` | Skip files above this size (default 300MB) |
| `--password` | Global password to try on encrypted PDFs/Office files |
| `--progress` | Stream live JSON progress lines to stdout (used by the UI) |

## Building the standalone .exe

This repo includes `main.spec` for PyInstaller. After installing requirements:

```bash
pyinstaller main.spec
```

The build bundles `.streamlit/config.toml` (raises the upload cap to 2GB, disables
telemetry) and the OCR/Excel dependencies. The output goes to `dist/main/`.

## Disclaimer

This tool is a **detection aid**, not a certified DPDP compliance solution. Detection is
pattern- and checksum-based and will not catch every form of personal data (e.g. names,
addresses, or PII embedded in unusual formats). Always have a human review flagged files
before taking any remediation action, and treat quarantined files as recoverable, not
deleted.

## License

See [LICENSE.txt](LICENSE.txt).

<img width="1356" height="617" alt="Screenshot 2026-06-30 113349" src="https://github.com/user-attachments/assets/0d5ad762-9ed2-49cb-a4a0-c5c0a5cc4f03" />

<img width="1327" height="532" alt="Screenshot 2026-06-30 113555" src="https://github.com/user-attachments/assets/891a2505-f84e-4854-8eb7-66b8d9ebf191" />

