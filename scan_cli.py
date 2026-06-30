import argparse
import hashlib
import json
import os
import re
import io
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

console = None
try:
    from rich.console import Console
    console = Console()
except ImportError:
    pass

# ──────────────────────────────────────────────────────────────────────────
# SUPPORTED FILE TYPES
# ──────────────────────────────────────────────────────────────────────────
DOC_EXTS   = {".pdf", ".docx", ".xlsx", ".pptx", ".csv", ".txt", ".json", ".xml", ".html", ".htm", ".eml", ".msg"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
SUPPORTED_EXTS = DOC_EXTS | IMAGE_EXTS

DEFAULT_MAX_SIZE_MB = 300  # skip files larger than this to avoid hanging a worker thread


def collect_files(root: Path) -> list[Path]:
    return sorted(f for f in root.rglob("*") if f.is_file() and f.suffix.lower() in SUPPORTED_EXTS)


# ──────────────────────────────────────────────────────────────────────────
# PII VALIDATORS  (checksum / structure checks to cut false positives)
# ──────────────────────────────────────────────────────────────────────────
def _verhoeff_valid(num: str) -> bool:
    """Validates Aadhaar's Verhoeff checksum digit."""
    d = [
        [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
        [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
        [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
        [9,8,7,6,5,4,3,2,1,0],
    ]
    p = [
        [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
        [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
        [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
    ]
    digits = [int(x) for x in num][::-1]
    c = 0
    for i, digit in enumerate(digits):
        c = d[c][p[i % 8][digit]]
    return c == 0


def validate_aadhaar(raw: str) -> bool:
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) != 12 or not digits.isdigit():
        return False
    try:
        return _verhoeff_valid(digits)
    except Exception:
        return False


def validate_pan(pan: str) -> bool:
    # 4th character encodes holder type: P, C, H, F, A, T, B, L, J, G
    return bool(re.match(r"^[A-Z]{3}[PCHFATBLJG][A-Z][0-9]{4}[A-Z]$", pan))


# ──────────────────────────────────────────────────────────────────────────
# PII PATTERNS
# ──────────────────────────────────────────────────────────────────────────
PII_PATTERNS = {
    "Aadhaar Number":  (re.compile(r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b"), validate_aadhaar),
    "PAN Card":        (re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), validate_pan),
    "GSTIN":           (re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z\d]\b"), None),
    "Indian Mobile":   (re.compile(r"(?<!\d)(?:\+91[\s\-]?|0)?[6-9]\d{9}(?!\d)"), None),
    "Email Address":   (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None),
    "IFSC Code":       (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), None),
    "Passport Number": (re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"), None),
    "Voter ID (EPIC)": (re.compile(r"\b[A-Z]{3}[0-9]{7}\b"), None),
    "Date of Birth":   (re.compile(r"\b(0[1-9]|[12]\d|3[01])[\/\-.](0[1-9]|1[0-2])[\/\-.](19|20)\d{2}\b"), None),
}


def scan_for_pii(text: str) -> dict[str, int]:
    hits = {}
    for label, (pattern, validator) in PII_PATTERNS.items():
        matches = pattern.findall(text)
        raw_matches = [m if isinstance(m, str) else m[0] for m in matches]
        if validator:
            raw_matches = [m for m in raw_matches if validator(m)]
        unique = set(raw_matches)
        if unique:
            hits[label] = len(unique)
    return hits


# ──────────────────────────────────────────────────────────────────────────
# OCR (offline, via local Tesseract install — no cloud calls)
# ──────────────────────────────────────────────────────────────────────────
def _ocr_image_bytes(image_bytes: bytes) -> str:
    from PIL import Image
    import pytesseract

    # Tesseract OCR is a standalone binary, not a Python package — point pytesseract
    # at the local install explicitly so it doesn't depend on PATH being configured.
    default_tesseract = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.path.exists(default_tesseract):
        pytesseract.pytesseract.tesseract_cmd = default_tesseract

    img = Image.open(io.BytesIO(image_bytes))
    return pytesseract.image_to_string(img)


def _ocr_scanned_pdf(file_path: Path) -> str:
    """Renders each page to an image and OCRs it. Used when a PDF has no
    extractable text layer (i.e. it's a scan/photo of a document)."""
    import fitz  # PyMuPDF
    text = ""
    doc = fitz.open(str(file_path))
    try:
        for page in doc:
            pix = page.get_pixmap(dpi=200)
            text += _ocr_image_bytes(pix.tobytes("png")) + "\n"
    finally:
        doc.close()
    return text


# ──────────────────────────────────────────────────────────────────────────
# EXTRACTION
# ──────────────────────────────────────────────────────────────────────────
def decrypt_and_extract(file_path: Path, password: str = "", enable_ocr: bool = True) -> tuple[str, str | None]:
    ext = file_path.suffix.lower()

    if ext in IMAGE_EXTS:
        if not enable_ocr:
            return "", "OCR Disabled (image skipped)"
        try:
            return _ocr_image_bytes(file_path.read_bytes()), None
        except Exception as e:
            return "", f"OCR Error: {e}"

    from markitdown import MarkItDown

    # Handle Protected PDFs explicitly before markitdown touches them
    if ext == ".pdf":
        try:
            import pypdf
            with open(file_path, "rb") as f:
                reader = pypdf.PdfReader(f)
                if reader.is_encrypted:
                    if not password:
                        return "", "Password Protected Document (Decryption Required)"
                    decrypted = reader.decrypt(password)
                    if decrypted == 0:
                        return "", "PDFPasswordIncorrect"
                    text = ""
                    for page in reader.pages:
                        extracted_text = page.extract_text()
                        if extracted_text:
                            text += extracted_text + "\n"
                    if not text.strip() and enable_ocr:
                        text = _ocr_scanned_pdf(file_path)
                    return text, None
        except Exception as e:
            return "", f"PDF Decryption check failed: {str(e)}"

    # Handle Office Cryptography
    elif ext in {".docx", ".xlsx", ".pptx"}:
        try:
            import msoffcrypto
            with open(file_path, "rb") as f:
                file_obj = msoffcrypto.OfficeFile(f)
                if file_obj.is_encrypted():
                    if not password:
                        return "", "Password Protected Office Document (Decryption Required)"
                    decrypted_stream = io.BytesIO()
                    try:
                        file_obj.load_key(password=password)
                        file_obj.decrypt(decrypted_stream)
                    except Exception:
                        return "", "OfficePasswordIncorrect"
                    decrypted_stream.seek(0)
                    try:
                        result = MarkItDown().convert_stream(decrypted_stream, file_extension=ext)
                        return result.text_content or "", None
                    except Exception:
                        pass  # fall through to standard path if stream conversion unsupported
        except Exception as e:
            return "", f"Crypto verification error: {str(e)}"

    # Standard open fallback (also handles eml/msg/json/xml/html/csv/txt via markitdown)
    try:
        result = MarkItDown().convert(str(file_path))
        text = result.text_content or ""
        # Scanned PDF with no protection but also no text layer
        if ext == ".pdf" and not text.strip() and enable_ocr:
            text = _ocr_scanned_pdf(file_path)
        return text, None
    except Exception as exc:
        exc_str = str(exc)
        if "PDFPasswordIncorrect" in exc_str or "PasswordIncorrect" in exc_str:
            return "", "PDFPasswordIncorrect"
        return "", f"Extraction Error: {exc_str}"


# ──────────────────────────────────────────────────────────────────────────
# SCAN A SINGLE FILE
# ──────────────────────────────────────────────────────────────────────────
def scan_file(file_path: Path, password: str = "", enable_ocr: bool = True,
              max_size_mb: float = DEFAULT_MAX_SIZE_MB) -> dict:
    start = time.time()
    size_mb = round(file_path.stat().st_size / (1024 * 1024), 3)

    if size_mb > max_size_mb:
        return {
            "filename": file_path.name, "abs_path": str(file_path.resolve()),
            "rel_path": str(file_path), "size_mb": size_mb, "violations": {},
            "flagged": False, "error": f"Skipped: exceeds size limit ({max_size_mb} MB)",
            "elapsed_s": 0.0, "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    text, err = decrypt_and_extract(file_path, password, enable_ocr=enable_ocr)
    violations = scan_for_pii(text) if not err else {}
    elapsed = round(time.time() - start, 2)

    return {
        "filename":   file_path.name,
        "abs_path":   str(file_path.resolve()),
        "rel_path":   str(file_path),
        "size_mb":    size_mb,
        "violations": violations,
        "flagged":    bool(violations),
        "error":      err,
        "elapsed_s":  elapsed,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ──────────────────────────────────────────────────────────────────────────
# RESUME CACHE  (skip unchanged files on re-scan of a large fileset)
# ──────────────────────────────────────────────────────────────────────────
def _cache_path(output: str) -> Path:
    return Path(output).with_suffix(".cache.json")


def _file_signature(f: Path) -> str:
    st = f.stat()
    return f"{st.st_size}:{int(st.st_mtime)}"


def load_cache(output: str) -> dict:
    p = _cache_path(output)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def save_cache(output: str, cache: dict) -> None:
    _cache_path(output).write_text(json.dumps(cache))


# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="DPDP PII Scanner — CLI batch mode")
    parser.add_argument("folder", help="Root folder to scan recursively")
    parser.add_argument("--output", "-o", default="report.json")
    parser.add_argument("--workers", "-w", type=int, default=4)
    parser.add_argument("--password", "-p", default="")
    parser.add_argument("--resume", action="store_true", help="Skip files unchanged since last scan")
    parser.add_argument("--no-ocr", action="store_true", help="Disable OCR on images/scanned PDFs (faster)")
    parser.add_argument("--max-size-mb", type=float, default=DEFAULT_MAX_SIZE_MB)
    parser.add_argument("--progress", action="store_true",
                         help="Stream one JSON line per completed file to stdout, for live UI progress")
    args = parser.parse_args()

    root = Path(args.folder)
    if not root.exists() or not root.is_dir():
        sys.exit(1)

    all_files = collect_files(root)
    if not all_files:
        sys.exit(0)

    cache = load_cache(args.output) if args.resume else {}
    to_scan, reused = [], []
    for f in all_files:
        sig = _file_signature(f)
        key = str(f.resolve())
        if args.resume and key in cache and cache[key]["sig"] == sig:
            reused.append(cache[key]["result"])
        else:
            to_scan.append(f)

    total = len(to_scan)
    results = list(reused)
    enable_ocr = not args.no_ocr

    if args.progress:
        print(json.dumps({"type": "start", "total": total + len(reused), "to_scan": total}), flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_file, f, args.password, enable_ocr, args.max_size_mb): f
            for f in to_scan
        }
        done_count = len(reused)
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            f = futures[future]
            cache[str(f.resolve())] = {"sig": _file_signature(f), "result": res}
            done_count += 1
            if args.progress:
                print(json.dumps({
                    "type": "progress", "done": done_count, "total": total + len(reused),
                    "filename": res["filename"], "flagged": res["flagged"], "error": res["error"],
                }), flush=True)

    if args.resume:
        save_cache(args.output, cache)

    flagged = [e for e in results if e["flagged"]]
    errors = [e for e in results if e["error"]]
    report = {
        "meta": {
            "scan_root": str(root.resolve()),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_files": len(results),
            "flagged": len(flagged),
            "clean": len(results) - len(flagged) - len(errors),
            "errors": len(errors),
            "pii_hits": sum(sum(e["violations"].values()) for e in results),
        },
        "entries": results
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    if args.progress:
        print(json.dumps({"type": "final", "report": report}), flush=True)


if __name__ == "__main__":
    main()