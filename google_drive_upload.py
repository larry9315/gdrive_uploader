#!/usr/bin/env python3
from __future__ import annotations

"""
google_drive_upload.py

Standalone CLI to upload a local file to Google Drive at an optional destination path.

Features:
- Reuses existing subfolders and creates only missing ones.
- Operates on the user's My Drive.
- If a file with the same name exists at the destination, uploads an additional copy
  by auto-renaming it with a numeric suffix: "name (1).ext", "name (2).ext", etc.
"""

import argparse
import json
import mimetypes
import os
import sys
import time
from pathlib import Path
from typing import Optional, List

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.errors import HttpError

# ---------- Constants ----------
SCOPES = ["https://www.googleapis.com/auth/drive"]
DEFAULT_LABEL = "default"
CONFIG_DIR = Path.home() / ".config" / "google_drive_upload" / "tokens"
DEFAULT_CHUNK_MB = 32
MAX_RETRIES = 5


# ---------- Logging ----------
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# ---------- FS helpers ----------
def ensure_secure_path(path: Path, is_file: bool):
    """Lock down permissions: dir 700, file 600."""
    try:
        os.chmod(path, 0o600 if is_file else 0o700)
    except PermissionError:
        # Non-fatal on some filesystems
        pass


def ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ensure_secure_path(CONFIG_DIR, is_file=False)
    return CONFIG_DIR


def token_path_for_label(label: str) -> Path:
    ensure_config_dir()
    return CONFIG_DIR / f"{label}.json"


# ---------- Client secrets ----------
def load_client_config(client_secrets_path: Optional[str]) -> dict:
    path = client_secrets_path or os.environ.get("GOOGLE_CLIENT_SECRETS")
    if not path:
        eprint("[error] Missing OAuth client secrets. Provide --client-secrets or set GOOGLE_CLIENT_SECRETS.")
        sys.exit(4)
    p = Path(path)
    if not p.exists():
        eprint(f"[error] Client secrets not found at: {p}")
        sys.exit(4)
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as ex:
        eprint(f"[error] Failed to read client secrets JSON: {ex}")
        sys.exit(4)


# ---------- Token cache ----------
def save_credentials(creds: Credentials, label: str):
    path = token_path_for_label(label)
    data = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    ensure_secure_path(path, is_file=True)


def load_cached_credentials(label: str) -> Optional[Credentials]:
    path = token_path_for_label(label)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    try:
        return Credentials(
            token=data.get("token"),
            refresh_token=data.get("refresh_token"),
            token_uri=data.get("token_uri"),
            client_id=data.get("client_id"),
            client_secret=data.get("client_secret"),
            scopes=data.get("scopes"),
        )
    except Exception:
        return None


# ---------- OAuth + Drive client ----------
def get_credentials(
    client_config: dict,
    label: str,
    headless: bool,
    verbose: bool,
    auth_port: int,
) -> Credentials:
    """Obtain Google credentials, reusing cache when valid."""
    cached = load_cached_credentials(label)
    if cached and cached.valid:
        if verbose:
            eprint("[info] Using cached credentials.")
        return cached

    if verbose:
        eprint("[info] Starting OAuth flow...")

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)

    try:
        creds = flow.run_local_server(
            host="127.0.0.1",
            port=auth_port,            # 0 = pick a free port
            prompt="consent",
            open_browser=not headless, # headless -> print URL instead of auto-open
        )
    except Exception as ex:
        eprint(f"[error] OAuth loopback flow failed: {ex}")
        eprint("[hint] If this is a remote/headless machine, try SSH port-forwarding, e.g.:")
        eprint("       ssh -L 8080:127.0.0.1:8080 <user>@<server>")
        eprint("       then re-run with: --headless --auth-port 8080")
        sys.exit(4)

    save_credentials(creds, label)
    return creds


def build_drive(creds: Credentials):
    # cache_discovery=False avoids writing discovery cache under ~/.cache
    return build("drive", "v3", credentials=creds, cache_discovery=False)


# ---------- Path resolution ----------
def normalize_segments(destination_path: str | None) -> List[str]:
    if not destination_path:
        return []
    return [seg for seg in destination_path.strip("/").split("/") if seg]


def _escape_single_quotes(s: str) -> str:
    return s.replace("'", r"\'")


def _pick_oldest(files: List[dict]) -> dict | None:
    if not files:
        return None
    return sorted(files, key=lambda f: f.get("createdTime", ""))[0]


def find_child_folder(
    drive,
    parent_id: str,
    name: str,
    verbose: bool,
) -> dict | None:
    q = (
        f"name = '{_escape_single_quotes(name)}' and "
        f"mimeType = 'application/vnd.google-apps.folder' and "
        f"'{parent_id}' in parents and trashed = false"
    )
    params = {
        "q": q,
        "fields": "files(id,name,createdTime)",
        "pageSize": 100,
        "corpora": "user",
        "spaces": "drive",
        "supportsAllDrives": False,
        "includeItemsFromAllDrives": False,
    }

    if verbose:
        eprint(f"[debug] search child: parent={parent_id} name='{name}'")
    resp = drive.files().list(**params).execute()
    files = resp.get("files", [])
    if len(files) > 1 and verbose:
        eprint(f"[warn] Duplicate folders named '{name}' under parent {parent_id}; choosing oldest.")
    return _pick_oldest(files)


def create_child_folder(
    drive,
    parent_id: str,
    name: str,
    verbose: bool,
) -> dict:
    if verbose:
        eprint(f"[info] create folder: '{name}' under {parent_id}")
    body = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id],
    }
    return drive.files().create(
        body=body,
        fields="id,name,createdTime",
        supportsAllDrives=False,
    ).execute()


def resolve_parent_folder_id(
    drive,
    destination_path: str | None,
    verbose: bool,
    dry_run: bool,
) -> str:
    """
    Returns the target parent folder ID where the file should be uploaded.
    Uses My Drive root as the starting point.
    Reuses existing segments and creates only missing folders (unless --dry-run).
    """
    current_parent = "root"

    for seg in normalize_segments(destination_path):
        existing = find_child_folder(drive, current_parent, seg, verbose)
        if existing:
            current_parent = existing["id"]
            if verbose:
                eprint(f"[info] reuse: /{seg} -> {current_parent}")
            continue

        if dry_run:
            if verbose:
                eprint(f"[dry-run] would create folder '{seg}' under {current_parent}")
            current_parent = f"dryrun_{seg}"
        else:
            created = create_child_folder(drive, current_parent, seg, verbose)
            current_parent = created["id"]

    return current_parent


# ---------- Upload helpers ----------
def infer_mime(path: Path) -> Optional[str]:
    mime, _ = mimetypes.guess_type(str(path))
    return mime


def upload_with_retries(request, verbose: bool) -> dict:
    """Drive resumable upload with retry on transient errors."""
    attempt = 0
    response = None
    while True:
        try:
            status, response = request.next_chunk()
            if status and verbose:
                pct = int(status.progress() * 100)
                eprint(f"[progress] {pct}%")
            if response is not None:
                return response
        except HttpError as err:
            code = getattr(err, "status_code", None) or getattr(err.resp, "status", None)
            if code and int(code) in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                attempt += 1
                backoff = min(2 ** attempt, 32)
                eprint(f"[warn] transient HTTP {code}; retrying in {backoff}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(backoff)
                continue
            raise
        except Exception as ex:
            if attempt < MAX_RETRIES:
                attempt += 1
                backoff = min(2 ** attempt, 32)
                eprint(f"[warn] upload error: {ex}; retrying in {backoff}s (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(backoff)
                continue
            raise


def upload_file(
    drive,
    parent_id: str,
    source_path: Path,
    upload_name: str,
    mime_type: Optional[str],
    verbose: bool,
) -> tuple[str, Optional[str]]:
    media = MediaFileUpload(
        str(source_path),
        mimetype=mime_type,
        chunksize=DEFAULT_CHUNK_MB * 1024 * 1024,
        resumable=True,
    )
    metadata = {
        "name": upload_name,
        "parents": [parent_id],
    }
    request = drive.files().create(
        body=metadata,
        media_body=media,
        fields="id,webViewLink",
        supportsAllDrives=False,
    )
    resp = upload_with_retries(request, verbose)
    file_id = resp.get("id")
    web_view = resp.get("webViewLink")
    return file_id, web_view


def compute_upload_name(
    drive,
    parent_id: str,
    original_name: str,
    verbose: bool,
) -> str:
    """
    Compute a non-conflicting name in the target folder.

    If 'file.txt' does not exist -> 'file.txt'
    If 'file.txt' exists        -> 'file (1).txt'
    If 'file (1).txt' exists    -> 'file (2).txt'
    etc.
    """
    stem, ext = os.path.splitext(original_name)

    # List all items in this folder and examine their names
    q = f"'{parent_id}' in parents and trashed = false"
    params = {
        "q": q,
        "fields": "files(id,name,createdTime)",
        "pageSize": 1000,
        "corpora": "user",
        "spaces": "drive",
        "supportsAllDrives": False,
        "includeItemsFromAllDrives": False,
    }

    if verbose:
        eprint(f"[debug] listing existing names in parent {parent_id} to compute duplicate suffix")

    resp = drive.files().list(**params).execute()
    files = resp.get("files", [])

    existing_names = {f["name"] for f in files}

    # If plain name doesn't exist at all, just use it.
    if original_name not in existing_names:
        return original_name

    # Collect indices for patterns like: "<stem> (N)<ext>"
    used_indices = {0}  # 0 represents original_name
    for name in existing_names:
        if not name.startswith(stem):
            continue
        prefix = f"{stem} ("
        suffix = f"){ext}"
        if name.startswith(prefix) and name.endswith(suffix):
            middle = name[len(prefix) : -len(suffix)]
            try:
                n = int(middle)
                used_indices.add(n)
            except ValueError:
                continue

    # Find the smallest non-negative integer not used yet
    n = 1
    while n in used_indices:
        n += 1

    candidate = f"{stem} ({n}){ext}"
    if verbose:
        eprint(f"[info] Duplicate name detected; using '{candidate}'")
    return candidate


# ---------- CLI ----------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Upload a local file to Google Drive at an optional destination path."
    )
    p.add_argument("--source-file", required=True, help="Path to the local file to upload")
    p.add_argument("--destination-path", help="Destination path on Google Drive (e.g., /Work/Reports/2025)")
    p.add_argument(
        "--client-secrets",
        help="Path to OAuth 2.0 client JSON (Desktop app). If not provided, uses env GOOGLE_CLIENT_SECRETS.",
    )
    p.add_argument("--account-label", default=DEFAULT_LABEL, help="Token cache label for switching accounts.")
    p.add_argument("--headless", action="store_true", help="Don't auto-open a browser; print the auth URL instead.")
    p.add_argument(
        "--auth-port",
        type=int,
        default=0,
        help="Loopback port for OAuth (0 = auto). Use a fixed port (e.g., 8080) when tunneling via SSH.",
    )
    p.add_argument("--dry-run", action="store_true", help="Show the plan (reuse/create) without making changes.")
    p.add_argument("--verbose", action="store_true", help="Verbose logging.")
    return p.parse_args()


# ---------- Main ----------
def main():
    args = parse_args()

    # Validate source path early.
    src = Path(args.source_file)
    if not src.exists() or not src.is_file():
        eprint(f"[error] Source file not found or not a file: {src}")
        sys.exit(3)

    client_config = load_client_config(args.client_secrets)
    creds = get_credentials(
        client_config,
        label=args.account_label,
        headless=args.headless,
        verbose=args.verbose,
        auth_port=args.auth_port,
    )

    # Prove auth works & build Drive client
    try:
        drive = build_drive(creds)
        about = drive.about().get(fields="user(emailAddress,displayName)").execute()
        user = about.get("user", {})
        email = user.get("emailAddress", "<unknown>")
        name = user.get("displayName", "")
        if args.verbose:
            eprint(f"[info] Authenticated as: {name} <{email}>")
    except Exception as ex:
        eprint(f"[error] Failed to query Drive API: {ex}")
        sys.exit(4)

    # Resolve destination folder
    try:
        parent_id = resolve_parent_folder_id(
            drive=drive,
            destination_path=args.destination_path,
            verbose=args.verbose,
            dry_run=args.dry_run,
        )
    except HttpError as ex:
        code = getattr(ex.resp, "status", None)
        if code and int(code) == 403:
            eprint("[error] Permission denied resolving destination (403). Check folder access.")
            sys.exit(5)
        eprint(f"[error] Failed to resolve destination path: {ex}")
        sys.exit(6)

    if args.dry_run:
        eprint("[dry-run] Resolution complete.")
        eprint(f"[dry-run] Would upload '{src}' to parent folder id: {parent_id}")
        return

    # Compute final upload name that avoids conflicts by adding (1), (2), ...
    try:
        upload_name = compute_upload_name(
            drive=drive,
            parent_id=parent_id,
            original_name=src.name,
            verbose=args.verbose,
        )
    except HttpError as ex:
        code = getattr(ex.resp, "status", None)
        if code and int(code) == 403:
            eprint("[error] Permission denied listing folder contents (403).")
            sys.exit(5)
        eprint(f"[error] Failed to compute upload name: {ex}")
        sys.exit(6)

    if args.verbose:
        eprint(f"[info] Final upload name: {upload_name}")

    # ---- Upload ----
    mime = infer_mime(src)

    try:
        file_id, web_view = upload_file(
            drive=drive,
            parent_id=parent_id,
            source_path=src,
            upload_name=upload_name,
            mime_type=mime,
            verbose=args.verbose,
        )
    except HttpError as ex:
        code = getattr(ex.resp, "status", None)
        if code and int(code) == 403:
            eprint("[error] Permission denied uploading (403). Check write access to the destination.")
            sys.exit(5)
        eprint(f"[error] Upload failed: {ex}")
        sys.exit(6)
    except Exception as ex:
        eprint(f"[error] Upload failed: {ex}")
        sys.exit(6)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        eprint("\n[info] Aborted by user.")
        sys.exit(130)