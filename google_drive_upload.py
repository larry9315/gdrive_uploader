#!/usr/bin/env python3

"""
google_drive_upload.py

Standalone CLI to upload a local file to Google Drive at an optional destination path.
- Reuses existing subfolders and creates only missing ones.
- If a file with the same name exists, uploads an additional copy.
"""


from __future__ import annotations

# --- Standard library ---
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, List

# --- Google client libraries ---
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload          # for file uploads
from googleapiclient.errors import HttpError

# ---------- Constants ----------
APP_NAME = "google_drive_upload"
SCOPES = ["https://www.googleapis.com/auth/drive"]
DEFAULT_LABEL = "default"
CONFIG_DIR = Path.home() / ".config" / "google_drive_upload" / "tokens"

# ---------- Logging ----------
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# This function is about locking the door on a file or folder so only you (the owner) can use it.
# 0o600 = private file (read/write for you only).
# 0o700 = private folder (full access for you only).
# ---------- FS helpers ----------
def ensure_secure_path(path: Path, is_file: bool):
    try:
        os.chmod(path, 0o600 if is_file else 0o700)
    except PermissionError:
        pass

# This function makes a private, safe folder in your home directory for storing Google Drive authentication tokens, then hands you back the path to it.
def ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ensure_secure_path(CONFIG_DIR, is_file=False)
    return CONFIG_DIR

# Make sure the secure token folder exists, then give me the full path to the token file for this label.
def token_path_for_label(label: str) -> Path:
    ensure_config_dir()
    return CONFIG_DIR / f"{label}.json"

# finds and validates the Google OAuth client secrets JSON file.
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
def get_credentials(client_config: dict, label: str, headless: bool, verbose: bool, auth_port: int) -> Credentials:
    """Obtain Google credentials, reusing cache when valid.

    Uses the supported loopback flow (run_local_server). In headless mode we do
    not auto-open a browser. For remote/headless auth, use SSH port-forwarding
    and a fixed --auth-port (e.g., 8080), then open the printed URL locally.
    """
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
            port=auth_port,            # 0 = pick a free port; use a fixed port when tunneling
            prompt="consent",
            open_browser=not headless, # headless -> print URL instead of opening browser
        )
    except Exception as ex:
        eprint(f"[error] OAuth loopback flow failed: {ex}")
        eprint("[hint] If this is a remote/headless machine, try SSH port-forwarding, e.g.:")
        eprint("       ssh -L 8080:127.0.0.1:8080 <user>@<server>")
        eprint("       then re-run with: --headless --auth-port 8080")
        raise

    save_credentials(creds, label)
    return creds


def build_drive(creds: Credentials):
    # cache_discovery=False avoids writing to ~/.cache
    return build("drive", "v3", credentials=creds, cache_discovery=False)


#---- This block of code is all about figuring out where in Google Drive your file should be uploaded — and making sure that path exists ---
def normalize_segments(destination_path: str | None) -> List[str]:
    if not destination_path:
        return []
    return [seg for seg in destination_path.strip("/").split("/") if seg]

def _escape_single_quotes(s: str) -> str:
    # Drive query values are wrapped in single quotes; escape embedded single quotes
    return s.replace("'", r"\'")

def _pick_oldest(files: List[dict]) -> dict | None:
    if not files:
        return None
    return sorted(files, key=lambda f: f.get("createdTime", ""))[0]

def find_child_folder(
    drive,
    parent_id: str,
    name: str,
    shared_drive_id: str | None,
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
        "supportsAllDrives": True,
        "includeItemsFromAllDrives": True,
        "spaces": "drive",
    }
    # corpora: search within the user’s My Drive or a specific Shared Drive
    if shared_drive_id:
        params.update({"corpora": "drive", "driveId": shared_drive_id})
    else:
        params.update({"corpora": "user"})

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
        supportsAllDrives=True,
    ).execute()

def resolve_parent_folder_id(
    drive,
    destination_path: str | None,
    shared_drive_id: str | None,
    verbose: bool,
    dry_run: bool,
) -> str:
    """
    Returns the target parent folder ID where the file should be uploaded.
    Uses Shared Drive root if --shared-drive is set; otherwise My Drive root.
    Creates only missing path segments (unless --dry-run).
    """
    current_parent = shared_drive_id if shared_drive_id else "root"

    # Once we discover the first missing segment in dry-run,
    # we stop querying Drive and just simulate creation for the rest.
    simulate_chain = False

    for seg in normalize_segments(destination_path):
        if dry_run and simulate_chain:
            # We already know the remainder doesn't exist; just simulate
            if verbose:
                eprint(f"[dry-run] would create folder '{seg}' under {current_parent}")
            current_parent = f"dryrun_{seg}"
            continue

        # Try to reuse an existing folder (only real query when not simulating)
        existing = find_child_folder(drive, current_parent, seg, shared_drive_id, verbose)

        if existing:
            current_parent = existing["id"]
            if verbose:
                eprint(f"[info] reuse: /{seg} -> {current_parent}")
            continue

        # Missing segment
        if dry_run:
            if verbose:
                eprint(f"[dry-run] would create folder '{seg}' under {current_parent}")
            current_parent = f"dryrun_{seg}"
            simulate_chain = True  # from now on, don't hit the API
        else:
            created = create_child_folder(drive, current_parent, seg, verbose)
            current_parent = created["id"]

    return current_parent


# ---------- CLI ----------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Upload a local file to Google Drive at an optional destination path."
    )
    p.add_argument("--source-file", required=True, help="Path to the local file to upload")
    p.add_argument("--destination-path", help="Destination path on Google Drive (e.g., /Work/Reports/2025)")
    p.add_argument("--client-secrets", help="Path to OAuth 2.0 client JSON (Desktop app). If not provided, uses env GOOGLE_CLIENT_SECRETS.")
    p.add_argument("--account-label", default=DEFAULT_LABEL, help="Token cache label for switching accounts.")
    p.add_argument("--headless", action="store_true", help="Don't auto-open a browser; print the auth URL instead.")
    p.add_argument("--auth-port", type=int, default=0, help="Loopback port for OAuth (0 = auto). Use a fixed port (e.g., 8080) when tunneling via SSH.")
    p.add_argument("--verbose", action="store_true", help="Verbose logging.")
    p.add_argument("--auth-only", action="store_true", help="Authenticate and print the signed-in email, then exit.")
    p.add_argument("--shared-drive", help="Shared Drive ID to use as root (optional).")
    p.add_argument("--dry-run", action="store_true", help="Show the plan (reuse/create) without making changes.")
    return p.parse_args()

# ---------- Main ----------
def main():
    args = parse_args()

    # Validate source path early (even for --auth-only we keep the contract simple).
    src = Path(args.source_file)
    if not src.exists() or not src.is_file():
        eprint(f"[error] Source file not found or not a file: {src}")
        sys.exit(3)

    client_config = load_client_config(args.client_secrets)
    creds = get_credentials(client_config, args.account_label, args.headless, args.verbose, args.auth_port)

    # Prove auth works by calling Drive 'about'
    try:
        drive = build_drive(creds)
        about = drive.about().get(fields="user(emailAddress,displayName)").execute()
        user = about.get("user", {})
        email = user.get("emailAddress", "<unknown>")
        name = user.get("displayName", "")
        print(f"Authenticated as: {name} <{email}>")
    except Exception as ex:
        eprint(f"[error] Failed to query Drive API: {ex}")
        sys.exit(4)

    if args.auth_only:
        return  # stop here for auth-only runs

    # Resolve destination folder (reusing existing segments; create only missing ones)
    try:
        parent_id = resolve_parent_folder_id(
            drive=drive,
            destination_path=args.destination_path,
            shared_drive_id=args.shared_drive,
            verbose=args.verbose,
            dry_run=args.dry_run,
        )
    except HttpError as ex:
        code = getattr(ex.resp, "status", None)
        if code and int(code) == 403:
            eprint("[error] Permission denied resolving destination (403). Check folder access or Shared Drive membership.")
            sys.exit(5)
        eprint(f"[error] Failed to resolve destination path: {ex}")
        sys.exit(6)

    if args.dry_run:
        eprint("[dry-run] Resolution complete.")
        eprint(f"[dry-run] Would upload '{src}' to parent folder id: {parent_id}")
        return

    # Only runs if not dry-run
    print(f"[debug] Destination resolved. Parent folder id: {parent_id}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        eprint("\n[info] Aborted by user.")
        sys.exit(130)