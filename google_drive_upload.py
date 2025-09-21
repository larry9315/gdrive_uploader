#!/usr/bin/env python3

"""
google_drive_upload.py

Standalone CLI to upload a local file to Google Drive at an optional destination path.
- Reuses existing subfolders and creates only missing ones.
- If a file with the same name exists, uploads an additional copy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

APP_NAME = "google_drive_upload"
SCOPES = ["https://www.googleapis.com/auth/drive"]
DEFAULT_LABEL = "default"
CONFIG_DIR = Path.home() / ".config" / "google_drive_upload" / "tokens"

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# This function is about locking the door on a file or folder so only you (the owner) can use it.
# 0o600 = private file (read/write for you only).
# 0o700 = private folder (full access for you only).
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

def main():
    parser = argparse.ArgumentParser(
        description="Upload a local file to Google Drive at an optional destination path."
    )
    parser.add_argument("--source-file", required=True, help="Path to the local file to upload")
    parser.add_argument("--destination-path", help="Destination path on Google Drive (e.g., /Work/Reports/2025)")
    parser.add_argument("--client-secrets", default="client_secret.json", help="Path to OAuth2 client secret JSON file")

    args = parser.parse_args()

    # TODO: implement authentication, path resolution, and upload
    print(f"[debug] Would upload '{args.source_file}' to '{args.destination_path or '/'}'")

if __name__ == "__main__":
    main()

