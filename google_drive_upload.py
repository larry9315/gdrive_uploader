#!/usr/bin/env python3

"""
google_drive_upload.py

Standalone CLI to upload a local file to Google Drive at an optional destination path.
- Reuses existing subfolders and creates only missing ones.
- If a file with the same name exists, uploads an additional copy.
"""

import argparse

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

