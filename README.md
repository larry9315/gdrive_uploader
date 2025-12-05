# Google Drive Uploader

Uploads a local file to Google Drive at an optional destination path.

This project provides a standalone Python command-line application that uploads a specified local file
into an arbitrarily deep path on Google Drive. If the remote folder path does not fully exist, the tool
reuses existing folders and creates only the missing ones, ensuring no path duplication.
If a file with the same name already exists in the target folder, the uploader automatically renames the
new upload:

file.txt → file (1).txt
file (1).txt → file (2).txt

Features:

- Upload any local file to any Google Drive path.
- Automatically discovers and creates folder paths.
- Automatic duplicate naming resolution.
- Secure OAuth2 desktop authentication.
- Verbose and dry-run modes.

## Usage

```bash
python3 google_drive_upload.py --source-file ./example.txt --destination-path "/Uploads/Tests"
```

Usage Examples:
python google_drive_upload.py --source-file example.txt --destination-path "/A/B/C"
python google_drive_upload.py --source-file test.txt --dry-run --verbose

Token Storage:
Stored securely at ~/.config/google_drive_upload/tokens/

Exit Codes:
3 - Invalid source file
4 - OAuth error
5 - Permission denied
6 - Upload/destination failure
130 - User interrupt
