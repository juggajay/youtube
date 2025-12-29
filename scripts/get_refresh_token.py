#!/usr/bin/env python3
"""
YouTube Refresh Token Generator

Run this script ONCE locally to generate a refresh token for GitHub Actions.
The refresh token allows headless YouTube uploads without browser login.

Usage:
    python scripts/get_refresh_token.py

After running:
1. Copy the printed refresh token
2. Go to GitHub repo -> Settings -> Secrets -> Actions
3. Add new secret: YOUTUBE_REFRESH_TOKEN = <paste token>

Also add your client_secrets.json as base64:
    base64 -i data/client_secrets.json  (Mac/Linux)
    certutil -encode data/client_secrets.json temp.b64 && type temp.b64  (Windows)

Then add: YOUTUBE_CLIENT_SECRETS_B64 = <paste base64 string>
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def get_refresh_token():
    """Run OAuth flow and print refresh token for GitHub secrets."""

    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("ERROR: Install required package:")
        print("  pip install google-auth-oauthlib")
        return

    secrets_path = Path("data/client_secrets.json")

    if not secrets_path.exists():
        print("ERROR: data/client_secrets.json not found!")
        print("")
        print("To get credentials:")
        print("1. Go to https://console.cloud.google.com")
        print("2. Create/select a project")
        print("3. Enable YouTube Data API v3")
        print("4. Go to APIs & Services > Credentials")
        print("5. Create OAuth 2.0 Client ID (Desktop app)")
        print("6. Download JSON and save as 'data/client_secrets.json'")
        return

    print("=" * 60)
    print("YouTube Refresh Token Generator")
    print("=" * 60)
    print("")
    print("A browser window will open. Log in to your Google account")
    print("and authorize the app to upload videos.")
    print("")

    # Request offline access to get refresh token
    flow = InstalledAppFlow.from_client_secrets_file(
        str(secrets_path),
        scopes=[
            "https://www.googleapis.com/auth/youtube.upload",
            "https://www.googleapis.com/auth/youtube",
        ]
    )

    # Run the flow - this opens a browser
    creds = flow.run_local_server(
        port=8080,
        prompt="consent",  # Force consent to get refresh token
        access_type="offline",  # Required for refresh token
    )

    if not creds.refresh_token:
        print("")
        print("ERROR: No refresh token received!")
        print("This can happen if you've already authorized this app.")
        print("")
        print("To fix:")
        print("1. Go to https://myaccount.google.com/permissions")
        print("2. Remove access for your app")
        print("3. Run this script again")
        return

    print("")
    print("=" * 60)
    print("SUCCESS! Copy the token below to GitHub Secrets")
    print("=" * 60)
    print("")
    print("Secret Name: YOUTUBE_REFRESH_TOKEN")
    print("")
    print("-" * 60)
    print(creds.refresh_token)
    print("-" * 60)
    print("")
    print("=" * 60)
    print("Also add your client_secrets.json as base64:")
    print("=" * 60)
    print("")
    print("Secret Name: YOUTUBE_CLIENT_SECRETS_B64")
    print("")

    # Generate base64 of client secrets
    import base64
    with open(secrets_path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()

    print("-" * 60)
    print(b64)
    print("-" * 60)
    print("")
    print("Add both secrets to: GitHub Repo > Settings > Secrets > Actions")


if __name__ == "__main__":
    get_refresh_token()
