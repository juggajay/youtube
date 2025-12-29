#!/usr/bin/env python3
"""
Setup YouTube token pickle from environment variables.
Used by GitHub Actions to create credentials for headless uploads.
"""

import json
import os
import pickle
import sys


def setup_token():
    """Create youtube_token.pickle from env vars and client_secrets.json."""

    refresh_token = os.environ.get("YOUTUBE_REFRESH_TOKEN")
    if not refresh_token:
        print("No YOUTUBE_REFRESH_TOKEN set, skipping")
        return False

    secrets_path = "data/client_secrets.json"
    if not os.path.exists(secrets_path):
        print(f"ERROR: {secrets_path} not found")
        return False

    # Load client secrets
    with open(secrets_path) as f:
        secrets = json.load(f)

    installed = secrets.get("installed", {})
    client_id = installed.get("client_id")
    client_secret = installed.get("client_secret")

    if not client_id or not client_secret:
        print("ERROR: client_id or client_secret missing from client_secrets.json")
        return False

    # Import here to avoid issues if not installed
    try:
        from google.oauth2.credentials import Credentials
    except ImportError:
        print("ERROR: google-auth not installed")
        return False

    # Build credentials
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=[
            "https://www.googleapis.com/auth/youtube.upload",
            "https://www.googleapis.com/auth/youtube"
        ]
    )

    # Save pickle
    os.makedirs("data", exist_ok=True)
    with open("data/youtube_token.pickle", "wb") as f:
        pickle.dump(creds, f)

    print("YouTube token pickle created successfully")
    return True


if __name__ == "__main__":
    success = setup_token()
    sys.exit(0 if success else 1)
