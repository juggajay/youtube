#!/usr/bin/env python3
"""
YouTube OAuth Setup Script

Run this once to authenticate with YouTube:
    python scripts/setup_youtube.py

After authentication, the pipeline can upload videos automatically.

Prerequisites:
1. Create a project at console.cloud.google.com
2. Enable YouTube Data API v3
3. Create OAuth 2.0 credentials (Desktop app type)
4. Download as client_secrets.json and place in project root
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.publish.youtube import authenticate_youtube, is_youtube_authenticated


def main():
    print("=" * 60)
    print("YouTube OAuth Setup")
    print("=" * 60)

    if is_youtube_authenticated():
        print("\n✓ Already authenticated with YouTube!")
        print("  Token stored at: data/youtube_token.pickle")
        response = input("\nRe-authenticate? (y/N): ")
        if response.lower() != "y":
            return

    # Check for client secrets
    secrets_path = Path("client_secrets.json")
    if not secrets_path.exists():
        print("\n✗ client_secrets.json not found!")
        print("\nTo get credentials:")
        print("1. Go to https://console.cloud.google.com")
        print("2. Create a new project (or select existing)")
        print("3. Enable YouTube Data API v3")
        print("4. Go to APIs & Services > Credentials")
        print("5. Create OAuth 2.0 Client ID (Desktop app)")
        print("6. Download JSON and save as 'client_secrets.json'")
        return

    print("\nStarting OAuth flow...")
    print("A browser window will open. Log in to your Google account")
    print("and authorize the app to upload videos.\n")

    success = authenticate_youtube(str(secrets_path))

    if success:
        print("\n" + "=" * 60)
        print("✓ YouTube authentication successful!")
        print("=" * 60)
        print("\nThe pipeline can now upload videos automatically.")
        print("Token will refresh automatically when needed.")
    else:
        print("\n✗ Authentication failed. Check the logs for details.")


if __name__ == "__main__":
    main()
