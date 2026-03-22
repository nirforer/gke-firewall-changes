"""Authentication helpers for GCP."""

import subprocess

import google.auth
import google.auth.credentials
import google.auth.transport.requests


class GcloudCredentials(google.auth.credentials.Credentials):
    """Credentials that use `gcloud auth print-access-token`.
    Works in Cloud Shell without ADC login."""

    def __init__(self):
        super().__init__()
        self.token = None
        self.expiry = None

    def refresh(self, request):
        result = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise google.auth.exceptions.RefreshError(
                "Failed to get access token. Run: gcloud auth login"
            )
        self.token = result.stdout.strip()

    @property
    def valid(self):
        return bool(self.token)


def get_credentials():
    """Try ADC first, fall back to gcloud user credentials."""
    try:
        creds, _ = google.auth.default()
        creds.refresh(google.auth.transport.requests.Request())
        return creds
    except Exception:
        creds = GcloudCredentials()
        creds.refresh(None)
        return creds
