"""Hubstaff authentication helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests


@dataclass
class AuthTokens:
    access_token: str
    refresh_token: str = ""
    expires_at: Optional[datetime] = None


class HubstaffAuth:
    def __init__(
        self,
        access_token: str,
        *,
        refresh_token: str = "",
        client_id: str = "",
        client_secret: str = "",
        token_url: str = "",
        timeout_seconds: int = 30,
    ) -> None:
        self._tokens = AuthTokens(access_token=access_token, refresh_token=refresh_token)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._timeout_seconds = timeout_seconds

    @property
    def access_token(self) -> str:
        return self._tokens.access_token

    def authorization_header(self) -> dict[str, str]:
        self.refresh_if_needed()
        return {"Authorization": f"Bearer {self._tokens.access_token}"}

    def refresh_if_needed(self) -> None:
        expires_at = self._tokens.expires_at
        if not expires_at:
            return
        if datetime.now(timezone.utc) < expires_at - timedelta(minutes=1):
            return
        self._refresh_token()

    def _refresh_token(self) -> None:
        if not (self._token_url and self._tokens.refresh_token and self._client_id and self._client_secret):
            return
        response = requests.post(
            self._token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._tokens.refresh_token,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        self._tokens.access_token = data.get("access_token", self._tokens.access_token)
        self._tokens.refresh_token = data.get("refresh_token", self._tokens.refresh_token)
        expires_in = data.get("expires_in")
        if isinstance(expires_in, (int, float)):
            self._tokens.expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))
