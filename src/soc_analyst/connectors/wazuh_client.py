"""Wazuh API client for agent and rule metadata."""

from typing import Any

import httpx

from soc_analyst.config import get_settings


class WazuhClient:
    """Optional Wazuh Manager API for enriched context."""

    def __init__(
        self,
        base_url: str = "https://localhost:55000",
        user: str = "wazuh",
        password: str = "wazuh",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self._token: str | None = None

    def _headers(self) -> dict[str, str]:
        if not self._token:
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def authenticate(self) -> None:
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.post(
                    f"{self.base_url}/security/user/authenticate",
                    auth=(self.user, self.password),
                )
                response.raise_for_status()
                self._token = response.json()["data"]["token"]
        except Exception:
            self._token = None

    def health_check(self) -> dict[str, Any]:
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.get(
                    f"{self.base_url}/",
                    headers=self._headers(),
                )
                return {"status": "connected", "data": response.json()}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.get(
                    f"{self.base_url}/agents/{agent_id}",
                    headers=self._headers(),
                )
                response.raise_for_status()
                return response.json().get("data", {}).get("affected_items", [{}])[0]
        except Exception:
            return {}

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.get(
                    f"{self.base_url}/rules/{rule_id}",
                    headers=self._headers(),
                )
                response.raise_for_status()
                items = response.json().get("data", {}).get("affected_items", [])
                return items[0] if items else {}
        except Exception:
            return {}
