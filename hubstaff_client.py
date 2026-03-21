"""Hubstaff Tasks API client used by the optional Telegram task bot."""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from hubstaff_auth import HubstaffAuth
from hubstaff_models import HubstaffTask, HubstaffUser

logger = logging.getLogger(__name__)


class HubstaffClient:
    def __init__(
        self,
        *,
        auth: HubstaffAuth,
        base_url: str,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        tasks_path: str = "/v2/tasks",
        users_path: str = "/v2/users",
        statuses_path: str = "/v2/task_statuses",
        done_status_ids: Optional[list[str]] = None,
    ) -> None:
        self._auth = auth
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._tasks_path = tasks_path
        self._users_path = users_path
        self._statuses_path = statuses_path
        self._done_status_ids = [str(item) for item in (done_status_ids or []) if str(item)]

        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST", "PATCH", "PUT"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session = requests.Session()
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def list_tasks(self, *, filters: Optional[dict[str, Any]] = None, per_page: int = 50) -> list[HubstaffTask]:
        tasks: list[HubstaffTask] = []
        page = 1
        while True:
            params: dict[str, Any] = {"page": page, "per_page": per_page}
            if filters:
                params.update(filters)
            payload = self._request("GET", self._tasks_path, params=params)
            items = self._extract_items(payload, ("tasks", "data", "items"))
            tasks.extend(HubstaffTask.from_api(item) for item in items)
            if not self._has_next_page(payload, page, per_page, len(items)):
                break
            page += 1
        return tasks

    def get_task(self, task_id: str) -> HubstaffTask:
        payload = self._request("GET", f"{self._tasks_path}/{task_id}")
        task_payload = payload.get("task") if isinstance(payload, dict) else None
        if isinstance(task_payload, dict):
            return HubstaffTask.from_api(task_payload)
        if isinstance(payload, dict):
            return HubstaffTask.from_api(payload)
        raise ValueError(f"Task {task_id} not found")

    def update_task(self, task_id: str, fields: dict[str, Any]) -> HubstaffTask:
        payload = self._request("PATCH", f"{self._tasks_path}/{task_id}", json={"task": fields})
        task_payload = payload.get("task") if isinstance(payload, dict) else payload
        if not isinstance(task_payload, dict):
            raise ValueError("Hubstaff returned invalid task payload")
        return HubstaffTask.from_api(task_payload)

    def search_users(self, query: str = "") -> list[HubstaffUser]:
        params: dict[str, Any] = {}
        if query:
            params["search"] = query
        payload = self._request("GET", self._users_path, params=params)
        items = self._extract_items(payload, ("users", "data", "items"))
        users = [HubstaffUser.from_api(item) for item in items]
        if not query:
            return users
        lowered = query.lower()
        return [u for u in users if lowered in u.name.lower() or lowered in u.email.lower()]

    def assign_task(self, task_id: str, assignee_ids: list[str]) -> HubstaffTask:
        values = [str(item) for item in assignee_ids if str(item)]
        return self.update_task(task_id, {"assignee_ids": values})

    def complete_task(self, task_id: str) -> HubstaffTask:
        task = self.get_task(task_id)
        done_status = self._find_done_status_id(project_id=task.project_id)
        if not done_status:
            raise ValueError(
                "Unable to determine Hubstaff done status. Set HUBSTAFF_DONE_STATUS_IDS."
            )
        return self.update_task(task_id, {"status_id": done_status})

    def _find_done_status_id(self, *, project_id: str = "") -> str:
        if self._done_status_ids:
            return self._done_status_ids[0]

        params: dict[str, Any] = {}
        if project_id:
            params["project_id"] = project_id
        payload = self._request("GET", self._statuses_path, params=params)
        items = self._extract_items(payload, ("statuses", "task_statuses", "data", "items"))
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_id = item.get("id")
            if raw_id is None:
                continue
            name = str(item.get("name", "")).lower()
            if item.get("is_done") is True or item.get("done") is True:
                return str(raw_id)
            if name in {"done", "completed", "complete", "closed"}:
                return str(raw_id)
        return ""

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path if path.startswith('/') else '/' + path}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        headers.update(self._auth.authorization_header())

        response = self._session.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json,
            timeout=self._timeout_seconds,
        )
        if response.status_code == 429:
            raise RuntimeError("Hubstaff API rate limited (HTTP 429)")
        response.raise_for_status()
        if not response.text:
            return {}
        payload = response.json()
        if isinstance(payload, dict):
            return payload
        return {"items": payload}

    @staticmethod
    def _extract_items(payload: dict[str, Any], candidates: tuple[str, ...]) -> list[dict[str, Any]]:
        for key in candidates:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        items = payload.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return []

    @staticmethod
    def _has_next_page(payload: dict[str, Any], page: int, per_page: int, count: int) -> bool:
        pagination = payload.get("pagination")
        if isinstance(pagination, dict):
            total_pages = pagination.get("total_pages")
            if isinstance(total_pages, int):
                return page < total_pages
            has_next = pagination.get("has_next")
            if isinstance(has_next, bool):
                return has_next
        links = payload.get("links")
        if isinstance(links, dict) and links.get("next"):
            return True
        return count >= per_page
