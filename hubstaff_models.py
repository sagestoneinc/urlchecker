"""Hubstaff task and user models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class HubstaffUser:
    id: str
    name: str
    email: str = ""

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "HubstaffUser":
        return cls(
            id=str(payload.get("id", "")),
            name=payload.get("name") or payload.get("full_name") or "Unknown",
            email=payload.get("email", ""),
        )


@dataclass
class HubstaffTask:
    id: str
    title: str
    description: str = ""
    project_id: str = ""
    project_name: str = ""
    status_id: str = ""
    status_name: str = ""
    assignees: list[HubstaffUser] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    due_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    web_url: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "HubstaffTask":
        assignees_payload = payload.get("assignees") or payload.get("users") or []
        assignees = [
            HubstaffUser.from_api(item)
            for item in assignees_payload
            if isinstance(item, dict)
        ]
        labels_payload = payload.get("labels") or []
        labels: list[str] = []
        for label in labels_payload:
            if isinstance(label, str):
                labels.append(label)
            elif isinstance(label, dict) and label.get("name"):
                labels.append(str(label["name"]))

        return cls(
            id=str(payload.get("id", "")),
            title=payload.get("title") or payload.get("name") or "",
            description=payload.get("description", ""),
            project_id=str((payload.get("project") or {}).get("id", payload.get("project_id", ""))),
            project_name=(payload.get("project") or {}).get("name", payload.get("project_name", "")),
            status_id=str((payload.get("status") or {}).get("id", payload.get("status_id", ""))),
            status_name=(payload.get("status") or {}).get("name", payload.get("status_name", "")),
            assignees=assignees,
            labels=labels,
            due_at=payload.get("due_at") or payload.get("due_date"),
            created_at=payload.get("created_at"),
            updated_at=payload.get("updated_at"),
            web_url=payload.get("web_url") or payload.get("url"),
            raw=payload,
        )

    @property
    def assignee_names(self) -> str:
        if not self.assignees:
            return "Unassigned"
        return ", ".join(user.name for user in self.assignees)

    @property
    def is_overdue(self) -> bool:
        if not self.due_at:
            return False
        due = _parse_iso(self.due_at)
        if not due:
            return False
        return due < datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_iso(value: str) -> Optional[datetime]:
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
