from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class LoginEvent:
    """Represents one authentication event."""

    timestamp: datetime
    username: str
    ip_address: str
    country: str
    success: bool

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LoginEvent":
        required = {"timestamp", "username", "ip_address", "country", "success"}
        missing = required - payload.keys()
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(sorted(missing))}")

        if not isinstance(payload["success"], bool):
            raise ValueError("'success' must be true or false")

        try:
            timestamp = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid ISO-8601 timestamp") from exc

        return cls(
            timestamp=timestamp,
            username=str(payload["username"]).strip(),
            ip_address=str(payload["ip_address"]).strip(),
            country=str(payload["country"]).strip(),
            success=payload["success"],
        )
