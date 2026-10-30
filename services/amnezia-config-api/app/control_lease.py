"""Fresh control and bounded permission to serve existing peers are separate.

Restart closes both gates. Replaying a prior sequence cannot reopen them.
The runtime watchdog is independent and must remain short.
"""

import time
from datetime import datetime, timedelta
from typing import Literal
from .domain import Fault, expiry, now, stamp

from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator


class LeaseCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    operation: str = Field(pattern="^control_lease$")
    client_id: None = None
    controller_id: str = Field(pattern=r"^ctl_[a-f0-9]{32}$")
    sequence: int = Field(ge=1, le=2147483647)
    valid_until: str
    version: Literal[1, 2] = 1
    offline_until: str | None = None

    @field_validator("version", mode="before")
    @classmethod
    def integer_version(cls, value):
        if type(value) is not int:
            raise ValueError("invalid lease version")
        return value

    @model_validator(mode="after")
    def matching_version(self):
        if (self.version == 2) != (self.offline_until is not None):
            raise ValueError("offline permission requires version 2")
        return self


MAX_SECONDS = 120
MAX_OFFLINE_SECONDS = 3600


def remaining_until(value, current):
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00")) - current
    ).total_seconds()


class ControlLease:
    def __init__(self, store, clock=time.monotonic):
        self.store, self.clock = store, clock
        self.deadline = 0.0
        self.offline_deadline = 0.0
        self.peer_deadlines = {}
        with store.db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS control_lease (id INTEGER PRIMARY KEY CHECK(id=1), controller TEXT NOT NULL, sequence INTEGER NOT NULL, valid_until TEXT NOT NULL)"
            )
            # Keep v1 layout intact. Old code ignores this extension and restarts
            # closed; it cannot accidentally serve with a long v1 permission.
            db.execute(
                "CREATE TABLE IF NOT EXISTS control_offline (id INTEGER PRIMARY KEY CHECK(id=1), controller TEXT NOT NULL, sequence INTEGER NOT NULL, offline_until TEXT NOT NULL)"
            )

    def row(self):
        with self.store.db() as db:
            row = db.execute(
                "SELECT c.*,o.offline_until FROM control_lease c LEFT JOIN control_offline o ON c.id=o.id AND c.controller=o.controller AND c.sequence=o.sequence WHERE c.id=1"
            ).fetchone()
            return dict(row) if row else None

    def fresh(self):
        row = self.row()
        if row is None:
            return True
        if self.clock() >= self.deadline or row["valid_until"] <= stamp(now()):
            self.deadline = 0.0
            return False
        return True

    def allowed(self):
        row = self.row()
        if row is None:
            return True
        if row["offline_until"] is None:
            return self.fresh()
        if self.clock() >= self.offline_deadline or row["offline_until"] <= stamp(
            now()
        ):
            self.offline_deadline = 0.0
            return False
        return True

    def _peer_remaining(self, row):
        end, ident = row["expires_at"], row["client_id"]
        saved = self.peer_deadlines.get(ident)
        wall_remaining = remaining_until(end, now())
        if saved is None or saved[0] != end:
            saved = (end, self.clock() + max(0.0, wall_remaining))
        left = min(wall_remaining, saved[1] - self.clock())
        if left <= 0:
            saved = (end, 0.0)  # Clock rollback must not resurrect expiry.
        self.peer_deadlines[ident] = saved
        return left

    def peer_allowed(self, row):
        if not self.allowed():
            return False
        lease = self.row()
        return (
            not lease or lease["offline_until"] is None or self._peer_remaining(row) > 0
        )

    def describe(self):
        row = self.row()
        return {
            "version": 1,
            "supported_versions": [1, 2],
            "required": row is not None,
            "active": self.allowed(),
            "fresh": self.fresh(),
            "controller_id": row["controller"] if row else None,
            "sequence": row["sequence"] if row else 0,
            "valid_until": row["valid_until"] if row else None,
            "offline_until": row["offline_until"] if row else None,
            "server_time": stamp(now()),
            "max_seconds": MAX_SECONDS,
            "max_offline_seconds": MAX_OFFLINE_SECONDS,
        }

    def grant(self, controller, sequence, valid_until, offline_until=None):
        end = expiry(valid_until)
        offline_end = expiry(offline_until) if offline_until is not None else None
        current = now()
        remaining = remaining_until(end, current)
        offline_remaining = (
            remaining_until(offline_end, current) if offline_end else None
        )
        if (
            not controller
            or sequence is None
            or not 0 < remaining <= MAX_SECONDS
            or (
                offline_end is not None
                and not remaining <= offline_remaining <= MAX_OFFLINE_SECONDS
            )
        ):
            raise Fault("invalid_control_lease", 422)
        # Anchor BEFORE committing SQLite: slow storage cannot extend a grant.
        monotonic_start = self.clock()
        with self.store.db() as db:
            old = db.execute("SELECT * FROM control_lease WHERE id=1").fetchone()
            previous_offline = db.execute(
                "SELECT * FROM control_offline WHERE id=1"
            ).fetchone()
            if old:
                if old["controller"] != controller:
                    raise Fault("controller_conflict")
                old_end = (
                    previous_offline["offline_until"]
                    if previous_offline
                    and previous_offline["controller"] == controller
                    and previous_offline["sequence"] == old["sequence"]
                    else None
                )
                if sequence < old["sequence"] or (
                    sequence == old["sequence"]
                    and (end != old["valid_until"] or offline_end != old_end)
                ):
                    raise Fault("lease_sequence_conflict")
                if sequence == old["sequence"]:
                    return  # Replay never rearms either expired/restarted gate.
            db.execute(
                "INSERT OR REPLACE INTO control_lease VALUES (1,?,?,?)",
                (controller, sequence, end),
            )
            db.execute("DELETE FROM control_offline")
            if offline_end is not None:
                db.execute(
                    "INSERT INTO control_offline VALUES (1,?,?,?)",
                    (controller, sequence, offline_end),
                )
        self.deadline = monotonic_start + remaining
        self.offline_deadline = (
            monotonic_start + offline_remaining if offline_end else 0.0
        )

    def effective_expiry(self, row):
        lease = self.row()
        if not lease:
            return row["expires_at"]
        if lease["offline_until"] is None:
            return min(row["expires_at"], lease["valid_until"])
        # Repeated runtime applies cannot extend service after wall-clock rollback.
        remaining = min(self.offline_deadline - self.clock(), self._peer_remaining(row))
        return min(
            row["expires_at"],
            lease["offline_until"],
            stamp(now() + timedelta(seconds=max(0.0, remaining))),
        )
