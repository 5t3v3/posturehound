"""In-memory job tracker for live scan-progress logs.

The web app used to fake progress with a client-side timer that advanced
through fixed steps on a clock, regardless of what the server was actually
doing. This module makes that real: a scan runs as a background job, and every
real pipeline checkpoint (parsing, deterministic rules, Sonnet call, Opus call,
scoring, persistence) appends a timestamped log line the frontend can poll.

Single-process, in-memory by design (this is a local single-user tool run with
one worker) - jobs do not survive a server restart, which is fine since they
are transient by nature (the finished scan itself is what gets persisted).
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

_LOCK = threading.Lock()
_JOBS: dict[str, "Job"] = {}
_MAX_JOBS = 200   # bound memory; oldest finished jobs are evicted
_MAX_LOG = 2000   # cap per-job log entries to prevent unbounded memory growth


@dataclass
class Job:
    id: str
    log: list[dict] = field(default_factory=list)
    done: bool = False
    error: str | None = None
    scan_id: str | None = None
    cancelled: bool = False
    meta: dict = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)

    def append(self, message: str) -> None:
        with _LOCK:
            if len(self.log) < _MAX_LOG:
                self.log.append({"t": time.time(), "message": message})

    def finish(self, scan_id: str | None = None, error: str | None = None, **meta) -> None:
        with _LOCK:
            self.done = True
            self.scan_id = scan_id
            self.error = error
            if meta:
                self.meta.update(meta)

    def cancel(self) -> None:
        with _LOCK:
            if not self.done:
                self.cancelled = True
                self.log.append({"t": time.time(), "message": "Scan cancelled by user."})
                self.done = True
                self.error = "Scan cancelled by user."


def create_job() -> Job:
    job = Job(id=uuid.uuid4().hex[:12])
    with _LOCK:
        _JOBS[job.id] = job
        if len(_JOBS) > _MAX_JOBS:
            # evict the oldest finished job
            finished = sorted((j for j in _JOBS.values() if j.done), key=lambda j: j.started_at)
            for j in finished[:len(_JOBS) - _MAX_JOBS]:
                _JOBS.pop(j.id, None)
    return job


def get_job(job_id: str) -> Job | None:
    return _JOBS.get(job_id)


def list_running() -> list[Job]:
    return [j for j in _JOBS.values() if not j.done]


def run_in_background(fn: Callable[[Job], None]) -> Job:
    """Create a job and run fn(job) on a background thread. fn is responsible
    for calling job.append(...) at real progress points and job.finish(...) at
    the end (success or failure)."""
    job = create_job()

    def _runner():
        try:
            fn(job)
        except Exception as e:  # last-resort catch so a job never hangs at "running"
            if not job.done:
                job.append(f"Unexpected error: {type(e).__name__}: {e}")
                job.finish(error=str(e))

    threading.Thread(target=_runner, daemon=True).start()
    return job
