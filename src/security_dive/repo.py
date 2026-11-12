"""Private git mirrors and read-only source snapshots.

The user's own checkouts are never written: a project's mirror is a separate
bare clone (borrowing objects from the local repo via --reference, then
dissociated), and analysis runs against `git archive` exports of it.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from .config import Config, Project

MARKER = ".sdive-snapshot.json"


class GitError(Exception):
    pass


def git(*args: str | Path) -> str:
    proc = subprocess.run(["git", *map(str, args)], capture_output=True, text=True)
    if proc.returncode != 0:
        cmd = " ".join(map(str, args))
        raise GitError(f"git {cmd} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def ensure_mirror(cfg: Config, project: Project, fetch: bool = True) -> Path:
    """Create the project's bare mirror if needed; optionally fetch branches and tags."""
    mirror = cfg.mirror_path(project.name)
    if not mirror.exists():
        mirror.parent.mkdir(parents=True, exist_ok=True)
        args: list[str | Path] = ["clone", "--bare", "--quiet"]
        ref = project.reference_repo
        if ref is not None and ((ref / ".git").exists() or (ref / "objects").is_dir()):
            args += ["--reference", ref, "--dissociate"]
        git(*args, project.upstream, mirror)
        git("-C", mirror, "config", "remote.origin.fetch", "+refs/heads/*:refs/heads/*")
        fetch = True
    if fetch:
        git("-C", mirror, "fetch", "--quiet", "--prune", "--tags", "origin")
    return mirror


def resolve(cfg: Config, project: Project, rev: str) -> str:
    mirror = cfg.mirror_path(project.name)
    if not mirror.exists():
        raise GitError(f"no mirror for {project.name}; run `sdive mirror {project.name}`")
    return git("-C", mirror, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")


def _make_read_only(root: Path) -> None:
    """Strip write bits from files (directories stay writable so `rm -rf` works)."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath, name)
            if not p.is_symlink():
                p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def snapshot(cfg: Config, project: Project, sha: str) -> Path:
    """Export `sha` from the mirror to a read-only tree; idempotent.

    Submodules (e.g. MCUboot's ext/mbedtls) are not included by `git archive`.
    """
    dest = cfg.snapshot_path(project.name, sha)
    if (dest / MARKER).exists():
        return dest
    mirror = cfg.mirror_path(project.name)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    proc = subprocess.Popen(
        ["git", "-C", str(mirror), "archive", "--format=tar", sha],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
        tf.extractall(tmp, filter="data")
    err = proc.stderr.read().decode() if proc.stderr else ""
    if proc.wait() != 0:
        shutil.rmtree(tmp)
        raise GitError(f"git archive {sha} failed: {err.strip()}")
    marker = {
        "project": project.name,
        "sha": sha,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "note": "git archive export; submodules not included",
    }
    (tmp / MARKER).write_text(json.dumps(marker, indent=2) + "\n")
    _make_read_only(tmp)
    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    return dest
