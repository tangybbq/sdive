"""Private git mirrors and read-only source snapshots.

The user's own checkouts are never written: a project's mirror is a separate
bare clone (borrowing objects from the local repo via --reference, then
dissociated), and analysis runs against `git archive` exports of it.

Submodules listed as references in the project definition are exported into
the snapshot at the commit the parent pins, each from its own private mirror.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .config import Config, Project, Reference

MARKER = ".sdive-snapshot.json"


class GitError(Exception):
    pass


def git(*args: str | Path) -> str:
    proc = subprocess.run(["git", *map(str, args)], capture_output=True, text=True)
    if proc.returncode != 0:
        cmd = " ".join(map(str, args))
        raise GitError(f"git {cmd} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _has_commit(git_dir: Path, sha: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(git_dir), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
    )
    return proc.returncode == 0


def _clone_bare(url: str, dest: Path, reference: Path | None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    args: list[str | Path] = ["clone", "--bare", "--quiet"]
    if reference is not None:
        args += ["--reference", reference, "--dissociate"]
    git(*args, url, dest)
    git("-C", dest, "config", "remote.origin.fetch", "+refs/heads/*:refs/heads/*")


def _local_git_dir(path: Path | None) -> Path | None:
    """A usable --reference for a local repo or bare git dir, if it exists."""
    if path is None:
        return None
    if (path / ".git").exists():
        return path
    if (path / "objects").is_dir():
        return path
    return None


def _git_dir_of(path: Path | None) -> Path | None:
    """The git directory of a local repo (where `modules/` lives), if any."""
    if path is None:
        return None
    dotgit = path / ".git"
    if dotgit.is_dir():
        return dotgit
    if dotgit.is_file():  # worktree or linked checkout: "gitdir: <path>"
        target = dotgit.read_text().strip().removeprefix("gitdir:").strip()
        p = (path / target).resolve()
        return p if p.is_dir() else None
    return path if (path / "objects").is_dir() else None


def ensure_mirror(cfg: Config, project: Project, fetch: bool = True) -> Path:
    """Create the project's bare mirror if needed; optionally fetch branches and tags."""
    mirror = cfg.mirror_path(project.name)
    if not mirror.exists():
        _clone_bare(project.upstream, mirror, _local_git_dir(project.reference_repo))
        fetch = True
    if fetch:
        git("-C", mirror, "fetch", "--quiet", "--prune", "--tags", "origin")
    return mirror


def resolve(cfg: Config, project: Project, rev: str) -> str:
    mirror = cfg.mirror_path(project.name)
    if not mirror.exists():
        raise GitError(f"no mirror for {project.name}; run `sdive mirror {project.name}`")
    return git("-C", mirror, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")


# --- submodules ------------------------------------------------------------


@dataclass(frozen=True)
class Submodule:
    name: str
    path: str
    url: str


def submodules(git_dir: Path, sha: str) -> dict[str, Submodule]:
    """Submodules declared in `.gitmodules` at `sha`, keyed by path."""
    try:
        out = git("-C", git_dir, "config", "--blob", f"{sha}:.gitmodules",
                  "--get-regexp", r"^submodule\..*\.(path|url)$")
    except GitError:
        return {}
    fields: dict[str, dict[str, str]] = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        prefix, _, attr = key.rpartition(".")
        fields.setdefault(prefix.removeprefix("submodule."), {})[attr] = value
    return {
        f["path"]: Submodule(name, f["path"], f["url"])
        for name, f in fields.items()
        if "path" in f and "url" in f
    }


def gitlink(git_dir: Path, sha: str, path: str) -> str:
    """The commit a superproject pins at `path`."""
    out = git("-C", git_dir, "ls-tree", sha, "--", path)
    parts = out.split()
    if len(parts) < 3 or parts[1] != "commit":
        raise GitError(f"{path} is not a submodule (gitlink) at {sha[:12]}")
    return parts[2]


def _resolve_url(url: str, parent_url: str) -> str:
    """Resolve a relative submodule URL (`../x.git`) against the parent's URL."""
    if not url.startswith(("./", "../")):
        return url
    scheme, sep, rest = parent_url.partition("://")
    if not sep:
        return posixpath.normpath(posixpath.join(parent_url, url))
    return f"{scheme}://{posixpath.normpath(posixpath.join(rest, url))}"


def _mirror_name(url: str) -> str:
    stem = re.sub(r"^[a-z]+://", "", url).removesuffix(".git").strip("/")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", stem) + ".git"


def ensure_submodule_mirror(
    cfg: Config, project: Project, url: str, sha: str, reference: Path | None
) -> Path:
    """A private bare mirror of a submodule's repo that contains `sha`."""
    mirror = cfg.work / "mirrors" / project.name / "sub" / _mirror_name(url)
    if not mirror.exists():
        _clone_bare(url, mirror, _local_git_dir(reference))
    if not _has_commit(mirror, sha):
        git("-C", mirror, "fetch", "--quiet", "--tags", "origin")
    if not _has_commit(mirror, sha):
        git("-C", mirror, "fetch", "--quiet", "origin", sha)  # pinned off any branch/tag
    if not _has_commit(mirror, sha):
        raise GitError(f"{url}: cannot obtain pinned commit {sha}")
    return mirror


# --- snapshots ---------------------------------------------------------------


def _export(git_dir: Path, sha: str, dest: Path, paths: tuple[str, ...] = ()) -> None:
    """`git archive` `sha` (optionally only `paths`) and extract it under `dest`."""
    if paths:
        present = [p for p in paths if git("-C", git_dir, "ls-tree", "--name-only", sha, "--", p)]
        if not present:
            raise GitError(f"none of {list(paths)} exist at {sha[:12]}")
        paths = tuple(present)
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        ["git", "-C", str(git_dir), "archive", "--format=tar", sha, "--", *paths],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
        tf.extractall(dest, filter="data")
    err = proc.stderr.read().decode() if proc.stderr else ""
    if proc.wait() != 0:
        raise GitError(f"git archive {sha} failed: {err.strip()}")


def _export_references(
    cfg: Config,
    project: Project,
    refs: tuple[Reference, ...],
    parent_git: Path,
    parent_sha: str,
    parent_url: str,
    parent_local: Path | None,
    prefix: str,
    tree: Path,
    out: list[dict],
) -> None:
    mods = submodules(parent_git, parent_sha)
    for ref in refs:
        full = prefix + ref.path
        sm = mods.get(ref.path)
        if sm is None:
            raise GitError(f"reference {full} is not a submodule at {parent_sha[:12]}")
        sha = gitlink(parent_git, parent_sha, ref.path)
        url = _resolve_url(sm.url, parent_url)
        # Local submodule git dirs are keyed by submodule *name*, not path.
        local = parent_local / "modules" / sm.name if parent_local else None
        local = local if local is not None and local.is_dir() else None
        mirror = ensure_submodule_mirror(cfg, project, url, sha, local)
        _export(mirror, sha, tree / full, ref.export)
        out.append({"path": full, "name": sm.name, "url": url, "sha": sha,
                    "role": ref.role, "export": list(ref.export)})
        if ref.nested:
            _export_references(cfg, project, ref.nested, mirror, sha, url, local,
                               full + "/", tree, out)


def _layout(project: Project) -> str:
    """Fingerprint of everything besides the commit that shapes a snapshot."""
    spec = json.dumps([r.as_dict() for r in project.references], sort_keys=True)
    return hashlib.sha256(spec.encode()).hexdigest()[:16]


def _make_read_only(root: Path) -> None:
    """Strip write bits from files (directories stay writable so `rm -rf` works)."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath, name)
            if not p.is_symlink():
                p.chmod(p.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def read_marker(tree: Path) -> dict:
    try:
        return json.loads((tree / MARKER).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def snapshot(cfg: Config, project: Project, sha: str) -> Path:
    """Export `sha` from the mirror, plus its reference submodules, to a
    read-only tree. Idempotent; rebuilt if the reference layout changed."""
    dest = cfg.snapshot_path(project.name, sha)
    layout = _layout(project)
    if read_marker(dest).get("layout") == layout:
        return dest
    mirror = cfg.mirror_path(project.name)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    try:
        _export(mirror, sha, tmp)
        refs: list[dict] = []
        _export_references(cfg, project, project.references, mirror, sha, project.upstream,
                           _git_dir_of(project.reference_repo), "", tmp, refs)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    marker = {
        "project": project.name,
        "sha": sha,
        "layout": layout,
        "references": refs,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "note": "git archive export; only listed reference submodules are included",
    }
    (tmp / MARKER).write_text(json.dumps(marker, indent=2) + "\n")
    _make_read_only(tmp)
    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    return dest
