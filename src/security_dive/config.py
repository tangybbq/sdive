"""Configuration: `config.toml` at the repo root plus `projects/<name>/project.toml`."""

from __future__ import annotations

import functools
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAME = "config.toml"
SOURCE_EXTS = (".c", ".h")


class ConfigError(Exception):
    pass


@functools.cache
def _glob_re(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to a regex. `**` spans directories, `*` does not."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and (j := pattern.find("]", i + 2)) != -1:
            body = pattern[i + 1 : j]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def glob_match(pattern: str, path: str) -> bool:
    return _glob_re(pattern).match(path) is not None


@dataclass(frozen=True)
class Area:
    name: str
    priority: int
    globs: tuple[str, ...] = ()
    description: str = ""

    def matches(self, path: str) -> bool:
        return any(glob_match(g, path) for g in self.globs)


@dataclass(frozen=True)
class Reference:
    """A submodule exported into snapshots for agents to *consult* (API
    contracts), never indexed, covered, or the location of a finding."""

    path: str  # relative to the parent tree (the project, or the parent reference)
    role: str = ""
    export: tuple[str, ...] = ()  # subpaths to export; empty = the whole tree
    nested: tuple[Reference, ...] = ()

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "export": list(self.export),
            "nested": [n.as_dict() for n in self.nested],
        }


def _flat_reference_paths(refs: tuple[Reference, ...], prefix: str = "") -> list[str]:
    out = []
    for r in refs:
        out.append(prefix + r.path)
        out.extend(_flat_reference_paths(r.nested, prefix + r.path + "/"))
    return out


@dataclass(frozen=True)
class Project:
    name: str
    github: str
    upstream: str
    reference_repo: Path | None
    default_branch: str
    threat_model: Path | None
    defdir: Path
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    areas: tuple[Area, ...]
    default_area: Area
    references: tuple[Reference, ...] = ()

    @property
    def lenses_dir(self) -> Path:
        return self.defdir / "lenses"

    @property
    def reference_paths(self) -> list[str]:
        return _flat_reference_paths(self.references)

    def is_reference(self, path: str) -> bool:
        return any(path == r or path.startswith(r + "/") for r in self.reference_paths)

    def in_scope(self, path: str) -> bool:
        if not path.endswith(SOURCE_EXTS) or self.is_reference(path):
            return False
        if not any(glob_match(g, path) for g in self.include):
            return False
        return not any(glob_match(g, path) for g in self.exclude)

    def area_for(self, path: str) -> Area:
        for area in self.areas:
            if area.matches(path):
                return area
        return self.default_area

    def area_named(self, name: str) -> Area:
        for area in (*self.areas, self.default_area):
            if area.name == name:
                return area
        raise ConfigError(f"project {self.name}: unknown area {name!r}")


@dataclass(frozen=True)
class Config:
    root: Path
    analysis: Path
    work: Path
    projects: dict[str, Project]

    def project(self, name: str) -> Project:
        try:
            return self.projects[name]
        except KeyError:
            known = ", ".join(sorted(self.projects)) or "none"
            raise ConfigError(f"unknown project {name!r} (configured: {known})") from None

    @property
    def db_path(self) -> Path:
        return self.analysis / "sdive.db"

    @property
    def staging(self) -> Path:
        return self.analysis / "staging"

    def mirror_path(self, project: str) -> Path:
        return self.work / "mirrors" / f"{project}.git"

    def snapshot_path(self, project: str, sha: str) -> Path:
        return self.work / "snapshots" / project / sha

    def dossier_path(self, project: str, area: str) -> Path:
        return self.analysis / "dossiers" / project / f"{area}.md"

    def run_record_path(self, project: str, run_id: int) -> Path:
        return self.analysis / "runs" / project / f"run-{run_id}.json"


def find_config(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for d in (here, *here.parents):
        if (d / CONFIG_NAME).is_file():
            return d / CONFIG_NAME
    raise ConfigError(f"no {CONFIG_NAME} found in {here} or its parents")


def _path(root: Path, value: str | None) -> Path | None:
    if not value:
        return None
    p = Path(value).expanduser()
    return p if p.is_absolute() else (root / p).resolve()


def _load_reference(raw: dict) -> Reference:
    return Reference(
        path=raw["path"].strip("/"),
        role=raw.get("role", ""),
        export=tuple(p.strip("/") for p in raw.get("export", ())),
        nested=tuple(_load_reference(n) for n in raw.get("nested", ())),
    )


def _load_project(root: Path, name: str, raw: dict) -> Project:
    defdir = root / "projects" / name
    deffile = defdir / "project.toml"
    spec = tomllib.loads(deffile.read_text()) if deffile.is_file() else {}
    scope = spec.get("scope", {})
    areas = tuple(
        Area(
            name=a["name"],
            priority=int(a.get("priority", 1)),
            globs=tuple(a.get("globs", ())),
            description=a.get("description", ""),
        )
        for a in spec.get("areas", ())
    )
    default = scope.get("default_area", {"name": "unassigned", "priority": 0})
    default_area = Area(
        name=default["name"],
        priority=int(default.get("priority", 0)),
        description=default.get("description", ""),
    )
    names = [a.name for a in (*areas, default_area)]
    if len(names) != len(set(names)):
        raise ConfigError(f"{deffile}: duplicate area names")
    for key in ("github", "upstream"):
        if key not in raw:
            raise ConfigError(f"projects.{name}: missing {key!r}")
    return Project(
        name=name,
        github=raw["github"],
        upstream=raw["upstream"],
        reference_repo=_path(root, raw.get("reference_repo")),
        default_branch=raw.get("default_branch", "main"),
        threat_model=_path(root, raw.get("threat_model")),
        defdir=defdir,
        include=tuple(scope.get("include", ())),
        exclude=tuple(scope.get("exclude", ())),
        areas=areas,
        default_area=default_area,
        references=tuple(_load_reference(r) for r in spec.get("reference", ())),
    )


def load_config(path: Path | None = None) -> Config:
    path = path or find_config()
    root = path.parent.resolve()
    with path.open("rb") as f:
        raw = tomllib.load(f)
    paths = raw.get("paths", {})
    return Config(
        root=root,
        analysis=_path(root, paths.get("analysis", "analysis")),
        work=_path(root, paths.get("work", "work")),
        projects={
            name: _load_project(root, name, p) for name, p in raw.get("projects", {}).items()
        },
    )
