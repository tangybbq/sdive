import subprocess
import textwrap
from pathlib import Path

import pytest

from security_dive.config import load_config

PARSER_C = """\
#include "parser.h"

static int check_len(int len)
{
    return len < 64;
}

#ifdef FAST
int parse(const char *buf, int len) { return check_len(len); }
#else
int parse(const char *buf, int len)
{
    return check_len(len) && buf[0];
}
#endif
"""

UTIL_C = """\
int helper(void)
{
    return 1;
}
"""


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def commit(repo: Path, msg: str = "init") -> str:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


def add_gitlink(repo: Path, name: str, path: str, url: Path, sha: str) -> None:
    """Record a submodule without `git submodule add` (no checkout needed).
    The empty directory reads as an unpopulated submodule, so a later
    `git add -A` doesn't stage the gitlink's deletion."""
    (repo / path).mkdir(parents=True, exist_ok=True)
    with (repo / ".gitmodules").open("a") as f:
        f.write(f'[submodule "{name}"]\n\tpath = {path}\n\turl = {url}\n')
    git(repo, "add", ".gitmodules")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},{path}")


@pytest.fixture
def library(tmp_path: Path) -> Path:
    """An external library with its own nested submodule, like mbedtls 4."""
    core = tmp_path / "core"
    (core / "src").mkdir(parents=True)
    (core / "src" / "core.c").write_text("int core(void) { return 0; }\n")
    git(core, "init", "-q", "-b", "main")
    core_sha = commit(core)

    lib = tmp_path / "lib"
    for d in ("include", "library", "tests"):
        (lib / d).mkdir(parents=True)
    (lib / "include" / "lib.h").write_text("int lib_parse(const char *b, int n);\n")
    (lib / "library" / "lib.c").write_text("int lib_parse(const char *b, int n) { return b[n]; }\n")
    (lib / "tests" / "t.c").write_text("int t(void) { return 0; }\n")
    git(lib, "init", "-q", "-b", "main")
    git(lib, "add", "-A")
    add_gitlink(lib, "core", "core", core, core_sha)
    commit(lib)
    return lib


@pytest.fixture
def upstream(tmp_path: Path, library: Path) -> Path:
    """A tiny git repo standing in for a project's upstream."""
    up = tmp_path / "upstream"
    (up / "src").mkdir(parents=True)
    (up / "src" / "parser.c").write_text(PARSER_C)
    (up / "src" / "parser.h").write_text("int parse(const char *buf, int len);\n")
    (up / "src" / "util.c").write_text(UTIL_C)
    (up / "test").mkdir()
    (up / "test" / "t.c").write_text("int t(void) { return 0; }\n")
    git(up, "init", "-q", "-b", "main")
    git(up, "add", "-A")
    add_gitlink(up, "vendor/lib", "ext/lib", library, git(library, "rev-parse", "HEAD"))
    commit(up)
    return up


@pytest.fixture
def root(tmp_path: Path, upstream: Path) -> Path:
    """A security-dive root with one project `demo` pointing at `upstream`."""
    r = tmp_path / "root"
    (r / "projects" / "demo" / "lenses").mkdir(parents=True)
    (r / "config.toml").write_text(textwrap.dedent(f"""\
        [projects.demo]
        github = "example/demo"
        upstream = "{upstream}"
        reference_repo = "{upstream}"
        threat_model = "tm.md"
        """))
    (r / "tm.md").write_text("# threat model\n")
    (r / "projects" / "demo" / "project.toml").write_text(textwrap.dedent("""\
        [scope]
        include = ["src/**", "test/**", "ext/**"]
        exclude = ["test/**"]
        default_area = { name = "misc", priority = 1 }

        [[areas]]
        name = "parsing"
        priority = 5
        globs = ["src/parser.[ch]"]

        [[reference]]
        path = "ext/lib"
        role = "Example library"
        export = ["include", "library"]

          [[reference.nested]]
          path = "core"
          export = ["src"]
        """))
    (r / "projects" / "demo" / "lenses" / "memory.md").write_text("Look for memory bugs.\n")
    return r


@pytest.fixture
def cfg(root: Path):
    return load_config(root / "config.toml")
