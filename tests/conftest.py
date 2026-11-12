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


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
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
    git(up, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")
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
        include = ["src/**", "test/**"]
        exclude = ["test/**"]
        default_area = { name = "misc", priority = 1 }

        [[areas]]
        name = "parsing"
        priority = 5
        globs = ["src/parser.[ch]"]
        """))
    (r / "projects" / "demo" / "lenses" / "memory.md").write_text("Look for memory bugs.\n")
    return r


@pytest.fixture
def cfg(root: Path):
    return load_config(root / "config.toml")
