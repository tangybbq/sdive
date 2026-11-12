"""sdive — bookkeeping CLI for security-dive. Makes no LLM calls."""

import tomllib
from pathlib import Path

import click

CONFIG_NAME = "config.toml"


def load_config(path: Path | None = None) -> dict:
    path = path or Path.cwd() / CONFIG_NAME
    with path.open("rb") as f:
        return tomllib.load(f)


@click.group()
@click.pass_context
def main(ctx: click.Context) -> None:
    """Track deep security analysis of MCUboot and Zephyr."""
    ctx.obj = load_config()


@main.command()
@click.pass_obj
def projects(cfg: dict) -> None:
    """List configured projects."""
    for name, p in cfg.get("projects", {}).items():
        click.echo(f"{name:10} {p.get('github', '')}")
