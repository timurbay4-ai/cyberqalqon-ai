"""Create the first administrator without shipping or logging a password."""

from __future__ import annotations

import argparse
import getpass
import sys

from pydantic import ValidationError

from app.core.config import get_settings
from app.db.alerts import AlertRepository
from app.db.auth import AuthRepository, BootstrapAlreadyCompletedError
from app.schemas.auth import AnalystCreate, AnalystRole


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bootstrap the first CyberQalqon administrator")
    parser.add_argument("--username", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read one password line from stdin instead of prompting twice",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("Bootstrap failed: passwords do not match.", file=sys.stderr)
            return 2

    try:
        request = AnalystCreate(
            username=args.username,
            display_name=args.display_name,
            password=password,
            role=AnalystRole.ADMIN,
        )
    except ValidationError as exc:
        print(f"Bootstrap failed: {exc.errors()[0]['msg']}.", file=sys.stderr)
        return 2

    settings = get_settings()
    alerts = AlertRepository(settings.database_url)
    alerts.initialize()
    repository = AuthRepository(alerts.path, settings)
    try:
        analyst = repository.bootstrap_first_admin(request)
    except BootstrapAlreadyCompletedError:
        print("Bootstrap refused: an analyst account already exists.", file=sys.stderr)
        return 3

    print(f"Created administrator {analyst.username} ({analyst.analyst_id}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
