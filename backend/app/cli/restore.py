"""Deliberate offline CyberQalqon database restore command."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from app.core.config import DEFAULT_DATABASE_URL, REPOSITORY_ROOT
from app.db.alerts import AlertRepository
from app.db.backup import BackupError, restore_backup


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Restore a verified CyberQalqon backup while the backend is stopped"
    )
    parser.add_argument("backup", type=Path)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--preserve-dir", type=Path, required=True)
    parser.add_argument("--database-url")
    parser.add_argument(
        "--confirm-restore",
        action="store_true",
        help="confirm that the backend is stopped and the target may be replaced",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    if not args.confirm_restore:
        print("Restore refused: pass --confirm-restore after stopping the backend", file=sys.stderr)
        return 2
    load_dotenv(REPOSITORY_ROOT / ".env", override=False)
    database_url = args.database_url or os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
    try:
        target = AlertRepository(database_url).path
        metadata = args.metadata or Path(f"{args.backup}.json")
        result = restore_backup(args.backup, metadata, target, args.preserve_dir)
    except (BackupError, ValueError) as exc:
        print(f"Restore failed: {exc}", file=sys.stderr)
        return 1
    print(f"Database restored: {result.database_path}")
    print(f"Schema version: {result.schema_version}")
    print(f"Invalidated analyst sessions: {result.invalidated_sessions}")
    if result.safety_backup is not None:
        print(f"Pre-restore safety backup: {result.safety_backup.database_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
