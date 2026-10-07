"""Create and verify sensitive CyberQalqon database backups."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from app.core.config import DEFAULT_DATABASE_URL, REPOSITORY_ROOT
from app.db.alerts import AlertRepository
from app.db.backup import BackupError, create_backup, verify_backup


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberQalqon SQLite backup utility")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create an online verified backup")
    create.add_argument("--output-dir", type=Path, required=True)
    create.add_argument("--filename")
    create.add_argument("--database-url")
    verify = subparsers.add_parser("verify", help="verify a backup and its metadata")
    verify.add_argument("backup", type=Path)
    verify.add_argument("--metadata", type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        if args.command == "create":
            load_dotenv(REPOSITORY_ROOT / ".env", override=False)
            database_url = args.database_url or os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
            source = AlertRepository(database_url).path
            artifact = create_backup(source, args.output_dir, filename=args.filename)
            print(f"Backup created: {artifact.database_path}")
            print(f"Metadata: {artifact.metadata_path}")
            print(f"SHA-256: {artifact.inspection.sha256}")
        else:
            inspection = verify_backup(args.backup, args.metadata)
            print(
                f"Backup verified: schema={inspection.schema_version} "
                f"bytes={inspection.size_bytes} sha256={inspection.sha256}"
            )
    except (BackupError, ValueError) as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
