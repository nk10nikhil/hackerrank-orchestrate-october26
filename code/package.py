"""Create and verify the submission code.zip without bundling challenge data."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


EXCLUDED_PARTS = {"__pycache__", ".venv", "venv", "node_modules", ".git", ".pytest_cache"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}


def build_archive(root: Path, destination: Path) -> list[str]:
    root = root.resolve()
    destination = destination.resolve()
    sources = [root / "README.md", root / "code", root / "evaluation"]
    if not all(path.exists() for path in sources):
        raise FileNotFoundError("Expected root README.md and code/ before packaging")
    names: list[str] = []
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in sources:
            candidates = [source] if source.is_file() else sorted(path for path in source.rglob("*") if path.is_file())
            for path in candidates:
                relative = path.relative_to(root)
                if any(part in EXCLUDED_PARTS for part in relative.parts):
                    continue
                if path.suffix.casefold() in ARCHIVE_SUFFIXES:
                    continue
                archive.write(path, relative.as_posix())
                names.append(relative.as_posix())
    verify_archive(destination)
    return names


def verify_archive(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "README.md" not in names:
            raise ValueError("Archive is missing README.md")
        required = {
            "code/main.py", "code/audit_agent.py", "evaluation/evaluation_report.md",
            "evaluation/usage_report.md", "code/requirements.txt",
        }
        missing = sorted(required - set(names))
        if missing:
            raise ValueError(f"Archive is missing required files: {', '.join(missing)}")
        forbidden = [name for name in names if name.startswith("dataset/") or Path(name).suffix.casefold() in ARCHIVE_SUFFIXES]
        if forbidden:
            raise ValueError(f"Archive contains prohibited dataset or nested archives: {forbidden[:5]}")
        for name in names:
            if any(part in EXCLUDED_PARTS for part in Path(name).parts):
                raise ValueError(f"Archive includes a cache or environment directory: {name}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--output", type=Path, default=root / "code.zip")
    args = parser.parse_args()
    entries = build_archive(args.root, args.output)
    print(f"Created {args.output.resolve()} with {len(entries)} files.")
    print("Archive verification passed: required code and reports are present; dataset and nested archives are excluded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

