"""Validate repository-relative workflow inputs before shell/tool use."""
import os
from pathlib import Path


def target_path(root: Path, supplied: str) -> Path:
    if not supplied or any(character in supplied for character in '\r\n\0'):
        raise ValueError('Path must be nonempty and cannot contain control characters')
    if Path(supplied).is_absolute():
        raise ValueError('Path must be relative to the target repository')
    resolved = (root / supplied).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('Path escapes the target repository')
    return resolved


def main():
    root = Path(os.environ['TARGET_DIR']).resolve()
    paths = {
        'SCAN_DIR': target_path(root, os.environ['SCAN_PATH']),
        'DOCKERFILE_PATH': target_path(root, os.environ['DOCKERFILE']),
        'REQUESTED_POLICY_FILE': target_path(root, os.environ['REQUESTED_POLICY']),
    }
    if not paths['SCAN_DIR'].is_dir():
        raise ValueError('Scan directory does not exist')
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as stream:
        for key, value in paths.items():
            stream.write(f'{key}={value}\n')


if __name__ == '__main__':
    main()
