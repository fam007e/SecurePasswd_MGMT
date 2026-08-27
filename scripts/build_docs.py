#!/usr/bin/env python3
"""Automated Doxygen documentation generator and HTML auditor."""

import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs" / "api" / "html"
DOXYFILE = REPO_ROOT / "Doxyfile"
CMAKELISTS = REPO_ROOT / "CMakeLists.txt"


def get_project_version() -> str:
    """Extract project version from CMakeLists.txt."""
    if CMAKELISTS.exists():
        content = CMAKELISTS.read_text(encoding="utf-8")
        match = re.search(r"project\(.*?VERSION\s+([0-9.]+)", content, re.DOTALL)
        if match:
            return match.group(1)
    return "latest"


def update_doxyfile_version(version: str) -> None:
    """Sync version into Doxyfile before running."""
    if not DOXYFILE.exists():
        return
    content = DOXYFILE.read_text(encoding="utf-8")
    updated = re.sub(
        r"^(PROJECT_NUMBER\s*=\s*).*$",
        rf"\g<1>{version}",
        content,
        flags=re.MULTILINE,
    )
    DOXYFILE.write_text(updated, encoding="utf-8")


def fix_and_audit_html() -> None:
    """Fix image paths and format code blocks in generated HTML documentation."""
    if not DOCS_DIR.exists():
        print(f"Error: Documentation directory '{DOCS_DIR}' not found.", file=sys.stderr)
        sys.exit(1)

    # Ensure .nojekyll exists for GitHub Pages
    nojekyll = DOCS_DIR / ".nojekyll"
    if not nojekyll.exists():
        nojekyll.touch()

    html_files = list(DOCS_DIR.glob("**/*.html"))
    print(f"Auditing and fixing {len(html_files)} HTML files...")

    replacements = [
        ('src="gui/icons/app_icon.svg"', 'src="app_icon.svg"'),
        ('src="./gui/icons/app_icon.svg"', 'src="app_icon.svg"'),
        ('src="gui/icons/app_icon.png"', 'src="app_icon.png"'),
        ('src="./gui/icons/app_icon.png"', 'src="app_icon.png"'),
    ]

    def format_code_block(match: re.Match) -> str:
        raw_code = match.group(1)
        stripped = raw_code.strip()
        
        # Only transform multiline code or blocks starting with bash/sh
        if "\n" in stripped or stripped.startswith("bash ") or stripped.startswith("sh "):
            clean_code = re.sub(r"^(?:bash|sh)\s*\n?", "", stripped)
            lines = [f'<div class="line">{line}</div>' for line in clean_code.split("\n")]
            return f'<div class="fragment">{"".join(lines)}</div>'
        
        # Keep single-line identifiers intact
        return match.group(0)

    modified_count = 0
    for html_file in html_files:
        content = html_file.read_text(encoding="utf-8", errors="ignore")
        updated = content

        # Fix image paths
        for old_str, new_str in replacements:
            updated = updated.replace(old_str, new_str)

        # Fix mangled code blocks in lists
        updated = re.sub(r'<span class="tt">(.*?)</span>', format_code_block, updated, flags=re.DOTALL)

        if updated != content:
            html_file.write_text(updated, encoding="utf-8")
            modified_count += 1

    print(f"Updated and audited {modified_count} HTML file(s).")

    # Verify critical assets exist in the output root
    required_assets = ["app_icon.svg", "index.html"]
    for asset in required_assets:
        asset_path = DOCS_DIR / asset
        if not asset_path.exists():
            print(f"Warning: Required asset '{asset}' missing from '{DOCS_DIR}'", file=sys.stderr)
        else:
            print(f"Asset verified: {asset}")


def main() -> None:
    version = get_project_version()
    print(f"=== Generating documentation for SecurePasswd_MGMT (v{version}) ===")
    update_doxyfile_version(version)

    # Verify doxygen is installed
    doxygen_bin = shutil.which("doxygen")
    if not doxygen_bin:
        print("Error: 'doxygen' executable not found in PATH.", file=sys.stderr)
        sys.exit(1)
    doxygen_bin = str(Path(doxygen_bin).resolve())

    print(f"Running Doxygen using {doxygen_bin}...")
    result = subprocess.run([doxygen_bin, str(DOXYFILE)], cwd=REPO_ROOT)
    if result.returncode != 0:
        print(f"Doxygen failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)

    print("Post-processing and auditing HTML output...")
    fix_and_audit_html()
    print("Documentation build completed successfully!")


if __name__ == "__main__":
    main()
