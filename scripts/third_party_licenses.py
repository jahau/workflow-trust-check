"""Write license notices for the dependencies compiled into a release binary.

Usage: python scripts/third_party_licenses.py <target-triple> <output-file>

The dependency set comes from `cargo metadata --locked --filter-platform`, so
only crates resolved for the given target are listed. License texts are read
from the crate sources in the local Cargo registry; crates that do not ship a
license file are listed with their SPDX expression and repository.
"""

import json
import pathlib
import subprocess
import sys

LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "COPYRIGHT")


def main() -> int:
    target, output = sys.argv[1], pathlib.Path(sys.argv[2])
    metadata = json.loads(
        subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                target,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    packages = {package["id"]: package for package in metadata["packages"]}
    root = metadata["resolve"]["root"]
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}

    # Walk normal (non-dev, non-build) dependencies reachable from the root.
    reachable, pending = set(), [root]
    while pending:
        node = nodes[pending.pop()]
        for dependency in node["deps"]:
            kinds = {kind["kind"] for kind in dependency["dep_kinds"]}
            if None in kinds and dependency["pkg"] not in reachable:
                reachable.add(dependency["pkg"])
                pending.append(dependency["pkg"])

    lines = [
        "# Third-party licenses",
        "",
        f"Dependencies compiled into workflow-trust-check for `{target}`.",
        "",
    ]
    for package in sorted(
        (packages[package_id] for package_id in reachable),
        key=lambda package: (package["name"], package["version"]),
    ):
        lines += [
            f"## {package['name']} {package['version']}",
            "",
            f"License: {package.get('license') or 'see license file'}",
        ]
        if package.get("repository"):
            lines.append(f"Repository: {package['repository']}")
        lines.append("")
        directory = pathlib.Path(package["manifest_path"]).parent
        files = sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and path.name.upper().startswith(LICENSE_PREFIXES)
        )
        if not files:
            lines += ["No license file is included in the published crate.", ""]
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            lines += [f"### {path.name}", "", "```text", text, "```", ""]

    output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
