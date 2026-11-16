#!/usr/bin/env python3
"""Keep the Rust agent's copy of the protocol's local agent contract honest.

The Rust local API tests check /agent/status against the contract's real
bodies. They live in rust/crates/local-api/tests/localagent/, copied from the
protocol repo's localagent/ folder at the commit named in SOURCE.json, which
also records each file's SHA-256. The Rust test `copy_matches_source` checks
the hashes on every `cargo test`, so an edited copy fails there.

  verify                       Offline: the copy matches SOURCE.json (hashes,
                               no missing or extra files).
  check  --protocol DIR        The copy matches the files at SOURCE.json's
                               commit in a protocol checkout, byte for byte.
  update --protocol DIR --commit SHA
                               Copy the files from that commit and rewrite
                               SOURCE.json. Then run the Rust tests.

The macOS app keeps the same kind of copy (mac-agent
scripts/localagent-contract.py); both should name the same commit.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
COPY = ROOT / "rust/crates/local-api/tests/localagent"
SOURCE = COPY / "SOURCE.json"
REPO_PATH = "localagent"
# What the tests use: the status fixtures and the closed code sets.
WANTED = ("codes.v1.json", "fixtures/status/")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(protocol, *args):
    result = subprocess.run(
        ["git", "-C", str(protocol), *args],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed in {protocol}: {result.stderr.decode().strip()}")
    return result.stdout


def files_at(protocol, commit):
    """Wanted contract files at `commit`, as {relative name: bytes}."""
    listing = git(protocol, "ls-tree", "-r", "--name-only", "-z", commit, f"{REPO_PATH}/")
    names = [n for n in listing.decode().split("\0") if n]
    out = {}
    for name in names:
        rel = name[len(REPO_PATH) + 1:]
        if rel == WANTED[0] or (rel.startswith(WANTED[1]) and rel.endswith(".json")):
            out[rel] = git(protocol, "show", f"{commit}:{name}")
    if not out:
        sys.exit(f"no contract files under {REPO_PATH}/ at {commit}")
    return out


def copied_files():
    out = {}
    for path in sorted(COPY.rglob("*")):
        if path.is_file() and path != SOURCE:
            out[path.relative_to(COPY).as_posix()] = path.read_bytes()
    return out


def load_source():
    try:
        source = json.loads(SOURCE.read_text())
    except (OSError, ValueError) as error:
        sys.exit(f"{SOURCE}: {error}")
    files = source.get("files")
    if len(source.get("commit", "")) != 40 or not isinstance(files, list):
        sys.exit(f"{SOURCE}: needs a full 40-character commit and a files list")
    # Each file is {"name", "sha256"} on separate lines: a name next to a
    # hash on one line reads like a credential to the secret scanner.
    try:
        source["files"] = {entry["name"]: entry["sha256"] for entry in files}
    except (KeyError, TypeError):
        sys.exit(f"{SOURCE}: each file needs a name and a sha256")
    return source


def compare(label, want, have):
    problems = []
    for name in sorted(set(want) | set(have)):
        if name not in have:
            problems.append(f"missing in copy: {name}")
        elif name not in want:
            problems.append(f"not in {label}: {name}")
        elif want[name] != have[name]:
            problems.append(f"differs from {label}: {name}")
    return problems


def report(problems, ok_message):
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(ok_message)


def verify(_args):
    source = load_source()
    have = {name: sha256(data) for name, data in copied_files().items()}
    problems = compare("SOURCE.json", source["files"], have)
    report(problems, f"copy matches SOURCE.json ({len(have)} files, protocol {source['commit'][:7]})")


def check(args):
    source = load_source()
    want = files_at(args.protocol, source["commit"])
    problems = compare(f"protocol {source['commit'][:7]}", want, copied_files())
    problems += compare("SOURCE.json", source["files"], {n: sha256(d) for n, d in want.items()})
    report(problems, f"copy matches protocol {source['commit'][:7]} ({len(want)} files)")


def update(args):
    commit = git(args.protocol, "rev-parse", "--verify", f"{args.commit}^{{commit}}").decode().strip()
    files = files_at(args.protocol, commit)
    for path in COPY.rglob("*.json"):
        if path != SOURCE:
            path.unlink()
    for name, data in files.items():
        target = COPY / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    source = {
        "repository": "labtether/protocol",
        "path": REPO_PATH,
        "commit": commit,
        "files": [{"name": name, "sha256": sha256(data)} for name, data in sorted(files.items())],
    }
    SOURCE.write_text(json.dumps(source, indent=2) + "\n")
    print(f"copied {len(files)} files from protocol {commit[:7]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify").set_defaults(run=verify)
    for name, run in (("check", check), ("update", update)):
        cmd = sub.add_parser(name)
        cmd.add_argument("--protocol", type=Path, required=True, help="protocol repo checkout")
        if name == "update":
            cmd.add_argument("--commit", required=True)
        cmd.set_defaults(run=run)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
