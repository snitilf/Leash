#!/bin/sh
# offline, deterministic macro workload for the NFR-2 overhead harness
# (docs/measurements/0001-m1-overhead.md section 2.2). run bare and under
# `leash run -- sh macro.sh <workdir>`; the driver times the whole script.
#
# it materializes this repository's tracked tree into the workdir, does a recursive
# read/grep pass, runs a scripted burst of file creates/edits/renames simulating an
# agent editing session, then git init + add + commit. no network, no clock reads that
# would make it non-reproducible; the only input is HEAD of the repo the script lives in.

set -eu

workdir="${1:?usage: macro.sh <workdir>}"

# derive the source repo from the script's own location (benches/workloads/macro.sh),
# so `git archive` works no matter the caller's cwd or the overlay mount.
script_dir=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$script_dir/../.." && pwd)

mkdir -p "$workdir"

# materialize the tracked tree (no .git, tracked files only) into the workdir.
git -C "$repo" archive HEAD | tar -x -C "$workdir"

cd "$workdir"

# recursive read/grep pass over the materialized tree.
grep -rIl . . >/dev/null 2>&1 || true
find . -type f -exec cat {} + >/dev/null 2>&1 || true

# scripted create/edit/rename burst: a few hundred mutating ops.
i=0
while [ "$i" -lt 200 ]; do
	printf 'line %s\n' "$i" >"gen_$i.txt"
	printf 'more %s\n' "$i" >>"gen_$i.txt"
	mv "gen_$i.txt" "ren_$i.txt"
	i=$((i + 1))
done

# git init + add + commit. set identity locally so it works on a bare box with no
# global git config.
git init -q .
git config user.name "leash-bench"
git config user.email "bench@leash.local"
git add -A
git commit -q -m "macro workload commit" >/dev/null
