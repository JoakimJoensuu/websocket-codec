#!/usr/bin/env bash
# clang-format + clang-tidy over a three-dot range, never HEAD~1.
#
#   --base <sha>  files in <sha>...HEAD (whole PR / branch vs that base)
#   --ci          pick the base: PR base if this branch has a PR, else
#                 origin/main. On main, check every tracked C file.
#   (no args)     every tracked C file
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASE=""
CI=0
if [[ "${1:-}" == "--base" ]]; then
    BASE="${2:?--base requires a commit SHA}"
elif [[ "${1:-}" == "--ci" ]]; then
    CI=1
fi

if [[ "$CI" -eq 1 ]]; then
    git fetch --no-tags origin main
    if [[ "${GITHUB_REF:-}" == refs/heads/main ]]; then
        BASE=""
    else
        pr_base=""
        if command -v gh >/dev/null && [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
            pr_base="$(gh pr view --json baseRefOid -q .baseRefOid 2>/dev/null || true)"
        fi
        if [[ -n "$pr_base" ]]; then
            git fetch --no-tags origin "$pr_base"
            BASE="$pr_base"
        else
            BASE="$(git merge-base HEAD origin/main)"
        fi
        echo "check-style: three-dot $BASE...HEAD"
    fi
fi

if [[ -n "$BASE" ]]; then
    mapfile -t FILES < <(git diff --name-only --diff-filter=ACMR "$BASE"...HEAD -- '*.c' '*.h')
else
    mapfile -t FILES < <(git ls-files '*.c' '*.h')
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "check-style: no C files to check"
    exit 0
fi

echo "check-style: formatting ${#FILES[@]} file(s)"
clang-format --dry-run --Werror "${FILES[@]}"

TIDY=()
for f in "${FILES[@]}"; do
    case "$f" in
        *.c) TIDY+=("$f") ;;
    esac
done
for f in "${FILES[@]}"; do
    case "$f" in
        include/* | src/*)
            TIDY+=(src/wsio.c src/wsio_utf8.c)
            break
            ;;
    esac
done

if [[ ${#TIDY[@]} -eq 0 ]]; then
    echo "check-style: no translation units to tidy"
    exit 0
fi

mapfile -t TIDY < <(printf '%s\n' "${TIDY[@]}" | sort -u)

if [[ ! -f build/compile_commands.json ]]; then
    cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
fi

echo "check-style: clang-tidy ${#TIDY[@]} translation unit(s)"
clang-tidy -p build --warnings-as-errors='*' "${TIDY[@]}"
