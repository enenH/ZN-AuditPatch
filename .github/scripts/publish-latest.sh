#!/usr/bin/env bash
set -euo pipefail

archive=${1:?Usage: publish-latest.sh ARCHIVE VERSION}
version=${2:?Usage: publish-latest.sh ARCHIVE VERSION}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

if [[ ! -s "$archive" || ! -s "$archive.sha256" ]]; then
    echo 'Release ZIP or SHA-256 file is missing or empty.' >&2
    exit 1
fi

temp_dir=$(mktemp -d)
trap 'rm -f "$temp_dir/error" "$temp_dir/notes"; rmdir "$temp_dir"' EXIT

if tag=$(gh api "repos/$GITHUB_REPOSITORY/releases/latest" --jq .tag_name 2> "$temp_dir/error"); then
    if [[ -z "$tag" || "$tag" == null ]]; then
        echo 'The Latest release did not return a tag name.' >&2
        exit 1
    fi
    # Only replace assets owned by this workflow, retaining other release assets.
    gh release upload "$tag" "$archive" "$archive.sha256" \
        --repo "$GITHUB_REPOSITORY" --clobber
elif grep -q '(HTTP 404)' "$temp_dir/error"; then
    # A new repository has no Latest release yet. Bootstrap its first stable release.
    tag=$version
    printf 'Automated ARM64 and x86_64 build from commit %s.\n' "$GITHUB_SHA" > "$temp_dir/notes"
    gh release create "$tag" "$archive" "$archive.sha256" \
        --repo "$GITHUB_REPOSITORY" \
        --target "$GITHUB_SHA" \
        --title "$version" \
        --notes-file "$temp_dir/notes" \
        --latest
else
    cat "$temp_dir/error" >&2
    exit 1
fi

release_url=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json url --jq .url)
printf 'Uploaded %s to %s\n' "$archive" "$release_url"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf 'Published [%s](%s) from commit `%s`.\n' "$tag" "$release_url" "$GITHUB_SHA" >> "$GITHUB_STEP_SUMMARY"
fi
