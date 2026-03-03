#!/usr/bin/env bash
set -euo pipefail

# Deploy CryptoFS slides to GitHub Pages
# Pages is configured to serve from main:/docs

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
SLIDES="docs/cryptofs-presentation.html"
PAGES_URL="https://geekychris.github.io/cryptfs/cryptofs-presentation.html"
BRANCH="main"
REMOTE="origin"

cd "$REPO_ROOT"

# --- Preflight checks ---

if [ ! -f "$SLIDES" ]; then
    echo "Error: $SLIDES not found." >&2
    exit 1
fi

if ! git remote get-url "$REMOTE" &>/dev/null; then
    echo "Error: remote '$REMOTE' not configured." >&2
    exit 1
fi

# --- Stage and commit docs changes if needed ---

git add docs/
if git diff --cached --quiet -- docs/; then
    echo "No uncommitted changes in docs/."
else
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    git commit -m "docs: update slides ($TIMESTAMP)" \
               -m "Co-Authored-By: Oz <oz-agent@warp.dev>"
    echo "Committed docs changes."
fi

# --- Push ---

echo "Pushing $BRANCH to $REMOTE..."
git push "$REMOTE" "$BRANCH"

# --- Wait for GitHub Pages build ---

echo "Waiting for GitHub Pages deployment..."
MAX_WAIT=120
INTERVAL=10
ELAPSED=0

# Get the latest deployment status
while [ $ELAPSED -lt $MAX_WAIT ]; do
    STATUS=$(gh api "repos/geekychris/cryptfs/pages/builds/latest" --jq '.status' 2>/dev/null || echo "unknown")
    if [ "$STATUS" = "built" ]; then
        echo "Pages build complete."
        break
    fi
    echo "  Build status: $STATUS (${ELAPSED}s elapsed)"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "Warning: timed out waiting for Pages build (${MAX_WAIT}s)."
    echo "Check status at: https://github.com/geekychris/cryptfs/actions"
fi

# --- Verify ---

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$PAGES_URL" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "Slides live at: $PAGES_URL"
else
    echo "Warning: $PAGES_URL returned HTTP $HTTP_CODE (may still be propagating)."
fi
