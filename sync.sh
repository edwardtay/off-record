#!/bin/bash
# web/ is the page as served at prompt20.com/tools/private-prompt/. Copy it into the prompt20 site.
set -euo pipefail
DEST="${PROMPT20_DIR:-$HOME/2-projects/prompt20}/tools/private-prompt"
mkdir -p "$DEST" && cp -r web/. "$DEST/"
echo "copied web/ to $DEST"
