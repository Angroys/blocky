#!/usr/bin/env bash
set -e

HELPER_DEST="/usr/local/lib/blocky/blocky-apply.py"
SUDOERS_DEST="/etc/sudoers.d/blocky"
CURRENT_USER="${SUDO_USER:-$USER}"

echo "==> Installing Blocky helper..."

# Create directory and copy helper
sudo mkdir -p /usr/local/lib/blocky
sudo cp "$(dirname "$0")/helper/blocky-apply.py" "$HELPER_DEST"
sudo chmod 755 "$HELPER_DEST"
sudo chown root:root "$HELPER_DEST"

# Write sudoers drop-in
SUDOERS_CONTENT="# Blocky - app and website blocker
$CURRENT_USER ALL=(ALL) NOPASSWD: $HELPER_DEST"

echo "$SUDOERS_CONTENT" | sudo tee "$SUDOERS_DEST" > /dev/null
sudo chmod 440 "$SUDOERS_DEST"

echo "==> Helper installed at $HELPER_DEST"
echo "==> Sudoers drop-in written at $SUDOERS_DEST"
echo ""
echo "Now run: uv sync"
echo "Then run: uv run python -m blocky"
