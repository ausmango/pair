#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_binary="$script_dir/pair"
source_icon="$script_dir/pair-logo.png"

if [ ! -f "$source_binary" ]; then
    echo "Pair binary not found beside this installer: $source_binary" >&2
    exit 1
fi

bin_dir="$HOME/.local/bin"
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
applications_dir="$data_dir/applications"
icon_dir="$data_dir/icons/hicolor/512x512/apps"
installed_binary="$bin_dir/pair"
desktop_file="$applications_dir/pair.desktop"
installed_icon="$icon_dir/pair.png"
temporary_binary="$bin_dir/.pair.tmp.$$"
temporary_desktop="$desktop_file.tmp.$$"

mkdir -p "$bin_dir" "$applications_dir" "$icon_dir"
trap 'rm -f "$temporary_binary" "$temporary_desktop"' EXIT HUP INT TERM
cp "$source_binary" "$temporary_binary"
chmod 0755 "$temporary_binary"
mv "$temporary_binary" "$installed_binary"

if [ -f "$source_icon" ]; then
    cp "$source_icon" "$installed_icon"
fi

escaped_binary=$(printf '%s' "$installed_binary" | sed 's/\\/\\\\/g; s/"/\\"/g; s/`/\\`/g; s/\$/\\$/g')

cat > "$temporary_desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Pair
Comment=Encrypted notepad for two computers on a local network
Exec="$escaped_binary"
Icon=pair
Terminal=false
Categories=Utility;TextEditor;
StartupNotify=true
EOF

chmod 0755 "$temporary_desktop"
mv "$temporary_desktop" "$desktop_file"
trap - EXIT HUP INT TERM

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" >/dev/null 2>&1 || true
fi

echo "Pair was installed for this user."
echo "Open Pair from your desktop's Applications menu."
