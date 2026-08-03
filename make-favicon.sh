#!/bin/bash

set -euo pipefail

SOURCE="favicon.svg"
MASTER="$(mktemp --suffix=.png)"

cleanup() {
    rm -f "$MASTER" favicon-48x48.png
}

trap cleanup EXIT

inkscape "$SOURCE" \
    --export-filename="$MASTER" \
    --export-width=2048 \
    --export-height=2048

render_png() {
    local size="$1"
    local output="$2"

    magick "$MASTER" \
        -filter Lanczos \
        -resize "${size}x${size}" \
        -alpha on \
        -define png:color-type=6 \
        -interlace none \
        -strip \
        "$output"
}

render_png 192 android-chrome-192x192.png
render_png 512 android-chrome-512x512.png
render_png 180 apple-touch-icon.png
render_png 16  favicon-16x16.png
render_png 32  favicon-32x32.png
render_png 48  favicon-48x48.png

magick \
    favicon-16x16.png \
    favicon-32x32.png \
    favicon-48x48.png \
    favicon.ico

file \
    android-chrome-192x192.png \
    android-chrome-512x512.png \
    apple-touch-icon.png \
    favicon-16x16.png \
    favicon-32x32.png \
    favicon.ico
