#!/bin/sh
# Codex через GonkaGate: поднимает прокси, прописывает профиль gonka и запускает codex.
# Аргументы передаются в codex как есть, например: ./codex-gonka.sh -m deepseek-ai/deepseek-v4-flash-0731
DIR=$(cd "$(dirname "$0")" && pwd)
python3 "$DIR/proxy.py" --codex 2>/dev/null || python "$DIR/proxy.py" --codex || exit 1
exec codex --profile gonka "$@"
