@echo off
rem Codex через GonkaGate: поднимает прокси, прописывает профиль gonka и запускает codex.
rem Аргументы передаются в codex как есть, например: codex-gonka -m deepseek-ai/deepseek-v4-flash-0731
python "%~dp0proxy.py" --codex || exit /b 1
codex --profile gonka %*
