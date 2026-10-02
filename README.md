# Claude Code и Codex на GonkaGate

Подключает модели [GonkaGate](https://gonkagate.com) — GLM, DeepSeek, MiniMax — к Claude Code и Codex.
Нужны только Python и ключ GonkaGate.

Работает только внутри этой папки. В остальных папках `claude` и `codex` остаются обычными,
подписка и настройки не трогаются.

## Режимы

| Режим | Когда подходит | Команда |
|---|---|---|
| Claude Code + подписка | Есть подписка Claude, нужна дешёвая модель рядом | `claude` |
| Claude Code без подписки | Подписки нет | `claude --settings .claude/gonka-only.json` |
| Codex | Codex на моделях GonkaGate вместо GPT | `.\codex-gonka.cmd` или `./codex-gonka.sh` |

## Что нужно

- [Claude Code](https://docs.claude.com/en/docs/claude-code/setup) и/или [Codex CLI](https://developers.openai.com/codex/cli)
- Python 3.8+ — проверка: `python --version` (на Mac: `python3 --version`).
  На Windows можно поставить так: `winget install Python.Python.3.12`, затем перезапустить терминал.
- Ключ GonkaGate вида `gp-...` из личного кабинета [gonkagate.com](https://gonkagate.com)

## Установка

1. Скачайте папку:

   ```
   git clone https://github.com/pewdredd/gonka-claude-codex
   cd gonka-claude-codex
   ```

   Без git: на GitHub нажмите **Code → Download ZIP**, распакуйте и откройте терминал в этой папке.

2. Создайте файл `.env` из шаблона и впишите ключ:

   ```
   copy .env.example .env     # Windows
   cp .env.example .env       # Mac / Linux
   ```

   ```
   GONKA_API_KEY=gp-ваш-ключ
   ```

   Если пропустить этот шаг, `.env` создастся сам при первом запуске — останется вписать ключ.
   Файл `.env` не попадает в git.

3. Запустите нужный режим — см. ниже.

## Claude Code с подпиской

```
claude
```

При первом запуске Claude Code спросит, доверяете ли вы папке. Ответьте «да» — иначе прокси не запустится.

Откройте `/model`: к обычным моделям Claude добавится **GLM-5.3 Flash**. Выбрали её — запросы идут
через GonkaGate. Вернулись на Opus или Sonnet — снова по подписке. Переключаться можно посреди разговора.

Другие модели GonkaGate включаются по id:

```
/model deepseek-ai/deepseek-v4-flash-0731
/model minimaxai/minimax-m2.7
```

Чтобы в списке `/model` была другая модель вместо GLM, поменяйте `ANTHROPIC_CUSTOM_MODEL_OPTION`
и `ANTHROPIC_CUSTOM_MODEL_OPTION_NAME` в `.claude/settings.json`.

Claude Code предупредит, что не знает эти модели, и будет считать контекст в 200k токенов.
Это нормально: у GLM и DeepSeek контекст 400k, просто сжатие диалога начнётся раньше.

## Claude Code без подписки

```
claude --settings .claude/gonka-only.json
```

Все модели, включая фоновые запросы и субагентов, заменяются на GLM. Входить в аккаунт Anthropic не нужно.

## Codex

```
.\codex-gonka.cmd      # Windows
./codex-gonka.sh       # Mac / Linux
```

Скрипт поднимает прокси, создаёт профиль `~/.codex/gonka.config.toml` и запускает `codex --profile gonka`.
Основной `~/.codex/config.toml` не меняется, обычный `codex` остаётся на GPT. Аккаунт OpenAI не нужен.

Аргументы передаются в Codex как есть:

```
.\codex-gonka.cmd -m deepseek-ai/deepseek-v4-flash-0731
.\codex-gonka.cmd exec "перескажи README.md"
```

| Модель | id |
|---|---|
| GLM-5.3 Flash (по умолчанию) | `zai-org/glm-5.3-flash` |
| DeepSeek V4 Flash | `deepseek-ai/deepseek-v4-flash-0731` |
| MiniMax M2.7 | `minimaxai/minimax-m2.7` |

Просто `codex` в папке не сработает: Codex разрешает задавать провайдера моделей только
из `~/.codex`, а не из папки проекта.

## Ограничения

Проверено 2026-10-02 на Claude Code 2.1.285 и Codex 0.144.1.

| | Claude Code | Codex |
|---|---|---|
| GLM, DeepSeek, MiniMax | да | да |
| Модели Claude по подписке рядом с ними | да | — |
| Чтение и правка файлов, команды в терминале | да | да |
| WebSearch | нет | нет |
| Картинки и PDF | нет | нет |

- WebSearch — серверный инструмент Anthropic, на моделях GonkaGate его нет.
- Картинки и PDF модель не видит: прокси подставляет вместо них пометку, сессия не ломается.
- Рассуждения моделей в Codex показываются отдельным блоком. В Claude Code MiniMax пишет их в ответ — прокси их вырезает.

Модели GonkaGate слабее Claude и GPT: иногда в ответ попадает лишний текст на английском или
инструмент вызывается дважды. Для простых задач хватает. В режиме с подпиской сложное можно отдать Opus,
не выходя из сессии.

## Если что-то не работает

**GLM нет в `/model`.** Запускайте `claude` в корне этой папки — из подпапки настройки не подхватываются.
И проверьте, что ответили «да» на вопрос о доверии к папке.

**Ошибка про ключ.** Исправьте `.env` и повторите запрос — перезапуск не нужен.

**Модель долго отвечает.** У шлюза лимит одновременных запросов на ключ. Прокси сам ждёт и повторяет
запрос до двух минут.

**После обновления `proxy.py` ничего не изменилось.** Прокси остаётся работать в фоне.
Остановите процесс `python`/`pythonw` (или перезагрузите компьютер) — при следующем запуске поднимется новая версия.

**Порт 8787 занят.** Поменяйте порт в `ANTHROPIC_BASE_URL` в `.claude/settings.json` и задайте такой же
в переменной окружения `GONKA_PROXY_PORT`.

**Codex из другой папки.** Укажите полный путь к `codex-gonka.cmd` или `codex-gonka.sh`.

## Как это устроено

Claude Code и Codex не умеют работать с GonkaGate напрямую. Между ними стоит `proxy.py` на `127.0.0.1:8787`
(только стандартная библиотека Python). Он берёт ключ из `.env` и:

- **Разводит запросы.** Модели со слэшем в id (`zai-org/...`, `deepseek-ai/...`, `minimaxai/...`) идут
  в GonkaGate, модели Claude — в Anthropic с вашей авторизацией. Ключ GonkaGate не уходит в Anthropic, и наоборот.
- **Исправляет запросы под шлюз.** GonkaGate отвечает 400 на сообщения с ролью system и на regex
  с lookahead в схемах инструментов — прокси их переписывает.
- **Переводит протокол для Codex.** Codex использует OpenAI Responses API, GonkaGate — Chat Completions.
  Прокси переводит запросы и ответы, включая стриминг и вызовы инструментов.

| Файл | Назначение |
|---|---|
| `proxy.py` | Прокси |
| `.env.example` | Шаблон для `.env` с ключом |
| `.claude/settings.json` | Направляет Claude Code в прокси, добавляет GLM в `/model`, запускает прокси при старте |
| `.claude/gonka-only.json` | Режим без подписки |
| `codex-gonka.cmd`, `codex-gonka.sh` | Запуск Codex |
| `codex-models.json` | Описания моделей для Codex. Без него Codex не даёт модели править файлы |
