"""Прокси Claude Code и Codex -> брокеры сети Gonka (GonkaGate, gonka.gg, dahl и другие).

Брокеры. Список - в providers.json, ключи - в .env рядом с этим файлом, у каждого брокера
своя переменная. Запрос уходит первому живому брокеру с ключом. Лежит, перегружен, завис
или не принял ключ - запрос сразу уходит следующему. Сломавшегося минуту не трогаем, а тот,
кто ответил последним, пробуем первым. Отказали все - прокси сам идёт на новый круг через
2 с, до 5 минут: Claude Code на ошибку отвечает паузой, которая растёт до нескольких минут.

Claude Code. Запросы к моделям Gonka (id со слэшем: zai-org/..., deepseek-ai/...,
minimaxai/...) уходят брокерам, всё остальное - в Anthropic как есть, с авторизацией
подписки. Так в /model остаются модели Claude, а модель Gonka добавляется к ним.
Напрямую Claude Code с брокерами не работает, они отвечают 400 в двух местах:
1. Claude Code кладёт в messages сообщения с role "system", а брокеры принимают
   только user/assistant. Прокси переносит их в верхнеуровневый system и склеивает
   соседние сообщения одной роли.
2. Валидатор сети не понимает lookahead (?! в regex схем инструментов. Прокси выкидывает
   из схем строковые pattern.
Картинки и PDF брокеры тоже не принимают - прокси подменяет их текстовой пометкой.
Серверные инструменты Anthropic (WebSearch) прокси убирает.
Большинство брокеров говорит на языке OpenAI ("format": "openai" в providers.json) -
таким прокси переводит запрос в Chat Completions, а ответ обратно в формат Anthropic.

Codex. Codex говорит только на OpenAI Responses API (/v1/responses), а брокеры умеют
только Chat Completions. Прокси переводит запрос в chat/completions, а стрим ответа
обратно в события Responses.

Руками запускать не нужно: его поднимает хук из .claude/settings.json при старте claude
и скрипт codex-gonka.cmd / codex-gonka.sh.
  python proxy.py           - запустить в этом окне (видно лог запросов)
  python proxy.py --ensure  - поднять в фоне, если ещё не запущен, лог в proxy.log
  python proxy.py --codex   - то же плюс профиль gonka в ~/.codex/gonka.config.toml
"""
import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit

ANTHROPIC = "api.anthropic.com"
PORT = int(os.environ.get("GONKA_PROXY_PORT", "8787"))
HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, ".env")
ENV_EXAMPLE = os.path.join(HERE, ".env.example")
PROVIDERS_FILE = os.path.join(HERE, "providers.json")
LOG_FILE = os.path.join(HERE, "proxy.log")
# Заглушка из ANTHROPIC_AUTH_TOKEN в режиме «без подписки», см. .claude/gonka-only.json.
PLACEHOLDER_TOKEN = "key-is-in-.env"
# Эти заголовки к Anthropic не пересылаем: их выставляет http.client, а сжатый ответ
# прокси не распаковывает, поэтому просим несжатый.
SKIP_HEADERS = ("host", "content-length", "connection", "accept-encoding", "keep-alive",
                "proxy-connection", "transfer-encoding")
SKIP_RESPONSE_HEADERS = ("transfer-encoding", "connection", "content-length", "content-encoding")

COOLDOWN = 60          # сколько секунд не трогать брокера после сбоя
CONNECT_TIMEOUT = 5    # брокер не принял соединение за 5 с - сразу к следующему
# Сколько ждать начала ответа. Зависший брокер держит запрос, пока не истечёт это время.
FIRST_BYTE_TIMEOUT = int(os.environ.get("GONKA_FIRST_BYTE_TIMEOUT", "30"))
RETRY_FOR = int(os.environ.get("GONKA_RETRY_FOR", "300"))
RETRY_PAUSE = 2
# На эти ответы переключаемся на следующего брокера. 400 - ошибка в самом запросе, её отдаём как есть.
FAILOVER_STATUS = {401, 402, 403, 404, 408, 409, 429} | set(range(500, 600))

state_lock = threading.Lock()
preferred = None   # имя брокера, который ответил последним
down_until = {}    # имя брокера -> время, до которого его не трогаем


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------- брокеры ----------

def load_env():
    # Файл читается на каждый запрос: поправил ключ в .env - перезапускать ничего не надо.
    env = {}
    try:
        with open(ENV_FILE, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    for line in lines:
        name, sep, value = line.partition("=")
        if sep and not name.strip().startswith("#"):
            env[name.strip()] = value.strip().strip("\"'")
    env.update({k: v for k, v in os.environ.items() if k.endswith("_API_KEY")})
    # Пустое значение или образец вида gp-... - ключа нет.
    return {k: v for k, v in env.items() if v and not v.endswith("...")}


def load_providers():
    """Брокеры с ключом, в порядке из providers.json; последний удачный - первым."""
    env = load_env()
    with open(PROVIDERS_FILE, encoding="utf-8") as f:
        listed = json.load(f)
    providers = []
    for p in listed:
        key = next((env[k] for k in [p["key_env"], *p.get("key_env_aliases", [])] if k in env), "")
        if key and not p.get("disabled"):
            providers.append({**p, "key": key})
    with state_lock:
        now = time.time()
        providers.sort(key=lambda p: (down_until.get(p["name"], 0) > now, p["name"] != preferred))
    return providers


def mark(name, ok):
    global preferred
    with state_lock:
        if ok:
            preferred = name
            down_until.pop(name, None)
        else:
            down_until[name] = time.time() + COOLDOWN


def model_for(p, model):
    # У части брокеров свои имена моделей, соответствие - в поле models в providers.json.
    return p.get("models", {}).get(model, model)


def open_upstream(p, method, path, body, headers):
    """Отправляет запрос брокеру, возвращает (conn, resp). Ошибки сети - исключением."""
    u = urlsplit(p["base_url"])
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.netloc, timeout=CONNECT_TIMEOUT)
    try:
        conn.connect()
        conn.sock.settimeout(FIRST_BYTE_TIMEOUT)
        conn.request(method, u.path.rstrip("/") + path, body=body, headers={
            "Authorization": f"Bearer {p['key']}", "x-api-key": p["key"],
            "Content-Type": "application/json", "User-Agent": "gonka-claude-codex", **headers})
        resp = conn.getresponse()
    except (OSError, http.client.HTTPException):
        conn.close()
        raise
    if conn.sock:
        conn.sock.settimeout(600)  # заголовки пришли - дальше модель может думать долго
    return conn, resp


def failover(method, build, label):
    """Отдаёт запрос брокерам по очереди. build(p) -> (path, body, headers) или None, если
    этому брокеру запрос не отправить. Возвращает (p, conn, resp) первого, кто ответил
    не сбоем, или (None, None, причины отказа)."""
    providers = load_providers()
    deadline = time.monotonic() + RETRY_FOR
    while True:
        failures = []
        for p in providers:
            req = build(p)
            if req is None:
                continue
            try:
                conn, resp = open_upstream(p, method, *req)
            except (OSError, http.client.HTTPException) as e:
                failures.append(f"{p['name']}: {e}")
                mark(p["name"], False)
                log(f"{p['name']} не ответил ({e}), пробую следующего")
                continue
            if resp.status in FAILOVER_STATUS:
                text = resp.read()[:300].decode("utf-8", "replace")
                conn.close()
                failures.append(f"{p['name']}: {resp.status} {text}")
                mark(p["name"], False)
                log(f"{p['name']} -> {resp.status}, пробую следующего")
                continue
            mark(p["name"], resp.status < 400)
            log(f"{label} -> {p['name']} {resp.status}")
            return p, conn, resp
        if not failures or time.monotonic() + RETRY_PAUSE > deadline:
            return None, None, failures
        log(f"все брокеры отказали, новый круг через {RETRY_PAUSE} с: " + " | ".join(f[:120] for f in failures))
        time.sleep(RETRY_PAUSE)
        providers = load_providers()


def is_gonka(model):
    # У моделей Anthropic в id слэша не бывает, у всех моделей Gonka он есть.
    return isinstance(model, str) and "/" in model


def strip_patterns(schema):
    # Свойство с именем "pattern" (у Grep) - это dict, его не трогаем.
    if isinstance(schema, dict):
        return {k: strip_patterns(v) for k, v in schema.items()
                if not (k == "pattern" and isinstance(v, str)) and k != "patternProperties"}
    if isinstance(schema, list):
        return [strip_patterns(v) for v in schema]
    return schema


# ---------- Claude Code: Anthropic Messages ----------

def as_blocks(content):
    if isinstance(content, str):
        return [{"type": "text", "text": content}] if content else []
    return list(content or [])


def drop_media(blocks):
    # Брокеры отвечают 400 на картинки и PDF и роняют весь запрос. Подменяем их текстом,
    # чтобы сессия не ломалась, а модель знала, что файл она не видит.
    out = []
    for b in blocks:
        if isinstance(b, dict) and b.get("type") in ("image", "document"):
            out.append({"type": "text", "text": f"[{b['type']} пропущен: модели Gonka не принимают картинки и PDF]"})
            continue
        if isinstance(b, dict) and b.get("type") == "tool_result" and isinstance(b.get("content"), list):
            b = {**b, "content": drop_media(b["content"])}
        out.append(b)
    return out


def fix_messages(data):
    msgs = data.get("messages")
    if not isinstance(msgs, list):
        return data
    system = as_blocks(data.get("system"))
    fixed = []
    for m in msgs:
        if m.get("role") == "system":
            system += [{k: v for k, v in b.items() if k in ("type", "text")}
                       for b in as_blocks(m.get("content")) if b.get("type") == "text"]
            continue
        m = {k: v for k, v in m.items() if k in ("role", "content")}
        if isinstance(m.get("content"), list):
            m["content"] = drop_media(m["content"])
        if fixed and fixed[-1]["role"] == m["role"]:
            fixed[-1]["content"] = as_blocks(fixed[-1]["content"]) + as_blocks(m["content"])
        else:
            fixed.append(m)
    data["messages"] = fixed
    if "tools" in data:
        # У серверных инструментов (web_search и т. п.) есть поле type - брокеры их не знают.
        tools = [t for t in data["tools"] if t.get("type") in (None, "custom")]
        for t in tools:
            if "input_schema" in t:
                t["input_schema"] = strip_patterns(t["input_schema"])
        data["tools"] = tools
        if not tools:
            data.pop("tools")
            data.pop("tool_choice", None)
    if system:
        data["system"] = system
    return data


# ---------- Claude Code: перевод Anthropic <-> OpenAI Chat Completions ----------

def block_text(content):
    if isinstance(content, str):
        return content
    return "\n".join(b.get("text", "") for b in content or [] if b.get("type") == "text")


def to_openai(body, model):
    msgs = []
    if body.get("system"):
        msgs.append({"role": "system", "content": block_text(body["system"])})
    for m in body["messages"]:
        blocks = as_blocks(m["content"])
        if m["role"] == "assistant":
            msg = {"role": "assistant", "content": block_text(blocks) or None}
            calls = [{"id": b["id"], "type": "function",
                      "function": {"name": b["name"], "arguments": json.dumps(b.get("input", {}), ensure_ascii=False)}}
                     for b in blocks if b.get("type") == "tool_use"]
            if calls:
                msg["tool_calls"] = calls
            msgs.append(msg)
            continue
        # Результаты инструментов - отдельными сообщениями role=tool, сразу после вызова.
        for b in blocks:
            if b.get("type") == "tool_result":
                text = block_text(b.get("content"))
                msgs.append({"role": "tool", "tool_call_id": b["tool_use_id"],
                             "content": ("ОШИБКА: " if b.get("is_error") else "") + (text or "(пусто)")})
        text = block_text([b for b in blocks if b.get("type") == "text"])
        if text:
            msgs.append({"role": "user", "content": text})

    out = {"model": model, "messages": msgs, "max_tokens": body.get("max_tokens", 4096),
           "stream": bool(body.get("stream"))}
    if out["stream"]:
        out["stream_options"] = {"include_usage": True}
    for a, o in (("temperature", "temperature"), ("top_p", "top_p"), ("stop_sequences", "stop")):
        if a in body:
            out[o] = body[a]
    if body.get("tools"):
        out["tools"] = [{"type": "function", "function": {
            "name": t["name"], "description": t.get("description", ""),
            "parameters": t.get("input_schema", {"type": "object"})}} for t in body["tools"]]
        choice = (body.get("tool_choice") or {}).get("type")
        if choice == "any":
            out["tool_choice"] = "required"
        elif choice == "tool":
            out["tool_choice"] = {"type": "function", "function": {"name": body["tool_choice"]["name"]}}
        elif choice == "none":
            out["tool_choice"] = "none"
    return out


STOP = {"stop": "end_turn", "length": "max_tokens", "tool_calls": "tool_use", "function_call": "tool_use"}


def starts_in_think(model):
    # Брокеры с API как у OpenAI присылают рассуждения MiniMax без открывающего <think>,
    # только с закрывающим. Поэтому ответ MiniMax считаем рассуждением, пока тег не закроется.
    # Не закрылся - ThinkSplitter отдаст всё текстом, ответ не пропадёт.
    return "minimax" in model.lower()


def without_think(text, model):
    return "".join(t for think, t in ThinkSplitter(starts_in_think(model)).feed(text, final=True) if not think)


def from_openai(data, model):
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message", {})
    text = without_think(msg.get("content") or "", model)
    content = [{"type": "text", "text": text}] if text else []
    for c in msg.get("tool_calls") or []:
        try:
            args = json.loads(c["function"].get("arguments") or "{}")
        except ValueError:
            args = {"_raw": c["function"].get("arguments")}
        content.append({"type": "tool_use", "id": c.get("id") or f"toolu_{uuid.uuid4().hex[:24]}",
                        "name": c["function"]["name"], "input": args})
    u = data.get("usage") or {}
    return {"id": data.get("id") or f"msg_{uuid.uuid4().hex[:24]}", "type": "message", "role": "assistant",
            "model": model, "content": content, "stop_sequence": None,
            "stop_reason": STOP.get(choice.get("finish_reason"), "end_turn"),
            "usage": {"input_tokens": u.get("prompt_tokens", 0), "output_tokens": u.get("completion_tokens", 0)}}


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8")


def stream_from_openai(resp, model):
    """Поток Chat Completions -> поток событий Anthropic. Рассуждения MiniMax (<think>) вырезаются."""
    yield sse("message_start", {"type": "message_start", "message": {
        "id": f"msg_{uuid.uuid4().hex[:24]}", "type": "message", "role": "assistant", "model": model,
        "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0}}})
    index, open_kind, tool_slots = -1, None, {}
    finish, usage = None, {}
    think = ThinkSplitter(starts_in_think(model))

    def close():
        nonlocal open_kind
        if open_kind:
            open_kind = None
            return sse("content_block_stop", {"type": "content_block_stop", "index": index})
        return b""

    def text_out(text):
        nonlocal index, open_kind
        if open_kind != "text":
            yield close()
            index += 1
            open_kind = "text"
            yield sse("content_block_start", {"type": "content_block_start", "index": index,
                                              "content_block": {"type": "text", "text": ""}})
        yield sse("content_block_delta", {"type": "content_block_delta", "index": index,
                                          "delta": {"type": "text_delta", "text": text}})

    buf = b""
    while True:
        chunk = resp.read1(65536)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            payload = line[5:].strip()
            if payload == b"[DONE]":
                continue
            try:
                data = json.loads(payload)
            except ValueError:
                continue
            usage = data.get("usage") or usage
            for ch in data.get("choices") or []:
                delta = ch.get("delta") or {}
                finish = ch.get("finish_reason") or finish
                if delta.get("content"):
                    for in_think, text in think.feed(delta["content"]):
                        if not in_think:
                            yield from text_out(text)
                for tc in delta.get("tool_calls") or []:
                    slot = tc.get("index", 0)
                    if slot not in tool_slots:
                        yield close()
                        index += 1
                        open_kind = "tool"
                        tool_slots[slot] = index
                        yield sse("content_block_start", {"type": "content_block_start", "index": index,
                                  "content_block": {"type": "tool_use", "input": {},
                                                    "id": tc.get("id") or f"toolu_{uuid.uuid4().hex[:24]}",
                                                    "name": (tc.get("function") or {}).get("name", "")}})
                    args = (tc.get("function") or {}).get("arguments")
                    if args:
                        yield sse("content_block_delta", {"type": "content_block_delta", "index": tool_slots[slot],
                                                          "delta": {"type": "input_json_delta", "partial_json": args}})
    for in_think, text in think.feed("", final=True):
        if not in_think:
            yield from text_out(text)
    yield close()
    yield sse("message_delta", {"type": "message_delta",
                                "delta": {"stop_reason": STOP.get(finish, "end_turn"), "stop_sequence": None},
                                "usage": {"input_tokens": usage.get("prompt_tokens", 0),
                                          "output_tokens": usage.get("completion_tokens", 0)}})
    yield sse("message_stop", {"type": "message_stop"})


# ---------- Codex: Responses -> Chat Completions ----------

def text_of(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    parts = []
    for c in content:
        if not isinstance(c, dict):
            continue
        if "text" in c:
            parts.append(c["text"])
        elif c.get("type") in ("input_image", "input_file"):
            parts.append("[картинка пропущена: модели Gonka не принимают картинки и файлы]")
    return "\n".join(parts)


def responses_to_chat(req):
    tools, custom = [], set()
    for t in req.get("tools") or []:
        if t.get("type") == "function":
            params = t.get("parameters") or {"type": "object", "properties": {}}
            tools.append({"type": "function", "function": {
                "name": t["name"], "description": t.get("description", ""),
                "parameters": strip_patterns(params)}})
        elif t.get("type") == "custom":
            # Свободный ввод (apply_patch) в chat/completions не существует:
            # заворачиваем в функцию с одним строковым аргументом input.
            custom.add(t["name"])
            desc = t.get("description", "")
            fmt = t.get("format") or {}
            if fmt.get("definition"):
                desc += f"\n\nThe input string must follow this {fmt.get('syntax', '')} grammar:\n{fmt['definition']}"
            tools.append({"type": "function", "function": {
                "name": t["name"], "description": desc,
                "parameters": {"type": "object", "required": ["input"],
                               "properties": {"input": {"type": "string", "description": "Raw tool input"}}}}})
        # web_search, image_generation и прочие встроенные инструменты OpenAI шлюзу неизвестны.

    system = [req["instructions"]] if req.get("instructions") else []
    msgs, reasoning = [], None

    def assistant():
        nonlocal reasoning
        if not msgs or msgs[-1]["role"] != "assistant" or msgs[-1].get("_closed"):
            msgs.append({"role": "assistant", "content": None})
        if reasoning:
            msgs[-1]["reasoning_content"] = reasoning
            reasoning = None
        return msgs[-1]

    def add_call(call_id, name, arguments):
        a = assistant()
        a.setdefault("tool_calls", []).append(
            {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments or "{}"}})

    for item in req.get("input") or []:
        kind = item.get("type", "message")
        if kind == "message":
            role, text = item.get("role"), text_of(item.get("content"))
            if role in ("system", "developer"):
                system.append(text)
            elif role == "assistant":
                a = assistant()
                if a.get("tool_calls"):
                    a = {"role": "assistant", "content": None}
                    msgs.append(a)
                a["content"] = (a["content"] + "\n" if a["content"] else "") + text
            elif msgs and msgs[-1]["role"] == "user":
                msgs[-1]["content"] += "\n\n" + text
            else:
                msgs.append({"role": "user", "content": text})
        elif kind == "reasoning":
            # DeepSeek в режиме размышлений требует вернуть рассуждения вместе с вызовом инструмента.
            reasoning = "\n".join(s.get("text", "") for s in (item.get("summary") or []) + (item.get("content") or []))
        elif kind == "function_call":
            add_call(item["call_id"], item["name"], item.get("arguments"))
        elif kind == "custom_tool_call":
            add_call(item["call_id"], item["name"], json.dumps({"input": item.get("input", "")}, ensure_ascii=False))
        elif kind in ("function_call_output", "custom_tool_call_output"):
            out = item.get("output")
            if isinstance(out, dict):
                out = out.get("content", "")
            if msgs and msgs[-1]["role"] == "assistant":
                msgs[-1]["_closed"] = True
            msgs.append({"role": "tool", "tool_call_id": item["call_id"], "content": text_of(out)})
    for m in msgs:
        m.pop("_closed", None)
        if m["role"] == "assistant" and m["content"] is None and not m.get("tool_calls"):
            m["content"] = ""
    if system:
        msgs.insert(0, {"role": "system", "content": "\n\n".join(system)})

    body = {"model": req["model"], "messages": msgs, "stream": True,
            "stream_options": {"include_usage": True}}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
        body["parallel_tool_calls"] = bool(req.get("parallel_tool_calls", True))
    if req.get("max_output_tokens"):
        body["max_tokens"] = req["max_output_tokens"]
    return body, custom


class ThinkSplitter:
    """MiniMax пишет рассуждения прямо в текст ответа: <think>рассуждение</think>ответ.
    Закрывающий тег шлюз съедает, на его месте остаётся пустая строка, поэтому рассуждение
    заканчивается на </think> или на первых трёх переводах строки подряд.
    Режет поток текста на куски (рассуждение или нет, текст), теги могут прийти по частям."""

    OPEN, CLOSE = ("<think>",), ("</think>", "\n\n\n")

    def __init__(self, in_think=False):
        self.in_think = in_think
        self.after_think = False   # сразу после рассуждения срезаем пустые строки
        self.thought = ""          # текущее рассуждение, на случай если оно так и не закроется
        self.pending = ""          # хвост текста, который может оказаться началом тега

    def emit(self, out, text):
        if self.in_think:
            self.thought += text
        elif self.after_think:
            text = text.lstrip("\n")
            self.after_think = not text
        if text:
            out.append((self.in_think, text))

    def feed(self, delta, final=False):
        out, buf, self.pending = [], self.pending + delta, ""
        while buf:
            tags = self.CLOSE if self.in_think else self.OPEN
            found = [(buf.find(t), t) for t in tags if t in buf]
            if found:
                pos, tag = min(found)
                self.emit(out, buf[:pos])
                self.in_think = not self.in_think
                self.after_think, self.thought = not self.in_think, ""
                buf = buf[pos + len(tag):]
                continue
            keep = 0 if final else max(next((n for n in range(len(t) - 1, 0, -1) if buf.endswith(t[:n])), 0)
                                       for t in tags)
            self.emit(out, buf[:len(buf) - keep])
            self.pending = buf[len(buf) - keep:]
            break
        if final and self.in_think and self.thought:
            # Рассуждение не закрылось - значит, это и был ответ. Отдаём его текстом, чтобы не пропал.
            out.append((False, self.thought))
            self.in_think, self.thought = False, ""
        return out


def strip_think_sse(resp, write):
    # Стрим Anthropic Messages от шлюза: вырезаем <think>...</think> из текстовых блоков.
    splitters, held = {}, ""
    for raw in resp:
        line = raw.decode("utf-8", "replace")
        if line.startswith("event: content_block_stop"):
            held = line   # перед концом блока, возможно, придётся дописать застрявший хвост текста
            continue
        if line.startswith("data:") and '"text_delta"' in line:
            event = json.loads(line[5:])
            delta = event.get("delta") or {}
            if delta.get("type") == "text_delta":
                splitter = splitters.setdefault(event.get("index"), ThinkSplitter())
                delta["text"] = "".join(t for think, t in splitter.feed(delta.get("text", "")) if not think)
                line = "data: " + json.dumps(event, ensure_ascii=False) + "\n"
        elif held and line.startswith("data:"):
            index = json.loads(line[5:]).get("index")
            splitter = splitters.pop(index, None)
            tail = "".join(t for think, t in splitter.feed("", final=True) if not think) if splitter else ""
            if tail:
                event = {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": tail}}
                write(f"event: content_block_delta\ndata: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8"))
            write(held.encode("utf-8"))
            held = ""
        write(line.encode("utf-8"))


def strip_think_json(body):
    data = json.loads(body)
    for block in data.get("content") or []:
        if block.get("type") == "text":
            block["text"] = "".join(t for think, t in ThinkSplitter().feed(block["text"], final=True) if not think)
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


class ResponsesStream:
    """Переводит стрим chat/completions в события Responses API, которые ждёт Codex."""

    def __init__(self, write, model, custom):
        self.write, self.model, self.custom = write, model, custom
        self.id = "resp_" + uuid.uuid4().hex
        self.seq = 0
        self.output = []        # готовые элементы ответа, по порядку
        self.reasoning = None   # открытый элемент рассуждений: [index, id, text]
        self.message = None     # открытое текстовое сообщение: [index, id, text]
        self.calls = {}         # вызовы инструментов по index из стрима
        self.usage = None
        self.think = ThinkSplitter(starts_in_think(model))

    def on_content(self, delta, final=False):
        for in_think, text in self.think.feed(delta, final):
            (self.on_reasoning if in_think else self.on_text)(text)

    def event(self, name, **data):
        data = {"type": name, "sequence_number": self.seq, **data}
        self.seq += 1
        self.write(f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8"))

    def response(self, status, **extra):
        return {"id": self.id, "object": "response", "created_at": int(time.time()),
                "status": status, "model": self.model, "output": self.output, **extra}

    def add_item(self, item):
        self.output.append(None)
        index = len(self.output) - 1
        self.event("response.output_item.added", output_index=index, item=item)
        return index

    def done_item(self, index, item):
        self.output[index] = item
        self.event("response.output_item.done", output_index=index, item=item)

    def close_reasoning(self):
        if self.reasoning:
            index, rid, text = self.reasoning
            self.event("response.reasoning_summary_part.done", item_id=rid, output_index=index,
                       summary_index=0, part={"type": "summary_text", "text": text})
            self.done_item(index, {"type": "reasoning", "id": rid,
                                   "summary": [{"type": "summary_text", "text": text}]})
            self.reasoning = None

    def close_message(self):
        if self.message:
            index, mid, text = self.message
            part = {"type": "output_text", "text": text, "annotations": []}
            self.event("response.output_text.done", item_id=mid, output_index=index, content_index=0, text=text)
            self.event("response.content_part.done", item_id=mid, output_index=index, content_index=0, part=part)
            self.done_item(index, {"type": "message", "id": mid, "role": "assistant",
                                   "status": "completed", "content": [part]})
            self.message = None

    def on_reasoning(self, delta):
        if not self.reasoning:
            rid = "rs_" + uuid.uuid4().hex
            index = self.add_item({"type": "reasoning", "id": rid, "summary": []})
            self.event("response.reasoning_summary_part.added", item_id=rid, output_index=index,
                       summary_index=0, part={"type": "summary_text", "text": ""})
            self.reasoning = [index, rid, ""]
        self.reasoning[2] += delta
        self.event("response.reasoning_summary_text.delta", item_id=self.reasoning[1],
                   output_index=self.reasoning[0], summary_index=0, delta=delta)

    def on_text(self, delta):
        if not self.message:
            delta = delta.lstrip()
            if not delta:
                return
        self.close_reasoning()
        if not self.message:
            mid = "msg_" + uuid.uuid4().hex
            index = self.add_item({"type": "message", "id": mid, "role": "assistant",
                                   "status": "in_progress", "content": []})
            self.event("response.content_part.added", item_id=mid, output_index=index, content_index=0,
                       part={"type": "output_text", "text": "", "annotations": []})
            self.message = [index, mid, ""]
        self.message[2] += delta
        self.event("response.output_text.delta", item_id=self.message[1], output_index=self.message[0],
                   content_index=0, delta=delta)

    def on_tool_call(self, tc):
        call = self.calls.setdefault(tc.get("index", len(self.calls)), {"id": "", "name": "", "arguments": ""})
        call["id"] = tc.get("id") or call["id"]
        fn = tc.get("function") or {}
        call["name"] += fn.get("name") or ""
        call["arguments"] += fn.get("arguments") or ""

    def finish_calls(self):
        for n in sorted(self.calls):
            call = self.calls[n]
            call_id = call["id"] or "call_" + uuid.uuid4().hex
            if call["name"] in self.custom:
                try:
                    raw = json.loads(call["arguments"] or "{}").get("input", "")
                except (json.JSONDecodeError, AttributeError):
                    raw = call["arguments"]
                item = {"type": "custom_tool_call", "id": "ctc_" + uuid.uuid4().hex, "status": "completed",
                        "call_id": call_id, "name": call["name"], "input": raw}
            else:
                item = {"type": "function_call", "id": "fc_" + uuid.uuid4().hex, "status": "completed",
                        "call_id": call_id, "name": call["name"], "arguments": call["arguments"] or "{}"}
            index = self.add_item(item)
            self.done_item(index, item)
        self.calls = {}

    def run(self, resp):
        self.event("response.created", response=self.response("in_progress"))
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            chunk = json.loads(payload)
            if chunk.get("error"):
                err = chunk["error"]
                self.event("response.failed", response=self.response(
                    "failed", error={"code": str(err.get("code") or "server_error"), "message": err.get("message", str(err))}))
                return
            if chunk.get("usage"):
                self.usage = chunk["usage"]
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                thought = delta.get("reasoning_content") or delta.get("reasoning")
                if thought:
                    self.on_reasoning(thought)
                if delta.get("content"):
                    self.on_content(delta["content"])
                for tc in delta.get("tool_calls") or []:
                    self.close_reasoning()
                    self.on_tool_call(tc)
        self.on_content("", final=True)
        self.close_reasoning()
        self.close_message()
        self.finish_calls()
        u = self.usage or {}
        usage = {"input_tokens": u.get("prompt_tokens", 0),
                 "input_tokens_details": {"cached_tokens": (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)},
                 "output_tokens": u.get("completion_tokens", 0),
                 "output_tokens_details": {"reasoning_tokens": (u.get("completion_tokens_details") or {}).get("reasoning_tokens", 0)},
                 "total_tokens": u.get("total_tokens", 0)}
        self.event("response.completed", response=self.response("completed", usage=usage))


# ---------- HTTP ----------

class Handler(http.server.BaseHTTPRequestHandler):
    def send_json(self, status, data, headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def write(self, data):
        self.wfile.write(data)
        self.wfile.flush()

    def no_key(self, openai=False):
        msg = f"Нет ни одного ключа брокера. Впиши ключ в файл {ENV_FILE} (список брокеров - providers.json) и повтори запрос."
        if openai:
            return self.send_json(401, {"error": {"type": "invalid_request_error", "code": "no_key", "message": msg}})
        # 400, а не 401: на 401 Claude Code молча повторяет запрос и висит.
        self.send_json(400, {"type": "error", "error": {"type": "invalid_request_error", "message": msg}})

    def start_stream(self, resp):
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in SKIP_RESPONSE_HEADERS:
                self.send_header(k, v)
        # Длину заранее не знаем (стриминг), поэтому конец ответа = закрытие соединения.
        self.send_header("Connection", "close")
        self.end_headers()

    def pipe(self, resp):
        self.start_stream(resp)
        while True:
            chunk = resp.read1(8192)
            if not chunk:
                break
            self.write(chunk)

    def forward(self, method):
        body = None
        if method == "POST":
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/v1/responses"):
            return self.codex(body)
        data = None
        if body and self.path.startswith("/v1/messages"):
            data = json.loads(body)
        auth = self.headers.get("Authorization", "")
        model = data.get("model") if data else None
        # Без модели в запросе (GET /v1/models) смотрим на авторизацию: подписка Claude
        # всегда её шлёт, а режим без подписки и curl из терминала - нет или заглушку.
        to_gonka = is_gonka(model) if model else auth in ("", f"Bearer {PLACEHOLDER_TOKEN}")
        if not to_gonka:
            # Модель Claude: пересылаем в Anthropic как есть, с авторизацией подписки.
            headers = {k: v for k, v in self.headers.items() if k.lower() not in SKIP_HEADERS}
            conn = http.client.HTTPSConnection(ANTHROPIC, timeout=600)
            conn.request(method, self.path, body=body, headers=headers)
            self.pipe(conn.getresponse())
            return conn.close()
        if not load_providers():
            return self.no_key()
        self.gonka(method, fix_messages(data) if data else None, body)

    def gonka(self, method, data, raw):
        sub = self.path[3:] if self.path.startswith("/v1/") else self.path
        route = sub.split("?")[0]
        if route == "/messages/count_tokens":
            # Подсчёт есть не у всех брокеров, а 404 на нём уронил бы брокера в «сломанные».
            # Claude Code хватает оценки.
            return self.send_json(200, {"input_tokens": len(raw or b"") // 4})
        model = (data or {}).get("model", "")
        passed = {k: v for k, v in self.headers.items() if k.lower() in ("anthropic-version", "anthropic-beta")}
        passed.setdefault("anthropic-version", "2023-06-01")

        def build(p):
            openai = p.get("format") == "openai"
            if data is None:
                return sub, raw, {} if openai else passed
            target = model_for(p, model)
            if openai and route == "/messages":
                return "/chat/completions", json.dumps(to_openai(data, target), ensure_ascii=False).encode("utf-8"), {}
            return sub, json.dumps({**data, "model": target}, ensure_ascii=False).encode("utf-8"), passed

        p, conn, resp = failover(method, build, f"{route} {model}".strip())
        if not p:
            log("все брокеры отказали: " + " | ".join(resp))
            # 529 - «перегружено». retry-after просит Claude Code повторить через секунду,
            # а не ждать по нарастающей до нескольких минут.
            return self.send_json(529, {"type": "error", "error": {
                "type": "overloaded_error", "message": "Все брокеры недоступны: " + " | ".join(resp)}},
                {"retry-after": "1", "retry-after-ms": "1000", "x-should-retry": "true"})
        try:
            openai = p.get("format") == "openai"
            if route != "/messages":
                self.pipe(resp)
            elif openai and resp.status == 200 and data.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                for part in stream_from_openai(resp, model):
                    if part:
                        self.write(part)
            elif openai and resp.status == 200:
                self.send_json(200, from_openai(json.loads(resp.read()), model))
            elif openai:
                text = resp.read()[:500].decode("utf-8", "replace")
                self.send_json(resp.status, {"type": "error", "error": {
                    "type": "invalid_request_error", "message": f"{p['name']}: {text}"}})
            elif resp.status == 200 and "text/event-stream" in (resp.getheader("Content-Type") or ""):
                self.start_stream(resp)
                strip_think_sse(resp, self.write)
            elif resp.status == 200:
                self.start_stream(resp)
                self.write(strip_think_json(resp.read()))
            else:
                self.pipe(resp)
        except (OSError, ValueError, http.client.HTTPException) as e:
            log(f"{p['name']}: обрыв посреди ответа: {e}")
        finally:
            conn.close()

    def codex(self, body):
        if not load_providers():
            return self.no_key(openai=True)
        req = json.loads(body)
        chat, custom = responses_to_chat(req)

        def build(p):
            return "/chat/completions", json.dumps({**chat, "model": model_for(p, req["model"])},
                                                   ensure_ascii=False).encode("utf-8"), {}

        p, conn, resp = failover("POST", build, f"/responses {req['model']}")
        if not p:
            log("все брокеры отказали: " + " | ".join(resp))
            # На 5xx Codex сам повторит запрос.
            return self.send_json(503, {"error": {"type": "server_error", "code": "brokers_down",
                                                  "message": "Все брокеры недоступны: " + " | ".join(resp)}})
        try:
            if resp.status != 200:
                # Ошибку отдаём как есть.
                self.start_stream(resp)
                self.write(resp.read())
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            ResponsesStream(self.write, req["model"], custom).run(resp)
        except (OSError, ValueError, http.client.HTTPException) as e:
            log(f"{p['name']}: обрыв посреди ответа: {e}")
        finally:
            conn.close()

    def do_POST(self):
        self.forward("POST")

    def do_GET(self):
        if self.path.startswith("/v1/models") and "client_version" in self.path:
            # Codex спрашивает свой каталог моделей. Свой каталог он берёт из codex-models.json.
            # Пустой ответ с кодом 200 Codex записал бы в общий кэш ~/.codex/models_cache.json
            # и сломал бы список моделей обычному Codex, поэтому 404.
            return self.send_json(404, {"error": {"message": "no model catalog", "code": "not_found"}})
        self.forward("GET")

    def do_HEAD(self):
        # Claude Code проверяет связь HEAD-запросом; брокеров не трогаем.
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # свой лог - в log(): какой брокер ответил на какой запрос


def is_running():
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", PORT)) == 0


def ensure():
    if not os.path.exists(ENV_FILE) and os.path.exists(ENV_EXAMPLE):
        shutil.copyfile(ENV_EXAMPLE, ENV_FILE)
    if is_running():
        return
    # Отдельный процесс без окна, который переживёт выход из claude.
    python = sys.executable
    if os.name == "nt" and python.lower().endswith("python.exe"):
        pythonw = python[:-10] + "pythonw.exe"
        python = pythonw if os.path.exists(pythonw) else python
    # Лог начинаем заново, если он разросся больше мегабайта.
    mode = "w" if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 1_000_000 else "a"
    with open(LOG_FILE, mode, encoding="utf-8") as logf:
        kwargs = {"cwd": HERE, "stdin": subprocess.DEVNULL, "stdout": logf, "stderr": logf,
                  "env": {**os.environ, "PYTHONIOENCODING": "utf-8"}}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([python, os.path.abspath(__file__)], **kwargs)
    for _ in range(50):
        if is_running():
            return
        time.sleep(0.1)
    sys.exit(f"Прокси не поднялся на 127.0.0.1:{PORT}. Запусти руками: python proxy.py")


def install_codex():
    # Провайдера Codex не берёт из папки проекта, только из своей домашней папки.
    # Кладём туда профиль ~/.codex/gonka.config.toml (codex --profile gonka), общий
    # config.toml не трогаем. Файл переписывается при каждом запуске: путь к каталогу
    # моделей поменяется, если папку перенесли.
    home = os.environ.get("CODEX_HOME") or os.path.join(os.path.expanduser("~"), ".codex")
    catalog = os.path.join(HERE, "codex-models.json").replace("\\", "/")
    text = ("# Codex через сеть Gonka: codex --profile gonka.\n"
            f"# Файл пишет {os.path.join(HERE, 'proxy.py')} при каждом запуске codex-gonka, правки затрутся.\n"
            'model_provider = "gonka"\n'
            'model = "zai-org/glm-5.3-flash"\n'
            f"model_catalog_json = '{catalog}'\n\n"
            "[model_providers.gonka]\n"
            'name = "Gonka"\n'
            f'base_url = "http://127.0.0.1:{PORT}/v1"\n'
            'wire_api = "responses"\n')
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "gonka.config.toml"), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


if __name__ == "__main__":
    if "--codex" in sys.argv:
        install_codex()
        ensure()
    elif "--ensure" in sys.argv:
        ensure()
    else:
        names = [p["name"] for p in load_providers()]
        print(f"Прокси Gonka: http://127.0.0.1:{PORT}, брокеры с ключом: {', '.join(names) or 'нет'}", flush=True)
        http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
