"""Прокси Claude Code и Codex -> GonkaGate.

Claude Code. Запросы к моделям GonkaGate (id со слэшем: zai-org/..., deepseek-ai/...,
minimaxai/...) уходят в шлюз, всё остальное - в Anthropic как есть, с авторизацией
подписки. Так в /model остаются модели Claude, а модель GonkaGate добавляется к ним.
Напрямую Claude Code с GonkaGate не работает, шлюз отвечает 400 в двух местах:
1. Claude Code кладёт в messages сообщения с role "system", а шлюз принимает
   только user/assistant. Прокси переносит их в верхнеуровневый system и склеивает
   соседние сообщения одной роли.
2. Шлюз не понимает lookahead (?! в regex схем инструментов. Прокси выкидывает
   из схем строковые pattern.
Картинки и PDF шлюз тоже не принимает - прокси подменяет их текстовой пометкой.

Codex. Codex говорит только на OpenAI Responses API (/v1/responses), а GonkaGate умеет
только Chat Completions. Прокси переводит запрос в chat/completions, а стрим ответа
обратно в события Responses.

Ключ GonkaGate (GONKA_API_KEY) прокси берёт из .env рядом с собой и подставляет в каждый
запрос к шлюзу.

Руками запускать не нужно: его поднимает хук из .claude/settings.json при старте claude
и скрипт codex-gonka.cmd / codex-gonka.sh.
  python proxy.py           - запустить в этом окне (видно лог запросов)
  python proxy.py --ensure  - поднять в фоне, если ещё не запущен
  python proxy.py --codex   - то же плюс профиль gonka в ~/.codex/config.toml
"""
import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid

GONKA = "api.gonkagate.com"
ANTHROPIC = "api.anthropic.com"
PORT = int(os.environ.get("GONKA_PROXY_PORT", "8787"))
HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, ".env")
ENV_EXAMPLE = os.path.join(HERE, ".env.example")
GONKA_HEADERS = ("anthropic-version", "anthropic-beta", "content-type")
# Заглушка из ANTHROPIC_AUTH_TOKEN в режиме «только GonkaGate», см. README.
PLACEHOLDER_TOKEN = "key-is-in-.env"
# Эти заголовки к Anthropic не пересылаем: их выставляет http.client, а сжатый ответ
# прокси не распаковывает, поэтому просим несжатый.
SKIP_HEADERS = ("host", "content-length", "connection", "accept-encoding", "keep-alive",
                "proxy-connection", "transfer-encoding")
SKIP_RESPONSE_HEADERS = ("transfer-encoding", "connection", "content-length", "content-encoding")
BUSY_RETRIES, BUSY_DELAY = 40, 3  # повторяем до двух минут (40 x 3 с), пока шлюз занят


def read_key():
    # Файл читается на каждый запрос: поправил ключ в .env - перезапускать ничего не надо.
    try:
        with open(ENV_FILE, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return None
    for line in lines:
        name, _, value = line.partition("=")
        if name.strip() == "GONKA_API_KEY":
            key = value.strip().strip("\"'")
            return key if key.startswith("gp-") and key != "gp-..." else None
    return None


def retry_delay(header):
    # Retry-After от шлюза уважаем, но не ждём за раз дольше 30 с.
    try:
        return min(max(float(header), 1), 30)
    except (TypeError, ValueError):
        return BUSY_DELAY


def gonka_request(method, path, body, headers):
    # У шлюза лимит одновременных запросов на ключ, и слот освобождается не сразу после
    # ответа. Codex и Claude Code сдаются раньше, поэтому на 429 ждём и повторяем сами.
    # Так же повторяем, если шлюз оборвал соединение, не ответив.
    deadline = time.monotonic() + BUSY_RETRIES * BUSY_DELAY
    while True:
        conn = http.client.HTTPSConnection(GONKA, timeout=600)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
        except (ConnectionError, socket.gaierror) as e:
            conn.close()
            if time.monotonic() >= deadline:
                raise
            print(f"GonkaGate не ответил ({e}), повтор через {BUSY_DELAY} с", flush=True)
            time.sleep(BUSY_DELAY)
            continue
        if resp.status != 429 or time.monotonic() >= deadline:
            return conn, resp
        delay = retry_delay(resp.getheader("Retry-After"))
        resp.read()
        conn.close()
        print(f"GonkaGate занят (429), повтор через {delay:g} с", flush=True)
        time.sleep(delay)


def is_gonka(model):
    # У моделей Anthropic в id слэша не бывает, у всех моделей GonkaGate он есть.
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
    return list(content)


def drop_media(blocks):
    # Шлюз отвечает 400 на картинки и PDF и роняет весь запрос. Подменяем их текстом,
    # чтобы сессия не ломалась, а модель знала, что файл она не видит.
    out = []
    for b in blocks:
        if isinstance(b, dict) and b.get("type") in ("image", "document"):
            out.append({"type": "text", "text": f"[{b['type']} пропущен: модель через GonkaGate не принимает картинки и PDF]"})
            continue
        if isinstance(b, dict) and b.get("type") == "tool_result" and isinstance(b.get("content"), list):
            b = {**b, "content": drop_media(b["content"])}
        out.append(b)
    return out


def fix_messages(data):
    msgs = data.get("messages")
    if not isinstance(msgs, list):
        return data
    system = as_blocks(data.get("system") or [])
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
    for tool in data.get("tools") or []:
        if "input_schema" in tool:
            tool["input_schema"] = strip_patterns(tool["input_schema"])
    if system:
        data["system"] = system
    return data


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
            parts.append("[картинка пропущена: модель через GonkaGate не принимает картинки и файлы]")
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

    def __init__(self):
        self.in_think = False
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
        self.think = ThinkSplitter()

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
    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def no_key(self, openai=False):
        msg = f"Нет ключа GonkaGate. Впиши ключ в файл {ENV_FILE}: GONKA_API_KEY=gp-... и повтори запрос."
        if openai:
            return self.send_json(401, {"error": {"type": "invalid_request_error", "code": "no_key", "message": msg}})
        self.send_json(400, {"type": "error", "error": {"type": "invalid_request_error", "message": msg}})

    def start_stream(self, resp):
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in SKIP_RESPONSE_HEADERS:
                self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()

    def pipe(self, host, method, body, headers):
        if host == GONKA:
            conn, resp = gonka_request(method, self.path, body, headers)
        else:
            conn = http.client.HTTPSConnection(host, timeout=600)
            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        self.start_stream(resp)

        def write(data):
            self.wfile.write(data)
            self.wfile.flush()

        answer = host == GONKA and resp.status == 200 and self.path.startswith("/v1/messages") \
            and "count_tokens" not in self.path
        if answer and "text/event-stream" in (resp.getheader("Content-Type") or ""):
            strip_think_sse(resp, write)
        elif answer:
            write(strip_think_json(resp.read()))
        else:
            while chunk := resp.read1(8192):
                write(chunk)
        conn.close()

    def gonka_headers(self, key):
        headers = {k: v for k, v in self.headers.items() if k.lower() in GONKA_HEADERS}
        headers["Authorization"] = f"Bearer {key}"
        return headers

    def forward(self, method):
        body = None
        if method == "POST":
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.startswith("/v1/responses"):
            return self.codex(body)
        data = None
        if body and self.path.startswith("/v1/messages"):
            data = json.loads(body)
        auth = self.headers.get("Authorization", "")
        model = data.get("model") if data else None
        to_gonka = is_gonka(model) if model else auth == f"Bearer {PLACEHOLDER_TOKEN}"
        if not to_gonka:
            # Модель Claude: пересылаем в Anthropic как есть, с авторизацией подписки.
            headers = {k: v for k, v in self.headers.items() if k.lower() not in SKIP_HEADERS}
            return self.pipe(ANTHROPIC, method, body, headers)
        key = read_key()
        if not key:
            return self.no_key()
        if data:
            body = json.dumps(fix_messages(data), ensure_ascii=False).encode("utf-8")
        self.pipe(GONKA, method, body, self.gonka_headers(key))

    def codex(self, body):
        key = read_key()
        if not key:
            return self.no_key(openai=True)
        req = json.loads(body)
        chat, custom = responses_to_chat(req)
        conn, resp = gonka_request("POST", "/v1/chat/completions", json.dumps(chat, ensure_ascii=False).encode("utf-8"),
                                   {"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        if resp.status != 200:
            # Ошибку отдаём как есть: на 5xx Codex сам повторит запрос.
            self.start_stream(resp)
            self.wfile.write(resp.read())
            conn.close()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def write(data):
            self.wfile.write(data)
            self.wfile.flush()

        ResponsesStream(write, req["model"], custom).run(resp)
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
        # Claude Code проверяет связь HEAD-запросом; апстрим не трогаем.
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        print(self.address_string(), fmt % args, flush=True)


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
    kwargs = {"cwd": HERE, "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
              "stderr": subprocess.DEVNULL}
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
    text = ("# Codex через GonkaGate: codex --profile gonka.\n"
            f"# Файл пишет {os.path.join(HERE, 'proxy.py')} при каждом запуске codex-gonka, правки затрутся.\n"
            'model_provider = "gonka"\n'
            'model = "zai-org/glm-5.3-flash"\n'
            f"model_catalog_json = '{catalog}'\n\n"
            "[model_providers.gonka]\n"
            'name = "GonkaGate"\n'
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
        print(f"GonkaGate proxy: http://127.0.0.1:{PORT} -> {GONKA} / {ANTHROPIC}", flush=True)
        http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
