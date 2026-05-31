import re
import json


def parse_curl(curl_text: str) -> dict:
    text = curl_text.strip()
    if not text.startswith("curl"):
        raise ValueError("Input does not appear to be a cURL command")

    tokens = _tokenize_curl(text)

    result = {
        "url": "",
        "method": "GET",
        "headers": {},
        "cookies": {},
        "body": None,
    }

    i = 1
    while i < len(tokens):
        token = tokens[i]

        if token in ("-X", "--request"):
            i += 1
            if i < len(tokens):
                result["method"] = tokens[i].upper()
        elif token in ("-H", "--header"):
            i += 1
            if i < len(tokens):
                _parse_header(tokens[i], result)
        elif token in ("-b", "--cookie"):
            i += 1
            if i < len(tokens):
                _parse_cookies(tokens[i], result["cookies"])
        elif token in ("-d", "--data", "--data-raw", "--data-binary"):
            i += 1
            if i < len(tokens):
                result["method"] = "POST"
                result["body"] = tokens[i]
        elif token == "--compressed":
            pass
        elif not token.startswith("-"):
            result["url"] = token

        i += 1

    parsed_body = None
    if result["body"]:
        body_text = result["body"]
        try:
            parsed_body = json.loads(body_text)
        except (json.JSONDecodeError, TypeError):
            parsed_body = body_text

    return {
        "url": result["url"],
        "method": result["method"],
        "headers": result["headers"],
        "cookies": result["cookies"],
        "body_template": parsed_body or {},
    }


def _tokenize_curl(text: str) -> list[str]:
    tokens = []
    i = 0
    n = len(text)

    while i < n:
        if text[i] in (" ", "\t", "\n", "\r"):
            i += 1
            continue

        if text[i] == "\\" and i + 1 < n and text[i + 1] == "\n":
            i += 2
            continue

        if text[i] == "-" and _is_option_start(text, i):
            opt, i = _read_option(text, i, n)
            tokens.append(opt)
            continue

        if text[i] == "'":
            val, i = _read_single_quoted(text, i, n)
            tokens.append(val)
            continue

        if text[i] == '"':
            val, i = _read_double_quoted(text, i, n)
            tokens.append(val)
            continue

        if text[i] == "$" and i + 1 < n and text[i + 1] == "'":
            val, i = _read_dollar_single_quoted(text, i, n)
            tokens.append(val)
            continue

        val, i = _read_unquoted(text, i, n)
        if val:
            tokens.append(val)

    return tokens


def _is_option_start(text: str, i: int) -> bool:
    if i > 0 and text[i - 1] not in (" ", "\t", "\n", "\r"):
        return False
    return True


def _read_option(text: str, i: int, n: int) -> tuple[str, int]:
    j = i
    while j < n and text[j] not in (" ", "\t", "\n", "\r", "="):
        if text[j] == "\\" and j + 1 < n and text[j + 1] == "\n":
            break
        j += 1
    return text[i:j], j


def _read_single_quoted(text: str, i: int, n: int) -> tuple[str, int]:
    i += 1
    start = i
    while i < n and text[i] != "'":
        i += 1
    val = text[start:i]
    if i < n:
        i += 1
    return val, i


def _read_double_quoted(text: str, i: int, n: int) -> tuple[str, int]:
    i += 1
    parts = []
    start = i
    while i < n and text[i] != '"':
        if text[i] == "\\" and i + 1 < n:
            parts.append(text[start:i])
            i += 1
            parts.append(text[i])
            i += 1
            start = i
        else:
            i += 1
    parts.append(text[start:i])
    if i < n:
        i += 1
    return "".join(parts), i


def _read_dollar_single_quoted(text: str, i: int, n: int) -> tuple[str, int]:
    i += 2
    parts = []
    while i < n and text[i] != "'":
        if text[i] == "\\" and i + 1 < n:
            next_char = text[i + 1]
            if next_char == "n":
                parts.append("\n")
                i += 2
            elif next_char == "t":
                parts.append("\t")
                i += 2
            elif next_char == "r":
                parts.append("\r")
                i += 2
            elif next_char == "\\":
                parts.append("\\")
                i += 2
            elif next_char == "'":
                parts.append("'")
                i += 2
            elif next_char == '"':
                parts.append('"')
                i += 2
            elif next_char == "a":
                parts.append("\a")
                i += 2
            elif next_char == "b":
                parts.append("\b")
                i += 2
            elif next_char == "f":
                parts.append("\f")
                i += 2
            elif next_char == "v":
                parts.append("\v")
                i += 2
            elif next_char == "0":
                i += 1
                octal = ""
                while i < n and text[i] in "01234567" and len(octal) < 3:
                    octal += text[i]
                    i += 1
                parts.append(chr(int(octal, 8)) if octal else "\0")
            elif next_char == "x" or next_char == "X":
                i += 2
                hex_str = ""
                while i < n and text[i] in "0123456789abcdefABCDEF" and len(hex_str) < 2:
                    hex_str += text[i]
                    i += 1
                parts.append(chr(int(hex_str, 16)) if hex_str else "")
            elif next_char == "u":
                i += 2
                hex_str = ""
                while i < n and text[i] in "0123456789abcdefABCDEF" and len(hex_str) < 4:
                    hex_str += text[i]
                    i += 1
                if hex_str:
                    parts.append(chr(int(hex_str, 16)))
            elif next_char == "U":
                i += 2
                hex_str = ""
                while i < n and text[i] in "0123456789abcdefABCDEF" and len(hex_str) < 8:
                    hex_str += text[i]
                    i += 1
                if hex_str:
                    parts.append(chr(int(hex_str, 16)))
            elif next_char == "e" or next_char == "E":
                parts.append("\x1b")
                i += 2
            else:
                parts.append("\\" + next_char)
                i += 2
        else:
            parts.append(text[i])
            i += 1

    if i < n:
        i += 1
    return "".join(parts), i


def _read_unquoted(text: str, i: int, n: int) -> tuple[str, int]:
    start = i
    while i < n and text[i] not in (" ", "\t", "\n", "\r"):
        if text[i] == "\\" and i + 1 < n and text[i + 1] == "\n":
            break
        i += 1
    return text[start:i], i


def _parse_header(header_val: str, result: dict) -> None:
    if ":" not in header_val:
        return
    key, _, value = header_val.partition(":")
    key = key.strip()
    value = value.strip()
    if key.lower() == "cookie":
        _parse_cookies(value, result["cookies"])
    else:
        result["headers"][key] = value


def _parse_cookies(cookie_str: str, cookies: dict) -> None:
    for cookie_pair in cookie_str.split(";"):
        cookie_pair = cookie_pair.strip()
        if "=" in cookie_pair:
            ck, _, cv = cookie_pair.partition("=")
            cookies[ck.strip()] = cv.strip()
