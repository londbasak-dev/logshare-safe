"""Bounded, offline heuristics; redacted output still requires human review."""
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import unquote_plus

MARKER = '[REDACTED]'
MAX_BYTES = 5 * 1024 * 1024
SECRET_KEY = re.compile(r'(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|session(?:[_-]?id)?|private[_-]?key|client[_-]?secret)', re.I)
PRIVATE_KEY = re.compile(r'-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----|\Z)')
AUTH = re.compile(r'\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]+', re.I)
HEADERS = re.compile(r'(?<![\w-])((?:(?:proxy-)?authorization|(?:set-)?cookie)[ \t]*:[ \t]*)[^\r\n]*', re.I)
# Each identifier/scheme/local-part has one permitted start. Otherwise re.search
# retries long failing tails at every character, causing quadratic work.
ASSIGN = re.compile(r'''(?<![\w-])([\w-]+)(["']?\s*[:=]\s*)''')
ASSIGN_VALUE = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s&,;"'<>]+''')
USERINFO = re.compile(r'(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@]+@')
QUERY = re.compile(r'([?&])([^\s=?&#]+)=([^\s&#]*)')
EMAIL = re.compile(r'(?<![A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}(?![\w.-])')
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')


class SafeError(Exception):
    """Contains only a fixed, non-sensitive diagnostic."""


class Redactor:
    def __init__(self, literals=()):
        literals = list(literals)
        if len(literals) > 32 or any(not isinstance(x, str) or not 1 <= len(x) <= 256 for x in literals):
            raise SafeError('Custom literals must contain 1–256 characters; at most 32 are allowed.')
        self.literals = sorted(set(literals), key=len, reverse=True)
        self.counts = Counter()

    def _replace(self, pattern, text, rule, replacement=MARKER):
        text, count = pattern.subn(replacement, text)
        self.counts[rule] += count
        return text

    def text(self, text):
        text = self._replace(PRIVATE_KEY, text, 'private_key')
        text = self._replace(HEADERS, text, 'sensitive_header', lambda m: m[1] + MARKER)
        text = self._replace(AUTH, text, 'authorization', lambda m: m[1] + ' ' + MARKER)
        text = self._replace(USERINFO, text, 'url_userinfo', lambda m: m[1] + MARKER + '@')

        def query(match):
            if SECRET_KEY.search(unquote_plus(match[2])):
                self.counts['url_query'] += 1
                return match[1] + match[2] + '=' + MARKER
            return match[0]

        text = QUERY.sub(query, text)
        chunks, cursor = [], 0
        for match in ASSIGN.finditer(text):
            if match.start() < cursor or not SECRET_KEY.search(match[1]):
                continue
            value = ASSIGN_VALUE.match(text, match.end())
            if value:
                chunks.extend((text[cursor:match.end()], MARKER))
                cursor = value.end()
                self.counts['secret_assignment'] += 1
        chunks.append(text[cursor:])
        text = ''.join(chunks)
        text = self._replace(EMAIL, text, 'email')

        def ipv4(match):
            try:
                ipaddress.IPv4Address(match[0])
            except ValueError:
                return match[0]
            self.counts['ipv4'] += 1
            return MARKER

        text = IPV4.sub(ipv4, text)
        for literal in self.literals:
            count = text.count(literal)
            if count:
                text = text.replace(literal, MARKER)
                self.counts['custom_literal'] += count
        return text

    def value(self, value, max_depth=64, _depth=0):
        if _depth > max_depth:
            raise SafeError('JSON nesting exceeds the supported limit.')
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                # Keys can themselves contain personal data. Redact and reject collisions.
                safe_key = self.text(str(key))
                if safe_key in result:
                    raise SafeError('Redaction would create duplicate JSON keys.')
                if SECRET_KEY.search(str(key)):
                    self.counts['json_secret'] += 1
                    result[safe_key] = MARKER
                else:
                    result[safe_key] = self.value(child, max_depth, _depth + 1)
            return result
        if isinstance(value, list):
            return [self.value(child, max_depth, _depth + 1) for child in value]
        return self.text(value) if isinstance(value, str) else value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SafeError('Duplicate JSON keys are unsupported.')
        result[key] = value
    return result


def _reject_constant(_value):
    raise SafeError('Non-finite JSON numbers are unsupported.')


def process_file(source, destination, mode='auto', literals=(), max_bytes=MAX_BYTES):
    """Create a new output exclusively; never mutate or overwrite the input."""
    source, destination = Path(source), Path(destination)
    if mode not in ('auto', 'text', 'json') or not 1 <= max_bytes <= MAX_BYTES:
        raise SafeError('Unsupported format or input size limit.')
    try:
        if source.resolve() == destination.resolve() or destination.exists() or destination.is_symlink():
            raise SafeError('Output must be a new path distinct from the input.')
        if not source.is_file():
            raise SafeError('Input must be a readable regular file.')
        with source.open('rb') as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise SafeError('Input exceeds the size limit.')
        raw = data.decode('utf-8-sig')
        redactor = Redactor(literals)
        if mode == 'json' or (mode == 'auto' and source.suffix.lower() == '.json'):
            value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            rendered = json.dumps(redactor.value(value), ensure_ascii=True, indent=2, allow_nan=False) + '\n'
        else:
            rendered = redactor.text(raw)
        # O_EXCL also rejects dangling symlinks and races creating the output.
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as handle:
                handle.write(rendered)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return {'total_redactions': sum(redactor.counts.values()),
                'counts': {key: count for key, count in sorted(redactor.counts.items()) if count}}
    except SafeError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise SafeError('Unable to read, parse, redact, or create the output safely.') from None
