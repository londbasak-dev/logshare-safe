# LogShare Safe

A small Python CLI that redacts an explicitly supplied text log or JSON file **offline**, writing a new output. It never searches directories, contacts a service, reads your environment, or prints a raw preview. All bundled examples are newly invented synthetic data.

## Install and try

Requires Python 3.10 or newer. From this repository:

```sh
python -m venv .venv
# Activate the environment for your shell, then:
python -m pip install -e .
logshare-safe samples/synthetic.txt redacted.txt
logshare-safe samples/synthetic.json redacted.json --format json
logshare-safe samples/synthetic.txt custom-redacted.txt --literal SYNTHETIC_CUSTOM_ID
```

The output must not exist, and must differ from the input. Repeating a demo with the same output name intentionally fails. Successful stdout is JSON containing only counts, for example `{"counts": {"secret_assignment": 1}, "total_redactions": 1}` for the single input `password=synthetic`. Exit status: `0` completed, `2` invalid arguments/input or refused output. `--help` lists options.

## What it does

- Masks complete single-line Cookie, Set-Cookie, Authorization and Proxy-Authorization header values (including Digest authentication), standalone Bearer/Basic values, common token/password/API-key assignments, URL userinfo and sensitive query values, email addresses, valid IPv4 addresses, and multiline private-key blocks (including unterminated blocks). Header redaction consumes the rest of the line, including subsequent cookie pairs.
- Traverses JSON lists and objects, redacts values under sensitive keys (including entire subtrees), and examines other string values and keys. Rejects duplicate keys and collisions caused by key redaction. Original JSON formatting is not retained.
- `--format auto` treats `.json` files as strict JSON and other extensions as text. Choose `--format json` explicitly for JSON with another extension. There is no fallback to text after a JSON parse failure.
- Defaults to a 5 MiB input limit, with `--max-bytes` able only to lower it. JSON traversal is limited to depth 64; malformed, non-finite, and excessively nested JSON is refused.
- Custom patterns are **exact literals**, maximum 32 literals, 1–256 characters each. Arbitrary regular expressions are deliberately unsupported, preventing user-pattern backtracking attacks. Use the Python `Redactor(literals=[...])` API to avoid putting a sensitive literal in shell history or process arguments.
- Creates the output using exclusive creation and POSIX mode `0600`; refuses existing files and symlinks. On Windows, permissions inherit the destination directory ACL. Use a private directory and verify its ACL; POSIX mode bits do not establish Windows privacy. Parent directories are not created.

Counts record matching/replacement operations, not unique people or secrets; overlapping rules may count one value more than once. No input names, paths, captured values, or previews appear in the summary. Errors use fixed diagnostics.

## Limits

**Redaction is a heuristic, not a guarantee that a file is safe to share.** Review the entire output locally. Names, IPv6, identifiers, nested encodings, compressed/binary logs, multiline cookies, arbitrary application formats, and unknown key names may remain. Some legitimate text can be over-redacted. Numeric JSON values are preserved unless beneath a sensitive key. UTF-8 input only. A malformed or already modified PEM marker may evade detection. Unstructured assignments containing unusual escapes or delimiters may be only partly recognized.

Processing is in memory, so original content exists transiently in process memory. This is not secure deletion or protection against an untrusted local OS, crash dumps, or another process changing input/parent directories. An interrupted write may leave partial **redacted** output. No files are automatically uploaded, backed up, or synced.

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

The standard-library test suite uses temporary directories and exclusively synthetic strings. Adversarial long identifiers, punctuation and query delimiters are checked in bounded subprocesses to catch quadratic regex regressions; pattern start boundaries prevent retrying the same long token at every character. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). MIT licensed; see [LICENSE](LICENSE).
