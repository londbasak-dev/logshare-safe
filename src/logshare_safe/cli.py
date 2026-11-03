"""Count-only CLI: never print raw input or previews."""
import argparse
import json
import sys
from .redactor import MAX_BYTES, SafeError, process_file


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'error: invalid command arguments; use --help.\n')


def main(argv=None):
    parser = Parser(description='Offline heuristic log redaction to a new output file.')
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('--format', choices=('auto', 'text', 'json'), default='auto')
    parser.add_argument('--literal', action='append', default=[], help='Custom exact text, not regex; avoid secret values in shell history.')
    parser.add_argument('--max-bytes', type=int, default=MAX_BYTES, help='Lower the 5 MiB input cap.')
    args = parser.parse_args(argv)
    try:
        summary = process_file(args.input, args.output, args.format, args.literal, args.max_bytes)
    except SafeError as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
