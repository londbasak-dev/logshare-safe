import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

from logshare_safe.redactor import Redactor, SafeError, process_file
from logshare_safe.cli import main


class RedactorTests(unittest.TestCase):
    def test_complete_standard_header_redaction(self):
        for header in ('Cookie', 'Set-Cookie', 'Authorization', 'Proxy-Authorization'):
            payload = f'{header}: first=SYNTHETIC_FIRST; session=SYNTHETIC_SESSION; sid=SYNTHETIC_SID\nkeep next line'
            result = Redactor().text(payload)
            self.assertEqual(result, f'{header}: [REDACTED]\nkeep next line')
        self.assertEqual(Redactor().text('Authorization: Digest username="SYNTHETIC_USER", response="SYNTHETIC_RESPONSE"'), 'Authorization: [REDACTED]')

    def test_adversarial_text_runtime_is_bounded(self):
        script = 'import sys;from logshare_safe.redactor import Redactor;Redactor().text(sys.argv[1]*65536)'
        for character in ('a', '!', '?', 'a-', 'token'):
            with self.subTest(character=character):
                try:
                    completed = subprocess.run([sys.executable, '-c', script, character], capture_output=True, timeout=3)
                except subprocess.TimeoutExpired:
                    self.fail('Redaction exceeded the three second subprocess limit.')
                self.assertEqual(completed.returncode, 0)

    def test_cli_unknown_argument_is_not_echoed(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            main(['synthetic-input', 'synthetic-output', '--SYNTHETIC_PRIVATE_ARG'])
        self.assertNotIn('SYNTHETIC_PRIVATE_ARG', stderr.getvalue())

    def test_authorization_schemes(self):
        result = Redactor().text('Authorization: Bearer SYNTHETIC_BEARER\nAuthorization: Basic U1lOVEhFVElD')
        self.assertNotIn('SYNTHETIC_BEARER', result)
        self.assertNotIn('U1lOVEhFVElD', result)

    def test_assignments_and_quoted_values(self):
        result = Redactor().text('token=synthetic password="two words" api_key: synthetic-key outer=password=SYNTHETIC_NESTED')
        for value in ('synthetic', 'two words'):
            self.assertNotIn(value, result)
        self.assertNotIn('SYNTHETIC_NESTED', result)

    def test_url_userinfo_and_query(self):
        result = Redactor().text('https://demo:synthetic@example.test/a?access_token=synthetic2&view=all')
        self.assertNotIn('demo:', result)
        self.assertNotIn('synthetic', result)
        self.assertIn('view=all', result)

    def test_email_and_ipv4(self):
        result = Redactor().text('demo@example.test 192.0.2.10 invalid=999.2.3.4')
        self.assertNotIn('demo@example.test', result)
        self.assertNotIn('192.0.2.10', result)
        self.assertIn('999.2.3.4', result)

    def test_multiline_and_unterminated_private_key(self):
        for tail in ('\n-----END PRIVATE KEY-----', ''):
            self.assertNotIn('SYNTHETIC_KEY_BODY', Redactor().text('-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_BODY' + tail))

    def test_recursive_json_secret_subtree_and_strings(self):
        r = Redactor()
        result = r.value({'password': {'nested': 'synthetic'}, 'items': [{'text': 'demo@example.test'}]})
        self.assertEqual(result['password'], '[REDACTED]')
        self.assertNotIn('demo@example.test', json.dumps(result))

    def test_custom_patterns_are_literals_and_bounded(self):
        self.assertEqual(Redactor(['(a+)+']).text('x (a+)+ y'), 'x [REDACTED] y')
        with self.assertRaises(SafeError):
            Redactor(['x' * 257])
        with self.assertRaises(SafeError):
            Redactor([''] )

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d)/'in.txt', Path(d)/'out.txt'
            src.write_text('token=synthetic')
            dst.write_text('keep')
            with self.assertRaises(SafeError):
                process_file(src, dst)
            self.assertEqual(dst.read_text(), 'keep')

    def test_same_path_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)/'in.txt'
            src.write_text('keep')
            with self.assertRaises(SafeError):
                process_file(src, src)
            self.assertEqual(src.read_text(), 'keep')

    def test_strict_json_and_size_limits(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d)/'in.json', Path(d)/'out.json'
            for payload in ('{"a":1,"a":2}', '{broken', '{"x":NaN}'):
                src.write_text(payload)
                with self.assertRaises(SafeError):
                    process_file(src, dst, mode='json')
                self.assertFalse(dst.exists())
            src.write_text('x'*20)
            with self.assertRaises(SafeError):
                process_file(src, dst, max_bytes=10)

    def test_cli_counts_only_and_private_output(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d)/'in.txt', Path(d)/'out.txt'
            src.write_text('password=synthetic-value')
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main([str(src), str(dst)])
            self.assertEqual(code, 0)
            self.assertNotIn('synthetic-value', stdout.getvalue()+stderr.getvalue())
            self.assertEqual(json.loads(stdout.getvalue())['total_redactions'], 1)
            if os.name != 'nt':
                self.assertEqual(dst.stat().st_mode & 0o777, 0o600)

    def test_json_depth_limit(self):
        with self.assertRaises(SafeError):
            Redactor().value([[[['synthetic']]]], max_depth=2)


if __name__ == '__main__':
    unittest.main()
