import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import heimdald as h


class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.policy = h.load_policy(Path(h.__file__).with_name('safety.yaml'), True)

    def test_shell_bypass_and_unknown_subcommand(self):
        for command in ('ls; useradd bob', 'ls $(id)', 'apt remove-all vim',
                        'apt -y remove vim', 'cargo publish', 'sudo ls', 'ls\nrm -rf /'):
            with self.subTest(command=command):
                self.assertEqual(h.resolve(self.policy, command, 'hybrid')['verdict'], 'DENY')

    def test_mappings_and_mode(self):
        self.assertEqual(h.resolve(self.policy, 'netdiscover', 'hybrid')['verdict'], 'ASK')
        self.assertEqual(h.resolve(self.policy, 'nmap -sV localhost', 'hybrid')['verdict'], 'ASK')
        self.assertEqual(h.resolve(self.policy, 'python3 script.py', 'direct')['mode'], 'sandbox')

    def test_token_binding(self):
        token = h.mint_token(b'x' * 32, 'ls', 'direct')
        self.assertTrue(h.verify_token(b'x' * 32, token, 'ls', 'direct'))
        self.assertFalse(h.verify_token(b'x' * 32, token, 'cat', 'direct'))
        self.assertFalse(h.verify_token(b'x' * 32, token, 'ls', 'sandbox'))

    def test_history_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            h.History(Path(directory)).write({'event': 1})
            h.History(Path(directory)).write({'event': 2})
            lines = next(Path(directory).glob('*.jsonl')).read_bytes().splitlines()
            self.assertEqual(json.loads(lines[1])['prev_hash'], hashlib.sha256(lines[0]).hexdigest())

    def test_requests_and_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            paths = {'history': base / 'history', 'mode_file': base / 'mode'}
            daemon = h.Daemon(self.policy, b'x' * 32, paths, True)
            self.assertIn('error', daemon.dispatch([], None))
            self.assertEqual(daemon.dispatch({'op': 'verdict', 'cmd': 123}, None)['verdict'], 'DENY')
            self.assertIsNone(daemon.dispatch({'op': 'verdict', 'cmd': 'rm file'}, None)['token'])
            self.assertFalse(daemon.dispatch({'op': 'mode_set', 'mode': 'direct', 'phrase': ''}, None)['ok'])


if __name__ == '__main__':
    unittest.main()
