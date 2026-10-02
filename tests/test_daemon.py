import hashlib
import copy
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

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

    def test_confirmation_contract_and_strict_boolean(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            daemon = h.Daemon(self.policy, b'x' * 32,
                              {'history': base / 'history', 'mode_file': base / 'mode'}, True)
            request = {'op': 'verdict', 'cmd': 'nmap 127.0.0.1'}
            ask = daemon.dispatch(request, None)
            self.assertEqual(ask['confirm_phrase'], 'I UNDERSTAND THE RISK')
            for confirm in (False, 'true', 1):
                result = daemon.dispatch(dict(request, confirm=confirm, phrase=ask['confirm_phrase']), None)
                self.assertEqual(result['verdict'], 'ASK')
                self.assertIsNone(result['token'])
            approved = daemon.dispatch(dict(request, confirm=True, phrase=ask['confirm_phrase']), None)
            self.assertEqual(approved['verdict'], 'ALLOW')
            self.assertTrue(approved['confirmed'])
            self.assertTrue(h.verify_token(daemon.secret, approved['token'], request['cmd'], 'direct'))
            denied = daemon.dispatch({'op': 'verdict', 'cmd': 'rm -rf /', 'confirm': True,
                                      'phrase': ask['confirm_phrase']}, None)
            self.assertEqual(denied['verdict'], 'DENY')
            self.assertIsNone(denied['token'])

    def test_sandbox_confirmation_and_destructive_phrase(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            policy = copy.deepcopy(self.policy)
            policy['defaults']['warn_confirmation_phrase'] = 'CUSTOM PHRASE'
            daemon = h.Daemon(policy, b'x' * 32,
                              {'history': base / 'history', 'mode_file': base / 'mode'}, True)
            self.assertEqual(daemon.dispatch({'op': 'verdict', 'cmd': 'nmap localhost'}, None)['confirm_phrase'], 'CUSTOM PHRASE')
            ask = daemon.dispatch({'op': 'verdict', 'cmd': 'python3 script.py'}, None)
            self.assertEqual(ask['mode'], 'sandbox')
            self.assertIsNone(ask['confirm_phrase'])
            approved = daemon.dispatch({'op': 'verdict', 'cmd': 'python3 script.py', 'confirm': True}, None)
            self.assertEqual(approved['verdict'], 'ALLOW')
            self.assertEqual(approved['mode'], 'sandbox')
            policy['command_map']['labtool'] = 'destructive_study.malware.static_analysis'
            self.assertEqual(daemon.dispatch({'op': 'verdict', 'cmd': 'labtool'}, None)['verdict'], 'DENY')
            policy['lab_mode']['enabled'] = True
            policy['domains']['destructive_study']['enabled'] = True
            policy['domains']['destructive_study']['flags']['malware']['enabled'] = True
            ask = daemon.dispatch({'op': 'verdict', 'cmd': 'labtool'}, None)
            self.assertEqual(ask['confirm_phrase'], 'I HAVE WRITTEN AUTHORIZATION')
            self.assertIsNone(ask['token'])

    def test_m3_sandbox_scan_config_and_exec_audit_ops(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            daemon = h.Daemon(self.policy, b'x' * 32,
                              {'history': base / 'history', 'mode_file': base / 'mode'}, True)
            ask = daemon.dispatch({'op': 'verdict', 'cmd': 'python3 script.py'}, 1000)
            self.assertEqual(ask['mode'], 'sandbox')
            self.assertIn('sandbox_config', ask)
            self.assertEqual(ask['sandbox_config']['impl'], 'bwrap')
            self.assertIn('scan_config', ask)
            self.assertEqual(ask['scan_config']['language'], 'python')
            self.assertIn('bandit', ask['scan_config']['scanners'])
            approved = daemon.dispatch({'op': 'verdict', 'cmd': 'python3 script.py',
                                        'confirm': True}, 1000)
            self.assertEqual(approved['verdict'], 'ALLOW')
            start = daemon.dispatch({'op': 'exec_start', 'cmd': 'python3 script.py',
                                     'mode': 'sandbox', 'token': approved['token']}, 1000)
            self.assertTrue(start['ok'])
            end = daemon.dispatch({'op': 'exec_end', 'cmd': 'python3 script.py',
                                   'mode': 'sandbox', 'token': approved['token'],
                                   'rc': 3, 'duration_ms': 12,
                                   'stdout_sha256': '0' * 64,
                                   'stderr_sha256': '1' * 64,
                                   'sandboxed': True}, 1000)
            self.assertTrue(end['ok'])
            bad = daemon.dispatch({'op': 'exec_start', 'cmd': 'python3 other.py',
                                   'mode': 'sandbox', 'token': approved['token']}, 1000)
            self.assertFalse(bad['ok'])
            records = [json.loads(line) for line in next((base / 'history').glob('*.jsonl')).read_text().splitlines()]
            self.assertEqual(records[-2]['op'], 'exec_start')
            self.assertEqual(records[-1]['op'], 'exec_end')
            self.assertTrue(records[-1]['sandboxed'])

    def test_history_failure_revokes_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for dev in (True, False):
                daemon = h.Daemon(self.policy, b'x' * 32,
                                  {'history': base / 'history', 'mode_file': base / 'mode'}, dev)
                with patch.object(daemon.history, 'write', side_effect=OSError('disk full')):
                    result = daemon.dispatch({'op': 'verdict', 'cmd': 'nmap localhost',
                                               'confirm': True, 'phrase': 'I UNDERSTAND THE RISK'}, None)
                    self.assertEqual(result['verdict'], 'DENY')
                    self.assertIsNone(result['token'])
                    self.assertFalse(result['confirmed'])

    def test_socket_group_is_applied_on_unix_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            socket_path = base / 'bifrost.sock'
            daemon = h.Daemon(self.policy, b'x' * 32,
                              {'history': base / 'history', 'mode_file': base / 'mode'},
                              True, socket_group='heimdall')
            daemon.running = False
            group_module = types.SimpleNamespace(getgrnam=lambda name: types.SimpleNamespace(gr_gid=123))
            with patch.dict(sys.modules, {'grp': group_module}), patch.object(h.os, 'name', 'posix'), \
                    patch.object(h.socket, 'AF_UNIX', 1, create=True), patch.object(h.socket, 'socket'), \
                    patch.object(h.os, 'chown', create=True) as chown, \
                    patch.object(h.os, 'chmod') as chmod, patch('builtins.print'):
                daemon.serve(socket_path)
                chown.assert_called_once_with(socket_path, -1, 123)
                chmod.assert_called_once_with(str(socket_path), 0o660)


if __name__ == '__main__':
    unittest.main()
