from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import heimdall as c
from objectives import check_output
from scope import Scope


def allowed(command=''):
    return {'verdict': 'ALLOW', 'mode': 'direct', 'flag_path': 'test.allow', 'token': 'tok'}


class M8ScopeObjectiveTests(unittest.TestCase):
    def test_scope_matching_and_rule_guards(self):
        s = Scope({
            'program': 'test',
            'in_scope': [{'host': '*.example.com'}, {'cidr': '10.0.0.0/24'}],
            'out_of_scope': [{'host': 'admin.example.com'}],
            'rules': ['no_dos', 'no_bruteforce'],
        })
        self.assertTrue(s.check_target('api.example.com').ok)
        self.assertFalse(s.check_target('admin.example.com').ok)
        self.assertTrue(s.check_target('10.0.0.5').ok)
        self.assertFalse(s.check_target('192.168.1.1').ok)
        self.assertFalse(s.check_command('hydra -l root 10.0.0.5').ok)
        self.assertTrue(s.check_command('curl https://api.example.com/health').ok)

    def test_objective_detection(self):
        hits = check_output(
            [{'id': 'flag', 'pattern': r'flag\{[^}]+\}', 'match': 'first'}],
            'cat /root/flag.txt',
            'the flag is flag{abc123def456}\n',
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, 'flag{abc123def456}')

    def test_playbook_runner_loads_next_step(self):
        runner = c.PlaybookRunner('ctf_linux', '10.10.10.5', state_dir=tempfile.mkdtemp())
        step = runner.next_step()
        self.assertEqual(step['id'], 'host_discovery')
        self.assertEqual(step['command'], 'nmap -sn 10.10.10.5')

    def test_bug_bounty_scope_blocks_before_daemon_verdict(self):
        daemon = Mock()
        pal = c.Palette(False, ascii_only=True)
        with tempfile.TemporaryDirectory() as directory:
            scope_file = Path(directory) / 'scope.yaml'
            scope_file.write_text(
                'program: acme\n'
                'platform: hackerone\n'
                'in_scope:\n'
                '  - host: "*.acme-test.com"\n'
                'out_of_scope:\n'
                '  - host: "admin.acme-test.com"\n'
                'rules: [no_dos, no_bruteforce]\n',
                encoding='utf-8',
            )
            args = Mock(playbook='bug_bounty', target='admin.acme-test.com',
                        scope_file=str(scope_file), show_objectives=False,
                        yes_to_plan=True, dry_run=True, execute_on_windows=False,
                        timeout=5, ascii=True, playbook_state_dir=directory)
            self.assertEqual(c.cmd_playbook(pal, daemon, args), 2)
            daemon.verdict.assert_not_called()

    def test_playbook_dry_run_asks_daemon_for_scoped_command(self):
        daemon = Mock()
        daemon.verdict.return_value = allowed('whois acme-test.com')
        pal = c.Palette(False, ascii_only=True)
        with tempfile.TemporaryDirectory() as directory:
            scope_file = Path(directory) / 'scope.yaml'
            scope_file.write_text(
                'program: acme\n'
                'platform: hackerone\n'
                'in_scope:\n'
                '  - host: "*.acme-test.com"\n'
                '  - host: "acme-test.com"\n'
                'out_of_scope:\n'
                '  - host: "admin.acme-test.com"\n'
                'rules: [no_dos, no_bruteforce]\n',
                encoding='utf-8',
            )
            args = Mock(playbook='bug_bounty', target='acme-test.com',
                        scope_file=str(scope_file), show_objectives=True,
                        yes_to_plan=True, dry_run=True, execute_on_windows=False,
                        timeout=5, ascii=True, playbook_state_dir=directory)
            self.assertEqual(c.cmd_playbook(pal, daemon, args), 0)
            daemon.verdict.assert_called_once_with('whois acme-test.com')


if __name__ == '__main__':
    unittest.main()
