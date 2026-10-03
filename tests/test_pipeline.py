from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import bootstrap, build, label, normalize


class PipelineEndpointTests(unittest.TestCase):
    def test_tcp_endpoint_parser(self):
        self.assertEqual(label.parse_tcp_endpoint('127.0.0.1:47651'), ('127.0.0.1', 47651))
        with self.assertRaises(SystemExit):
            label.main(['--tcp', '127.0.0.1'])

    def test_build_dry_run_uses_unified_schema(self):
        self.assertIsNone(build.main(['--dry-run']))

    def test_default_label_endpoint_is_production_socket(self):
        self.assertEqual(label.DEFAULT_SOCKET, '/run/heimdall/bifrost.sock')
        self.assertTrue(label.DEV_SOCKET.replace('\\', '/').endswith('dev-run/run/bifrost.sock'))

    def test_trendyol_user_assistant_command_extraction(self):
        row = normalize._adapter('trendyol', {
            'system': 'You are a cybersecurity assistant.',
            'user': 'How do I list open TCP ports locally?',
            'assistant': 'Run:\n```bash\nss -tulpn\n```',
        })
        self.assertIsNotNone(row)
        self.assertEqual(row['goal'], 'How do I list open TCP ports locally?')
        self.assertEqual(row['command'], 'ss -tulpn')
        self.assertEqual(row['license'], 'Apache-2.0')

    def test_command_extraction_rejects_plain_explanation(self):
        self.assertIsNone(normalize._adapter('trendyol', {
            'user': 'Explain phishing.',
            'assistant': 'Phishing is a social engineering technique.',
        }))

    def test_command_extraction_rejects_absolute_path_prose(self):
        self.assertIsNone(normalize._adapter('trendyol', {
            'user': 'Explain environ poisoning.',
            'assistant': '/proc/self/environ poisoning refers to an LFI technique.',
        }))

    def test_command_extraction_allows_command_with_path_argument(self):
        row = normalize._adapter('trendyol', {
            'user': 'Show the hostname file.',
            'assistant': '```bash\ncat /etc/hostname\n```',
        })
        self.assertIsNotNone(row)
        self.assertEqual(row['command'], 'cat /etc/hostname')

    def test_bootstrap_rows_normalize(self):
        for goal, command in bootstrap.ROWS:
            with self.subTest(command=command):
                row = normalize._adapter('bootstrap', {'goal': goal, 'command': command})
                self.assertIsNotNone(row)
                self.assertEqual(row['command'], command)

    def test_bootstrap_teaches_web_audit_progression(self):
        audit_rows = [(goal, command) for goal, command in bootstrap.ROWS
                      if 'Authorized web audit for https://example.com' in goal]
        commands = [command for _, command in audit_rows]
        self.assertGreaterEqual(len(commands), 8)
        self.assertEqual(len(commands), len(set(commands)))
        self.assertEqual(commands[0], 'curl -I https://example.com/')
        self.assertIn('curl https://example.com/robots.txt', commands)
        self.assertIn('curl https://example.com/sitemap.xml', commands)
        self.assertIn('curl -I https://example.com/wp-json/', commands)
        self.assertIn('whois example.com', commands)
        self.assertIn('dig example.com', commands)
        self.assertIn('curl -I https://example.com/.env', commands)

    def test_system_prompt_rejects_web_audit_repetition(self):
        import heimdall
        self.assertIn('Never repeat a command that already succeeded', heimdall.SYSTEM_PROMPT)
        self.assertIn('WEB AUDIT FLOW', heimdall.SYSTEM_PROMPT)
        self.assertIn('choose the next distinct evidence', heimdall.SYSTEM_PROMPT)


if __name__ == '__main__':
    unittest.main()
