from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import build, label


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


if __name__ == '__main__':
    unittest.main()
