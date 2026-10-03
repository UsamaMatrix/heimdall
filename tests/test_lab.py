import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import heimdald as h
import lab

ROOT = Path(__file__).resolve().parents[1]


class LabTests(unittest.TestCase):
    def setUp(self):
        self.policy = h.load_policy(ROOT / 'safety.yaml', True)

    def test_env_check_reports_default_route_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = copy.deepcopy(self.policy)
            policy['lab_mode']['evidence_dir'] = str(Path(directory) / 'evidence')
            with patch.object(lab, '_run') as run:
                run.side_effect = [
                    (0, 'default via 192.0.2.1 dev eth0\n', ''),
                    (0, 'lo UNKNOWN 127.0.0.1/8\neth0 UP 192.0.2.10/24\n', ''),
                    (0, '', ''),
                ]
                snap = lab.env_check(policy, dev=True)
            self.assertFalse(snap['ok'])
            self.assertFalse(snap['checks']['no_default_route']['ok'])
            self.assertFalse(snap['checks']['no_non_lo_addr']['ok'])

    def test_evidence_writer_start_and_end(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / 'malware_sample.py'
            sample.write_text('print(1)\n', encoding='utf-8')
            writer = lab.EvidenceWriter(Path(directory) / 'evidence', dev=True)
            evidence_id = writer.new_id()
            writer.start_record(evidence_id, f'python3 {sample}', 'destructive_study.malware.static_analysis', {'ok': True}, 1000, sample_paths=[str(sample)])
            writer.end_record(evidence_id, 0, stdout_sha256='a' * 64, stderr_sha256='b' * 64, duration_ms=7, sandboxed=True)
            record = json.loads((Path(directory) / 'evidence' / f'{evidence_id}.json').read_text())
            self.assertEqual(record['status'], 'complete')
            self.assertEqual(record['samples'][0]['path'], str(sample))
            self.assertEqual(record['stdout_sha256'], 'a' * 64)

    def test_daemon_lab_guard_and_enable(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            policy = copy.deepcopy(self.policy)
            policy['command_map']['labtool'] = 'destructive_study.malware.static_analysis'
            daemon = h.Daemon(policy, b'x' * 32, {'history': base / 'history', 'mode_file': base / 'mode', 'var': base / 'var'}, True)
            denied = daemon.dispatch({'op': 'verdict', 'cmd': 'labtool'}, None)
            self.assertEqual(denied['verdict'], 'DENY')
            self.assertEqual(denied['reason'], 'lab_mode disabled')

            policy['lab_mode']['enabled'] = True
            daemon = h.Daemon(policy, b'x' * 32, {'history': base / 'history2', 'mode_file': base / 'mode2', 'var': base / 'var2'}, True)
            denied = daemon.dispatch({'op': 'verdict', 'cmd': 'labtool'}, None)
            self.assertEqual(denied['verdict'], 'DENY')
            self.assertIn('lab mode not active', denied['reason'])

            good = {'ok': True, 'checks': {'no_default_route': {'ok': True, 'detail': None}}}
            with patch.object(lab, 'env_check', return_value=good):
                self.assertTrue(daemon.dispatch({'op': 'lab_enable'}, None)['ok'])
                ask = daemon.dispatch({'op': 'verdict', 'cmd': 'labtool'}, None)
                self.assertEqual(ask['verdict'], 'ASK')
                self.assertEqual(ask['confirm_phrase'], 'I HAVE WRITTEN AUTHORIZATION')
                approved = daemon.dispatch({'op': 'verdict', 'cmd': 'labtool', 'confirm': True, 'phrase': 'I HAVE WRITTEN AUTHORIZATION'}, None)
                self.assertEqual(approved['verdict'], 'ALLOW')
                self.assertIn('evidence_id', approved)
                end = daemon.dispatch({'op': 'exec_end', 'cmd': 'labtool', 'mode': approved['mode'], 'token': approved['token'], 'rc': 0, 'duration_ms': 1, 'stdout_sha256': 'c' * 64, 'stderr_sha256': 'd' * 64}, None)
                self.assertTrue(end['ok'])
            daemon.lab.shutdown()


if __name__ == '__main__':
    unittest.main()
