import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import shlex
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import heimdall as c
import heimdald as d
import executor as e

ROOT = Path(__file__).resolve().parents[1]


def allowed(command='ls -la', mode='direct'):
    return {'verdict': 'ALLOW', 'mode': mode, 'flag_path': 'test.read',
            'token': d.mint_token(b'x' * 32, command, mode)}


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.pal = c.Palette(enabled=False, ascii_only=True)
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stderr = contextlib.redirect_stderr(io.StringIO())
        self.stdout.__enter__()
        self.stderr.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def test_llm_plan_schema(self):
        self.assertEqual(c._parse_llm_json('```json\n{"action":"execute","command":"ls"}\n```')['command'], 'ls')
        for content in ('[]', 'null', '{"action":"execute","command":3}',
                        '{"action":"done"}', '{"action":"ask","question":""}',
                        '{"action":"other"}', 'prefix {"action":"done","summary":"ok"}',
                        None, '{"action":"execute","command":"ls","reasoning":[]}'):
            with self.subTest(content=content), self.assertRaises(c.LLMError):
                c._parse_llm_json(content)

    def test_authorization_binding(self):
        self.assertIsNone(c.authorization_error(allowed(), 'ls -la'))
        for verdict in ({'verdict': 'ALLOW', 'mode': 'direct'},
                        allowed('cat file'),
                        {'verdict': 'DEFER'}, {'verdict': 'DENY'}):
            self.assertIsNotNone(c.authorization_error(verdict, 'ls -la'))
        self.assertIsNone(c.authorization_error(allowed(mode='sandbox'), 'ls -la'))

    def test_one_command_denies_defer_missing_token_and_sandbox(self):
        for response in ({'verdict': 'DENY'}, {'verdict': 'DEFER'},
                         {'verdict': 'ALLOW', 'mode': 'direct'}):
            daemon = Mock()
            daemon.verdict.return_value = response
            with self.subTest(response=response), patch.object(c, 'run_command') as run:
                self.assertNotEqual(c.cmd_one_command(self.pal, daemon, 'ls -la', False, True), 0)
                run.assert_not_called()

    def test_confirmation_and_recheck(self):
        daemon = Mock()
        ask = {'verdict': 'ASK', 'mode': 'direct', 'confirm_phrase': 'EXACT PHRASE',
               'flag_path': 'test.write', 'token': None}
        for reply, result in ((allowed(), 0), ({'verdict': 'ASK', 'mode': 'direct'}, 4),
                              (allowed('cat file'), 4)):
            daemon.verdict.side_effect = [ask, reply]
            daemon.request.return_value = {'ok': True}
            with self.subTest(reply=reply), patch('builtins.input', return_value='EXACT PHRASE'), \
                    patch.object(c, 'run_command') as run:
                run.return_value = type('R', (), {'rc': 0, 'stdout': '', 'stderr': '',
                                                  'sandboxed': False, 'duration_ms': 1})()
                self.assertEqual(c.cmd_one_command(self.pal, daemon, 'ls -la', False, True, 7), result)
                daemon.verdict.assert_called_with('ls -la', confirm=True, phrase='EXACT PHRASE')
                if result == 0:
                    run.assert_called_once_with('ls -la', 'direct', None, timeout=7, cwd=os.getcwd())
                else:
                    run.assert_not_called()

    def test_decline_and_dry_run_do_not_execute(self):
        daemon = Mock()
        daemon.verdict.return_value = {'verdict': 'ASK', 'mode': 'direct',
                                      'confirm_phrase': 'EXACT', 'token': None}
        with patch('builtins.input', side_effect=EOFError), patch.object(c, 'run_command') as run:
            self.assertEqual(c.cmd_one_command(self.pal, daemon, 'ls', False, True), 3)
            run.assert_not_called()
        daemon.verdict.return_value = allowed()
        with patch.object(c, 'run_command') as run:
            self.assertEqual(c.cmd_one_command(self.pal, daemon, 'ls -la', True, True), 0)
            run.assert_not_called()

    def test_agent_uses_same_execution_gate(self):
        for verdict in ({'verdict': 'ALLOW', 'mode': 'direct'},
                        {'verdict': 'DEFER'}):
            daemon = Mock()
            daemon.mode_show.return_value = {'mode': 'hybrid'}
            daemon.verdict.return_value = verdict
            llm = Mock()
            llm.propose.return_value = {'action': 'execute', 'command': 'ls -la'}
            with self.subTest(verdict=verdict), patch.object(c, 'run_command') as run:
                self.assertNotEqual(c.cmd_agent(self.pal, daemon, llm, 'list files', False, 2, True), 0)
                run.assert_not_called()

    def test_step_cap_and_repeat_stop(self):
        daemon = Mock()
        daemon.mode_show.return_value = {'mode': 'hybrid'}
        daemon.verdict.return_value = allowed()
        daemon.request.return_value = {'ok': True}
        llm = Mock()
        llm.propose.return_value = {'action': 'execute', 'command': 'ls -la'}
        result = type('R', (), {'rc': 0, 'stdout': 'same', 'stderr': '',
                                'sandboxed': False, 'duration_ms': 1})()
        with patch.object(c, 'run_command', return_value=result) as run:
            self.assertEqual(c.cmd_agent(self.pal, daemon, llm, 'list', False, 10, True), 5)
            self.assertEqual(run.call_count, 2)
        result = type('R', (), {'rc': 0, 'stdout': '', 'stderr': '',
                                'sandboxed': False, 'duration_ms': 1})()
        with patch.object(c, 'run_command', return_value=result) as run:
            self.assertEqual(c.cmd_agent(self.pal, daemon, llm, 'list', False, 1, True), 5)
            self.assertEqual(run.call_count, 1)

    def test_executor_output_timeout_and_shell_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'test.py'
            script.write_text("import sys\nsys.stdout.write('x' * 1100000)\n", encoding='utf-8')
            command = shlex.join([Path(sys.executable).as_posix(), script.as_posix()])
            rc, out, err = c.execute(command, 10)
            self.assertEqual(rc, 0, err)
            self.assertEqual(len(out), c.MAX_CAPTURE_BYTES)
            script.write_text("import time\ntime.sleep(5)\n", encoding='utf-8')
            self.assertEqual(c.execute(command, 0.1)[0], 124)
        self.assertEqual(c.execute('ls; echo nope')[0], 2)

    def test_bwrap_mounts_current_directory_before_chdir(self):
        cwd = '/home/kali/Desktop/heimdall'
        with patch.object(e.shutil, 'which', return_value='/usr/bin/bwrap'), \
                patch.object(e.os.path, 'exists', return_value=True), \
                patch.object(e.os.path, 'isdir', return_value=True):
            argv = e._build_bwrap_argv(['python3', 'hello.py'], {'rw_paths': []}, cwd=cwd)
        self.assertLess(argv.index('--bind'), argv.index('--chdir'))
        self.assertIn('--dir', argv)
        self.assertIn('/home/kali/Desktop', argv)
        self.assertIn(cwd, argv)
        bind_index = argv.index('--bind')
        self.assertEqual(argv[bind_index:bind_index + 3], ['--bind', cwd, cwd])
        chdir_index = argv.index('--chdir')
        self.assertEqual(argv[chdir_index:chdir_index + 2], ['--chdir', cwd])

    def test_old_daemon_and_bad_responses(self):
        client = c.DaemonClient(tcp=('127.0.0.1', 1))
        for response in ({'verdict': 'ASK', 'mode': 'direct'},
                         {'verdict': 'ASK', 'mode': 'direct', 'confirm_phrase': None},
                         {'verdict': 'ALLOW', 'confirm_phrase': []}, {'verdict': 'UNKNOWN'}):
            with self.subTest(response=response), patch.object(client, 'request', return_value=response), \
                    self.assertRaises(c.DaemonError):
                client.verdict('ls')

    def test_endpoint_validation_and_no_production_fallback(self):
        for endpoint in ('localhost', '127.0.0.1:0', '127.0.0.1:99999', '192.0.2.1:80'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                c._tcp_endpoint(endpoint)
        args = Mock(socket=None, tcp=None, dev=False)
        with patch.dict(os.environ, {}, clear=True), patch.object(c.os, 'name', 'posix'), \
                patch.object(c, 'Path', wraps=Path) as path:
            # Use a string factory to avoid creating PosixPath on a Windows host.
            path.side_effect = lambda value: value
            self.assertEqual(c.pick_endpoint(args)['socket_path'], '/run/heimdall/bifrost.sock')

    def test_rate_limiter_and_session_log(self):
        limiter = c.RateLimiter(2)
        self.assertTrue(limiter.acquire())
        self.assertTrue(limiter.acquire())
        self.assertFalse(limiter.acquire(timeout=0.01))
        limiter.last -= 60
        self.assertTrue(limiter.acquire(timeout=0.01))
        with tempfile.TemporaryDirectory() as directory:
            log = c.SessionLog(directory)
            log.write(kind='test', value=1)
            records = [json.loads(line) for line in log.path.read_text().splitlines()]
            self.assertEqual(records[0]['kind'], 'test')
            self.assertEqual(records[0]['seq'], 1)

    def test_mode_set_confirmation_and_daemon_request(self):
        daemon = Mock()
        daemon.request.return_value = {'ok': True, 'previous': 'hybrid', 'current': 'sandbox'}
        with patch('builtins.input', return_value='I UNDERSTAND THE RISK'):
            self.assertEqual(c.cmd_mode_set(self.pal, daemon, 'sandbox'), 0)
        daemon.request.assert_called_once_with({
            'op': 'mode_set',
            'mode': 'sandbox',
            'phrase': 'I UNDERSTAND THE RISK',
        })
        self.assertEqual(c.cmd_mode_set(self.pal, daemon, 'invalid'), 2)
        with patch('builtins.input', return_value='wrong'):
            self.assertEqual(c.cmd_mode_set(self.pal, daemon, 'hybrid'), 3)

    def test_installer_supports_reconfigure_from_sbin(self):
        script = (ROOT / 'heimdall-install.sh').read_text(encoding='utf-8')
        self.assertIn('source_dir()', script)
        self.assertIn('install_if_different()', script)
        self.assertIn('elif [[ -f "$PREFIX/heimdald.py"', script)
        self.assertIn('"$PREFIX/heimdald.service"', script)
        self.assertIn('install_if_different 0755 "$0" "$SBINDIR/heimdall-install"', script)


class LiveIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        base = Path(self.directory.name)
        policy = d.load_policy(ROOT / 'safety.yaml', True)
        self.daemon = d.Daemon(policy, b'x' * 32,
                               {'history': base / 'history', 'mode_file': base / 'mode'}, True)
        daemon = self.daemon

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                daemon.handle(self.request, self.client_address)

        self.server = socketserver.TCPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.client = c.DaemonClient(tcp=self.server.server_address)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_wire_confirmation_and_history(self):
        self.assertTrue(self.client.ping()['pong'])
        self.assertEqual(self.client.mode_show()['mode'], 'hybrid')
        ask = self.client.verdict('nmap 127.0.0.1')
        self.assertEqual(ask['verdict'], 'ASK')
        self.assertIsNone(ask['token'])
        self.assertEqual(self.client.verdict('nmap 127.0.0.1', True, 'wrong')['verdict'], 'ASK')
        approved = self.client.verdict('nmap 127.0.0.1', True, ask['confirm_phrase'])
        self.assertEqual(approved['verdict'], 'ALLOW')
        self.assertTrue(approved['confirmed'])
        self.assertTrue(d.verify_token(self.daemon.secret, approved['token'], 'nmap 127.0.0.1', 'direct'))
        self.assertIsNone(self.client.verdict('rm -rf /', True, ask['confirm_phrase'])['token'])
        records = [json.loads(line) for line in next(self.daemon.paths['history'].glob('*.jsonl')).read_text().splitlines()]
        self.assertTrue(records[2]['confirmed'])

    def test_cli_ping_deny_and_typed_dry_run(self):
        base = [sys.executable, str(ROOT / 'heimdall.py'), '--tcp',
                f'127.0.0.1:{self.server.server_address[1]}', '--ascii', '--no-color']
        for args, phrase, expected in ((['ping'], '', 0), (['mode', 'show'], '', 0),
                                      (['--cmd', 'rm -rf /', '--dry-run'], '', 2),
                                      (['--cmd', 'nmap 127.0.0.1', '--dry-run'], 'I UNDERSTAND THE RISK\n', 0)):
            with self.subTest(args=args):
                result = subprocess.run(base + args, input=phrase, capture_output=True,
                                        text=True, encoding='utf-8', timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertTrue(result.stdout.isascii(), result.stdout)
                self.assertNotIn('\x1b', result.stdout)

    def test_cli_executes_approved_direct_command(self):
        # A test-only mapping permits this harmless native Python fixture.
        executable = Path(sys.executable)
        self.daemon.policy['command_map'][executable.name] = 'linux_administration.file_read'
        script = Path(self.directory.name) / 'native_fixture.py'
        script.write_text("print('DIRECT_EXECUTION_OK')\n", encoding='utf-8')
        command = shlex.join([executable.as_posix(), script.as_posix()])
        result = subprocess.run(
            [sys.executable, str(ROOT / 'heimdall.py'), '--tcp',
             f'127.0.0.1:{self.server.server_address[1]}', '--cmd', command,
             '--execute-on-windows', '--ascii', '--no-color'],
            capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('DIRECT_EXECUTION_OK', result.stdout)
        self.assertIn('exit 0', result.stdout)

    def test_llm_http_observation_loop(self):
        payloads = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payloads.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                plan = ({'action': 'execute', 'command': 'ls -la', 'reasoning': 'List files'}
                        if len(payloads) == 1 else {'action': 'done', 'summary': 'Listed files'})
                body = json.dumps({'choices': [{'message': {'content': json.dumps(plan)}}]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        llm = c.LLMClient(f'http://127.0.0.1:{server.server_port}/v1/chat/completions', 'test-model', 5)
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                    patch.object(c, 'run_command') as run:
                run.return_value = type('R', (), {'rc': 1, 'stdout': 'x' * 3000,
                                                  'stderr': 'test failure',
                                                  'sandboxed': False,
                                                  'duration_ms': 1})()
                self.assertEqual(c.cmd_agent(c.Palette(False), self.client, llm, 'list files', False, 3, True, 7), 0)
                run.assert_called_once_with('ls -la', 'direct', None, timeout=7, cwd=os.getcwd())
            observation = payloads[1]['messages'][-1]['content']
            self.assertIn('exit=1', observation)
            self.assertIn('test failure', observation)
            self.assertNotIn('x' * 2001, observation)
            self.assertEqual(payloads[0]['model'], 'test-model')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
