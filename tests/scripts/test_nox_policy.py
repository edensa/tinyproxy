#!/usr/bin/env python3
"""Run with: python3 tests/scripts/test_nox_policy.py src/tinyproxy"""
import contextlib
import http.server
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = str(pathlib.Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else None
sys.argv[1:] = []


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'nox policy target')

    def log_message(self, *_args):
        pass


class NoxPolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
        cls.target_port = cls.target.server_port
        cls.server_thread = threading.Thread(target=cls.target.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.target.shutdown()
        cls.target.server_close()
        cls.server_thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proxy_port = free_port()

    def launch(self, rules):
        config = pathlib.Path(self.tmp.name) / 'tinyproxy.conf'
        config.write_text(f'Port {self.proxy_port}\nListen 127.0.0.1\n'
                          f'ConnectPort {self.target_port}\nNoxPolicy Yes\n{rules}\n')
        process = subprocess.Popen([BINARY, '-d', '-c', str(config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, process)
        for _ in range(100):
            if process.poll() is not None:
                self.fail(f'tinyproxy exited: {process.stderr.read()!r}')
            try:
                with socket.create_connection(('127.0.0.1', self.proxy_port), timeout=.2):
                    return process
            except OSError:
                time.sleep(.02)
        self.fail('tinyproxy did not become ready')

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.communicate(timeout=3)
        if process.poll() is None:
            process.kill()
            process.communicate()

    def request(self, host, method='GET'):
        authority = f'{host}:{self.target_port}'
        target = authority if method == 'CONNECT' else f'http://{authority}/'
        with socket.create_connection(('127.0.0.1', self.proxy_port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(f'{method} {target} HTTP/1.1\r\nHost: {authority}\r\n'
                         'Connection: close\r\n\r\n'.encode())
            result = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                result += data
                if method == 'CONNECT' and b'\r\n\r\n' in result:
                    break
            if method == 'CONNECT' and b' 200 ' in result.split(b'\r\n', 1)[0]:
                sock.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    result += data
            return result

    def test_default_deny_http_and_connect(self):
        self.launch('')
        for method in ('GET', 'CONNECT'):
            self.assertIn(b' 403 ', self.request('127.0.0.1', method).split(b'\r\n', 1)[0])

    def test_explicit_private_cidr_for_both_methods(self):
        self.launch(f'NoxAllow 127.0.0.0/8 {self.target_port}')
        for method in ('GET', 'CONNECT'):
            self.assertIn(b'nox policy target', self.request('127.0.0.1', method))
            self.assertIn(b'nox policy target', self.request('localhost', method))

    def test_domain_glob_does_not_authorize_localhost_literal(self):
        self.launch(f'NoxAllow *host {self.target_port}')
        for method in ('GET', 'CONNECT'):
            self.assertIn(b' 403 ', self.request('localhost', method).split(b'\r\n', 1)[0])

    def test_wrong_port_denied(self):
        self.launch(f'NoxAllow 127.0.0.0/8 1-2')
        self.assertIn(b' 403 ', self.request('127.0.0.1').split(b'\r\n', 1)[0])

    def test_invalid_rules_and_upstream_fail_start(self):
        for rule in ('NoxAllow *.example.org 0', 'NoxAllow 127.0.0.0/33 443',
                     'NoxAllow localhost 3-2', 'NoxAllow / 443',
                     'NoxAllow 2001:db8::/129 443',
                     'Upstream http 127.0.0.1:12345'):
            with self.subTest(rule=rule):
                config = pathlib.Path(self.tmp.name) / 'bad.conf'
                config.write_text(f'Port {self.proxy_port}\nNoxPolicy Yes\n{rule}\n')
                result = subprocess.run([BINARY, '-d', '-c', str(config)],
                                        capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    if not BINARY:
        raise SystemExit('usage: test_nox_policy.py /path/to/tinyproxy')
    unittest.main()
