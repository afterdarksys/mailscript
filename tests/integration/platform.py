#!/usr/bin/env python3
"""Exercise MailScript against an isolated go-emailservice-ads container.
Never uses deployment credentials or sends external mail.
"""
import argparse
import imaplib
import json
import pathlib
import signal
import smtplib
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
import urllib.request
import urllib.error


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_smtp(number, process=None):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process and process.poll() is not None:
            raise RuntimeError('MailScript exited during startup')
        try:
            with smtplib.SMTP('127.0.0.1', number, timeout=10):
                return
        except (OSError, smtplib.SMTPException):
            time.sleep(.5)
    raise RuntimeError('SMTP startup timed out')


def run(binary, image):
    name = 'mailscript-platform-' + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix='mailscript-platform-') as directory:
        root = pathlib.Path(directory)
        cert, key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        smtp, imap, proxy_port, grpc, api = [port() for _ in range(5)]
        tls_files = {'cert': '/test/cert.pem', 'key': '/test/key.pem'}
        config = {
            'server': {'addr': '0.0.0.0:2525', 'domain': 'mail.test', 'local_domains': ['mail.test'], 'tls': tls_files, 'spf': {'enabled': False}, 'dmarc': {'enabled': False}, 'dane': {'enabled': False}},
            'imap': {'addr': '0.0.0.0:1143', 'tls_mode': 'starttls', 'tls': tls_files},
            'api': {'rest_addr': '0.0.0.0:8080', 'tls': tls_files, 'api_keys': [{'name': 'test', 'key': 'isolated-api-token', 'permissions': ['quarantine:read', 'quarantine:write']}]},
            'platform': {'data_dir': '/data', 'policy_path': '/test/policies.yaml', 'listeners': [{'addr': '0.0.0.0:2525', 'role': 'perimeter', 'tls': tls_files}]},
            'auth': {'default_users': [{'username': 'probe@mail.test', 'email': 'probe@mail.test', 'password': 'isolated-test-password'}]},
            'content_filter': {'enabled': True, 'trusted_proxy_networks': ['127.0.0.1/32', '172.16.0.0/12', '192.168.0.0/16'], 'quarantine_header': 'X-MailScript-Quarantine', 'quarantine_folder': 'Junk'},
            'logging': {'level': 'warn', 'format': 'json'},
        }
        (root/'config.json').write_text(json.dumps(config))
        (root/'policies.yaml').write_text('policies: []\n')
        policy = root/'filter.star'
        policy.write_text('def evaluate():\n    if get_header("Subject") == "quarantine":\n        quarantine()\n        return\n    accept()\n')
        proxy = None
        try:
            subprocess.run(['docker', 'run', '--detach', '--rm', '--name', name, '--user', '0:0', '-p', f'127.0.0.1:{smtp}:2525', '-p', f'127.0.0.1:{imap}:1143', '-p', f'127.0.0.1:{api}:8080', '-v', f'{root}:/test:ro', image, '--config', '/test/config.json'], check=True, stdout=subprocess.DEVNULL)
            wait_smtp(smtp)
            with (root/'proxy.log').open('w+') as log:
                proxy = subprocess.Popen([binary, 'proxy', '--script', str(policy), '--port', str(proxy_port), '--grpc-port', str(grpc), '--upstream', f'127.0.0.1:{smtp}', '--upstream-tls', 'starttls', '--upstream-ca', str(cert), '--forward-quarantine'], stdout=log, stderr=log)
                wait_smtp(proxy_port, proxy)
                with smtplib.SMTP('127.0.0.1', proxy_port, timeout=10) as client:
                    client.ehlo()
                    assert client.mail('')[0] == 250
                    assert client.rcpt('outsider@external.test')[0] >= 500
                    assert client.rcpt('missing@mail.test')[0] == 550
                    assert client.rcpt('probe@mail.test')[0] == 250
                    code, text = client.data(b'From: probe@mail.test\r\nTo: probe@mail.test\r\nSubject: ordinary\r\nX-MailScript-Quarantine: forged\r\n\r\n.first\r\n..second\r\n')
                    assert code == 250, (code, text)
                    assert not client.sendmail('', ['probe@mail.test'], b'From: probe@mail.test\r\nSubject: quarantine\r\n\r\nheld\r\n')
                tls = ssl.create_default_context(cafile=str(cert))
                for folder, subject in [('INBOX', 'ordinary')]:
                    deadline = time.monotonic()+20
                    while time.monotonic() < deadline:
                        with imaplib.IMAP4('127.0.0.1', imap, timeout=5) as client:
                            client.starttls(ssl_context=tls)
                            client.login('probe@mail.test', 'isolated-test-password')
                            selected = client.select(folder)
                            if selected[0] == 'OK':
                                status, found = client.search(None, 'SUBJECT', subject)
                                if status == 'OK' and found[0]:
                                    _, records = client.fetch(found[0].split()[0], '(RFC822)')
                                    message = next(row[1] for row in records if isinstance(row, tuple))
                                    assert b'X-MailScript-Quarantine:' not in message
                                    if folder == 'INBOX':
                                        assert b'\r\n.first\r\n..second\r\n' in message
                                    break
                        time.sleep(.1)
                    else:
                        raise AssertionError(f'{subject} missing from {folder}')
                request = urllib.request.Request(f'https://localhost:{api}/api/v1/quarantine', headers={'Authorization': 'Bearer isolated-api-token'})
                with urllib.request.urlopen(request, context=tls, timeout=5) as response:
                    held = json.load(response)
                assert len(held) == 1 and held[0]['to'] == ['probe@mail.test'], held
                # The platform requires a scanner before releasing held mail.
                request = urllib.request.Request(f'https://localhost:{api}/api/v1/quarantine/{held[0]["id"]}/release', data=b'', headers={'Authorization': 'Bearer isolated-api-token'}, method='POST')
                try:
                    urllib.request.urlopen(request, context=tls, timeout=5)
                except urllib.error.HTTPError as error:
                    assert error.code == 409 and b'configured scanner' in error.read()
                else:
                    raise AssertionError('quarantine release bypassed scanner requirement')
                # Reload changes new evaluations; invalid reload retains it.
                policy.write_text('def evaluate():\n    if get_header("Subject") == "reload":\n        defer()\n        return\n    accept()\n')
                proxy.send_signal(signal.SIGHUP)
                deadline = time.monotonic()+5
                while time.monotonic()<deadline:
                    if 'Policy reloaded' in (root/'proxy.log').read_text(): break
                    time.sleep(.05)
                else: raise AssertionError('reload was not reported')
                policy.write_text('invalid(:')
                proxy.send_signal(signal.SIGHUP)
                deadline = time.monotonic()+5
                while time.monotonic()<deadline:
                    if 'Policy reload rejected' in (root/'proxy.log').read_text(): break
                    time.sleep(.05)
                else: raise AssertionError('invalid reload was not rejected')
                with smtplib.SMTP('127.0.0.1', proxy_port, timeout=10) as client:
                    client.ehlo(); assert client.mail('')[0] == 250
                    assert client.rcpt('probe@mail.test')[0] == 250
                    assert client.data('From: probe@mail.test\r\nSubject: reload\r\n\r\nbody\r\n')[0] == 451
                # Existing transaction must survive listener shutdown and finish.
                with smtplib.SMTP('127.0.0.1', proxy_port, timeout=10) as client:
                    client.ehlo(); assert client.mail('')[0] == 250
                    assert client.rcpt('probe@mail.test')[0] == 250
                    proxy.send_signal(signal.SIGTERM)
                    assert client.data('From: probe@mail.test\r\nSubject: draining\r\n\r\nbody\r\n')[0] == 250
                assert proxy.wait(timeout=10) == 0
                print('PASS: backend STARTTLS, null sender, recipient rejection, relay denial, INBOX delivery, quarantine hold/release gate, dot transparency, atomic reload, graceful drain')
        except Exception:
            subprocess.run(['docker', 'logs', name], check=False)
            if (root/'proxy.log').exists():
                print((root/'proxy.log').read_text())
            raise
        finally:
            if proxy and proxy.poll() is None:
                proxy.terminate()
                try: proxy.wait(timeout=5)
                except subprocess.TimeoutExpired: proxy.kill(); proxy.wait()
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mailscript', required=True)
    parser.add_argument('--image', default='mailhub:qualification-2.7')
    args = parser.parse_args()
    run(str(pathlib.Path(args.mailscript).resolve()), args.image)
