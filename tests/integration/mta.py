#!/usr/bin/env python3
"""Disposable real-MTA tests. Backend images are built from mta/Dockerfile."""
import argparse
import pathlib
import smtplib
import subprocess
import tempfile
import time
import uuid
from platform import port, wait_smtp


def run(binary, mta):
    name = 'mailscript-' + mta + '-' + uuid.uuid4().hex[:8]
    backend, proxy_port, grpc = [port() for _ in range(3)]
    process = None
    with tempfile.TemporaryDirectory(prefix='mailscript-mta-') as directory:
        root = pathlib.Path(directory)
        policy = root/'filter.star'
        policy.write_text('def evaluate():\n    add_header("X-MailScript-Test", "passed")\n    accept()\n')
        try:
            subprocess.run(['docker', 'run', '--detach', '--rm', '--name', name, '--hostname', 'mail.test', '-p', f'127.0.0.1:{backend}:25', f'mailscript-mta:{mta}'], check=True, stdout=subprocess.DEVNULL)
            wait_smtp(backend)
            with (root/'proxy.log').open('w+') as log:
                process = subprocess.Popen([binary, 'proxy', '--script', str(policy), '--port', str(proxy_port), '--grpc-port', str(grpc), '--upstream', f'127.0.0.1:{backend}'], stdout=log, stderr=log)
                wait_smtp(proxy_port, process)
                with smtplib.SMTP('127.0.0.1', proxy_port, timeout=10) as client:
                    client.ehlo(); assert client.mail('')[0] == 250
                    assert client.rcpt('outside@external.test')[0] >= 500
                    assert client.rcpt('probe@mail.test')[0] == 250
                    code, reason = client.data(b'From: probe@mail.test\r\nTo: probe@mail.test\r\nSubject: mailscript-integration\r\n\r\n.first\r\n..second\r\n')
                    assert code == 250, (code, reason)
                deadline = time.monotonic()+20
                while time.monotonic() < deadline:
                    result = subprocess.run(['docker', 'exec', name, 'sh', '-c', 'cat /var/mail/probe /home/probe/Maildir/new/* 2>/dev/null'], capture_output=True)
                    message = result.stdout.replace(b'\r\n', b'\n')
                    if b'X-MailScript-Test: passed' in message and b'\n.first\n..second\n' in message:
                        break
                    time.sleep(.2)
                else:
                    raise AssertionError('filtered message not found in local mailbox')
                print(f'PASS {mta}: relay denial, null sender, filtered delivery, dot transparency')
        except Exception:
            subprocess.run(['docker', 'logs', name], check=False)
            subprocess.run(['docker', 'exec', name, 'sh', '-c', 'find /home/probe /var/qmail/queue -type f 2>/dev/null | head -25'], check=False)
            if (root/'proxy.log').exists(): print((root/'proxy.log').read_text())
            raise
        finally:
            if process:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mailscript', required=True)
    parser.add_argument('--mta', required=True, choices=['postfix', 'exim', 'sendmail', 'qmail'])
    args = parser.parse_args()
    run(str(pathlib.Path(args.mailscript).resolve()), args.mta)
