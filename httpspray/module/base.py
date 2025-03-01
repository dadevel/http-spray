from argparse import Namespace
import random
import time
import urllib.parse

from requests import Response, Session


class BaseSpray:
    def __init__(self, opts: Namespace) -> None:
        self.target = urllib.parse.urlunparse(opts.target)
        self.session = Session()
        self.session.verify = False
        if opts.proxy:
            self.session.proxies.update(http=opts.proxy, https=opts.proxy)
        # set raw url path as internal header, also see 'make_request()'
        self.session.headers['X-HTTPSpray-Path'] = opts.target.path
        self.delay = opts.delay
        self.jitter = opts.jitter
        self.user_agents = opts.user_agents

    def check(self) -> Response|None:
        return None

    def login(self, username: str, password: str) -> Response:
        raise NotImplementedError()

    def filter(self, response: Response) -> dict[str, str|None]:
        if response.status_code == 200:
            return dict(status='valid')
        elif response.status_code == 401:
            return dict(status='invalid')
        else:
            return dict(status='unknown')

    def spray(self, credential: tuple[str, str]) -> tuple[Response, dict[str, str|None]]:
        username, password = credential
        response = self.login(username, password)
        result = self.filter(response)
        time.sleep(random.randint(self.delay - self.jitter, self.delay + self.jitter))
        return response, dict(user=username, password=password, **result)
