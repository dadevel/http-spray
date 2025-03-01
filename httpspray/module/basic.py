from requests import Response
from requests.auth import HTTPBasicAuth

from httpspray.module.base import BaseSpray


class BasicSpray(BaseSpray):
    def check(self) -> Response|None:
        response = self.session.get(self.target)
        if response.status_code == 401 and 'basic' in response.headers.get('WWW-Authenticate', '').lower():
            return None
        return response

    def login(self, username: str, password: str) -> Response:
        return self.session.post(
            self.target,
            auth=HTTPBasicAuth(username, password),
            headers={'User-Agent': next(self.user_agents)},
        )

    def filter(self, response: Response) -> dict[str, str|None]:
        if response.status_code != 401:
            return dict(status='valid')
        else:
            return dict(status='invalid')

