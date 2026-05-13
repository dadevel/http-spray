from requests import Response
from requests_ntlm import HttpNtlmAuth

from httpspray.module.base import BaseSpray


class NTLMSpray(BaseSpray):
    def check(self) -> Response|None:
        response = self.session.get(self.target)
        if response.status_code == 401 and 'ntlm' in response.headers.get('WWW-Authenticate', '').lower():
            return None
        return response

    def login(self, username: str, password: str) -> Response:
        return self.session.post(
            self.target,
            auth=HttpNtlmAuth(username, password),
            headers={'User-Agent': next(self.user_agents)},
        )

    def filter(self, response: Response) -> dict[str, str|None]:
        if response.status_code != 401:
            return dict(status='valid')
        else:
            return dict(status='invalid')
