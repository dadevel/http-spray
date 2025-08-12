from requests import Response
from httpspray.module.oauth import OAuthSpray


class MSAuthSpray(OAuthSpray):
    def filter(self, response: Response) -> dict[str, str|None]:
        # see https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes#aadsts-error-codes
        error_table = {
            'AADSTS50034': ('invalid', 'account does not exist'),
            'AADSTS50053': ('locked', 'account locked'),
            'AADSTS50055': ('valid', 'password expired'),
            'AADSTS50056': ('exists', 'account does not have a password'),
            'AADSTS50057': ('valid', 'account disabled'),
            'AADSTS50059': ('invalid', 'tenant does not exist'),
            'AADSTS50076': ('valid', 'Microsoft MFA required'),
            'AADSTS50079': ('valid', 'Microsoft MFA can be onboarded'),
            'AADSTS50126': ('exists', 'invalid password'),
            'AADSTS50128': ('invalid', 'tenant does not exist'),
            'AADSTS50131': ('valid', 'blocked by conditional access'),
            'AADSTS50158': ('valid', '3rd-party MFA requried'),
            'AADSTS53003': ('valid', 'blocked by conditional access'),
            'AADSTS80014': ('exists', 'pass-through authentication timeout exceeded'),
            'AADSTS90072': ('valid', 'credential not for this tenant'),
            'AADSTS500011': ('valid', 'invalid resource'),
            'AADSTS530031': ('valid', 'blocked by access policy'),
            'AADSTS7000112': ('valid', 'client disabled'),
        }
        if response.status_code == 200:
            data = response.json()
            return dict(status='valid', access_token=data.get('access_token'), refresh_token=data.get('refresh_token'), scope=data.get('scope'))
        elif response.status_code == 400:
            data = response.json()
            message = data.get('error_description')
            if not message:
                return dict(status='error', message=f'response has no error description: {data!r}')
            words = message.split(':', maxsplit=1)
            if len(words) != 2:
                return dict(status='error', message=f'response error description has unexpected format: {message!r}')
            if not words[0].startswith('AADSTS'):
                return dict(status='error', message=f'response error code has unexpected format: {words[0]!r}')
            if words[0] not in error_table:
                return dict(status='unknown', message=f'response error code is unknown: {words[0]!r}')
            result = error_table[words[0]]
            return dict(status=result[0], message=result[1])
        else:
            return dict(status='unknown')
