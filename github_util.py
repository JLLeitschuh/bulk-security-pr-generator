import os

import yaml
from github import Github


def load_github() -> Github:
    with open(f'{os.path.expanduser("~")}/.config/hub') as hub_file:
        hub_config = yaml.safe_load(hub_file)
        return Github(login_or_token=hub_config['github.com'][0]['oauth_token'])


def print_current_rate_limit():
    rate_limit = load_github().get_rate_limit().core
    print(f'Current Rate Limit: {rate_limit}, reset time: {rate_limit.reset}')
