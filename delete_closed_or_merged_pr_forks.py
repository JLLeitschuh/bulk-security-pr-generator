from typing import Generator
import json
import os

from github import UnknownObjectException
from github.PullRequest import PullRequest

import github_util

github = github_util.load_github()


def list_all_json_files() -> Generator[str, None, None]:
    base_dir = 'pom_vulnerability/save_points'
    directory = os.fsencode(base_dir)
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        if filename.startswith('g__') and filename.endswith('.json'):
            yield base_dir + '/' + filename


def read_results_data(json_file_name: str):
    with open(json_file_name) as jsonFile:
        data = json.load(jsonFile)
    return data


repo_removed = 0
repo_archived = 0
not_found = 0
merged_prs = 0
closed_prs = 0
open_prs = 0

project_name_to_fork = {}

for file in list_all_json_files():
    data = read_results_data(file)
    project_name: str = data['project_name']
    print(f'loading project: {project_name}')
    if (pull_url := data['pull_request']) == '':
        continue


    def add_entry_to_remove():
        if not project_name.lower().startswith('jlleitschuh'):
            fork_name = project_name.split('/')[-1]
        project_name_to_fork[project_name] = f'jlleitschuh/{fork_name}'


    try:
        repository = github.get_repo(project_name)
    except UnknownObjectException as e:
        repo_removed += 1
        add_entry_to_remove()
        continue
    if repository.archived:
        repo_archived += 1
    pull_number = int(str(pull_url).split('/')[-1])
    try:
        pull_request: PullRequest = repository.get_pull(pull_number)
    except UnknownObjectException as e:
        not_found += 1
        add_entry_to_remove()
        continue
    if pull_request.merged:
        merged_prs += 1
        add_entry_to_remove()
    elif pull_request.state == 'closed':
        closed_prs += 1
        add_entry_to_remove()
    elif pull_request.state == 'open':
        open_prs += 1
        # Don't add a removal entry, in this state, the fork should not be deleted

print('Stats:')
print(f'\tRepo (Removed {repo_removed}, Archived {repo_archived})')
print(f'\tPR (Open {open_prs}, Not Found {not_found}, Merged {merged_prs}, Closed {closed_prs})')

# deleted = 0
# for project in project_name_to_fork:
#     my_project_name = project_name_to_fork[project]
#     try:
#         my_repo = github.get_repo(my_project_name)
#     except UnknownObjectException as e:
#         continue
#     print(f'Deleting {my_project_name}')
#     my_repo.delete()
#     deleted += 1
# 
# print(f'Forks Deleted {deleted}')
