#!/usr/bin/python3

import os
import json
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from typing import Generator, List, Dict

clone_repos_location = 'cloned_repos'

# Cleanup method to get rid of previous files
shutil.rmtree(clone_repos_location)


def subprocess_run(args: List[str], cwd: str):
    subprocess.run(args, cwd=cwd, capture_output=True, check=True)


@dataclass
class VulnerableProjectFiles:
    project_name: str
    files: Dict[str, int]

    def project_file_name(self) -> str:
        return self.project_name.split('/')[1]

    def print(self):
        print(self.project_name)
        for file in self.files:
            print('\t' + file + ': ' + str(self.files[file]))

    def do_clone(self):
        subprocess_run(['hub', 'clone', self.project_name], cwd=clone_repos_location)

    def run_in(self, args: List[str]):
        subprocess_run(args, cwd=clone_repos_location + '/' + self.project_file_name())


def list_all_json_files() -> Generator[str, None, None]:
    base_dir = 'insecure_pom_data'
    directory = os.fsencode(base_dir)
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        if filename.startswith('g__') and filename.endswith('.json'):
            yield base_dir + '/' + filename


def read_repository_and_file_names(json_file_name: str) -> VulnerableProjectFiles:
    with open(json_file_name) as jsonFile:
        data = json.load(jsonFile)
        project_name: str = data['project']['name']
        files = Counter([obj[0]['file'] for obj in data['data']])
        return VulnerableProjectFiles(project_name, files)


def process_vulnerable_project(project: VulnerableProjectFiles):
    project.print()
    project.do_clone()
    pass


vulnerable_projects: List[VulnerableProjectFiles] = []
for json_file in list_all_json_files():
    vulnerable = read_repository_and_file_names(json_file)
    vulnerable.print()
    if 'jlleitschuh' in vulnerable.project_name.lower():
        vulnerable_projects.append(vulnerable)

print()
print('Processing Projects:')
for vulnerable_project in vulnerable_projects:
    process_vulnerable_project(vulnerable_project)
