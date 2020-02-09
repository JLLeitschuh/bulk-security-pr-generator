#!/usr/bin/python3

import os
import json
import re
import logging
import shutil
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from typing import Generator, List, Dict

clone_repos_location = 'cloned_repos'

# Cleanup method to get rid of previous files
if os.path.isdir(clone_repos_location):
    shutil.rmtree(clone_repos_location)
os.mkdir(clone_repos_location)

p_fix_regex = \
    re.compile(
        r'(?:(?<=<repository>)|(?<=<pluginRepository>)|(?<=<snapshotRepository>))((?:(?!repository>).)*)(<url>\s*)http://(\S*)(\s*</url>)',
        re.IGNORECASE + re.MULTILINE + re.DOTALL
    )
replacement = r'\1\2https://\3\4'


def subprocess_run(args: List[str], cwd: str):
    subprocess.run(args, cwd=cwd, capture_output=True, check=True)


@dataclass
class VulnerabilityFixReport:
    files_fixed: int
    vulnerabilities_fixed: int


@dataclass
class VulnerableProjectFiles:
    project_name: str
    files: Dict[str, int]

    def project_file_name(self) -> str:
        return clone_repos_location + '/' + self.project_name.split('/')[1]

    def print(self):
        print(self.project_name)
        for file in self.files:
            print('\t', '/' + self.project_file_name() + file + ': ' + str(self.files[file]))

    def do_clone(self):
        subprocess_run(['hub', 'clone', self.project_name, '--depth', '1'], cwd=clone_repos_location)

    def do_run_in(self, args: List[str]):
        subprocess_run(args, cwd=self.project_file_name())

    def do_fix_vulnerable_file(self, file: str, expected_fix_count: int) -> int:
        """
        Fixes the vulnerabilities in the file passed.

        :param file: The file to fix the vulnerabilities in.
        :param expected_fix_count: The expected number of vulnerabilities to be fixed.
        :return: The actual number of vulnerabilities fixed.
        """
        file_being_fixed: str = self.project_file_name() + file
        with open(file_being_fixed) as vulnerableFile:
            contents: str = vulnerableFile.read()

        new_contents, count = p_fix_regex.subn(replacement, contents)
        if count != expected_fix_count:
            logging.warning('Fix did match expected fix count: (expected: %d, actual: %d)', expected_fix_count, count)

        with open(file_being_fixed, 'w') as vulnerableFile:
            vulnerableFile.write(new_contents)
        return count

    def submodule_files(self) -> List[str]:
        """
        List all of the git submodule files in this project.

        We're not going to be fixing pom files in Git submodules so this allows us to filter them out.
        """
        files: List[str] = []
        submodule_file_path: str = self.project_file_name() + '/.gitmodules'
        if not os.path.isfile(submodule_file_path):
            return []
        with open(submodule_file_path) as submodule_file:
            for line in submodule_file:
                if 'path' in line:
                    files.append('/' + line.split('= ')[1][0:-1])
        return files

    def do_fix_vulnerabilities(self) -> VulnerabilityFixReport:

        project_vulnerabilities_fixed = 0
        project_files_fixed = 0
        submodules = self.submodule_files()
        for file in self.files:
            skip = next((True for submodule in submodules if file.startswith(submodule)), False)
            if not skip:
                project_vulnerabilities_fixed += self.do_fix_vulnerable_file(file, self.files[file])
                project_files_fixed += 1
        return VulnerabilityFixReport(project_files_fixed, project_vulnerabilities_fixed)


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
    # Counter is a Dict[file name, count] representation
    files = Counter([obj[0]['file'] for obj in data['data']])
    return VulnerableProjectFiles(project_name, files)


def process_vulnerable_project(project: VulnerableProjectFiles) -> VulnerabilityFixReport:
    project.print()
    project.do_clone()
    project_report: VulnerabilityFixReport = project.do_fix_vulnerabilities()
    return project_report


def do_run_everything():
    vulnerable_projects: List[VulnerableProjectFiles] = []
    for json_file in list_all_json_files():
        vulnerable = read_repository_and_file_names(json_file)
        vulnerable.print()
        if 'jlleitschuh' in vulnerable.project_name.lower():
            vulnerable_projects.append(vulnerable)

        if vulnerable.project_name.startswith('jenkins'):
            vulnerable_projects.append(vulnerable)

    print()
    print('Processing Projects:')
    projects_fixed = 0
    files_fixed = 0
    vulnerabilities_fixed = 0
    for vulnerable_project in vulnerable_projects:
        report = process_vulnerable_project(vulnerable_project)
        if report.vulnerabilities_fixed > 0:
            projects_fixed += 1
            files_fixed += report.files_fixed
            vulnerabilities_fixed += report.vulnerabilities_fixed

    print('Done!')
    print(f'Fixed {vulnerabilities_fixed} vulnerabilities in {files_fixed} files across {projects_fixed} projects!')


start = time.monotonic()
do_run_everything()
end = time.monotonic()
duration_seconds = end - start
print(f'Execution took {duration_seconds} seconds')
