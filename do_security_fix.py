#!/usr/bin/python3

import asyncio
import aiofiles
import os
import json
import re
import logging
import pathlib
import shutil
import time
import yaml
from collections import Counter
from dataclasses import dataclass
from github import Github
from typing import Generator, List, Dict

branch_name = 'fix/JLL/use_https_to_resolve_dependencies_2'
clone_repos_location = 'cloned_repos'
pr_message_file_absolute_path = f'{str(pathlib.Path().absolute())}/PR_MESSAGE.md'

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

with open(f'{os.path.expanduser("~")}/.config/hub') as hub_file:
    hub_config = yaml.safe_load(hub_file)

git_hub = Github(login_or_token=hub_config['github.com'][0]['oauth_token'])


async def subprocess_run(args: List[str], cwd: str):
    cmd = ' '.join(args)
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )

    stdout, stderr = await proc.communicate()

    print(f'[{cmd!r} exited with {proc.returncode}]')
    if stdout:
        print(f'[stdout]\n{stdout.decode()}')

    if proc.returncode != 0:
        if stderr:
            raise RuntimeError(f'[stderr]\n{stderr.decode()}')
    else:
        if stderr:
            print(f'[stderr]\n{stderr.decode()}')

    # subprocess.run(args, cwd=cwd, capture_output=True, check=True)


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

    async def do_clone(self):
        await subprocess_run(['hub', 'clone', self.project_name, '--depth', '1'], cwd=clone_repos_location)

    async def do_run_in(self, args: List[str]):
        await subprocess_run(args, cwd=self.project_file_name())

    async def do_fix_vulnerable_file(self, file: str, expected_fix_count: int) -> int:
        """
        Fixes the vulnerabilities in the file passed.

        :param file: The file to fix the vulnerabilities in.
        :param expected_fix_count: The expected number of vulnerabilities to be fixed.
        :return: The actual number of vulnerabilities fixed.
        """
        file_being_fixed: str = self.project_file_name() + file
        async with aiofiles.open(file_being_fixed) as vulnerableFile:
            contents: str = await vulnerableFile.read()

        new_contents, count = p_fix_regex.subn(replacement, contents)
        if count != expected_fix_count:
            logging.warning('Fix did match expected fix count: (expected: %d, actual: %d)', expected_fix_count, count)

        async with aiofiles.open(file_being_fixed, 'w') as vulnerableFile:
            await vulnerableFile.write(new_contents)
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

    async def do_fix_vulnerabilities(self) -> VulnerabilityFixReport:
        project_vulnerabilities_fixed = 0
        project_files_fixed = 0
        submodules = self.submodule_files()
        for file in self.files:
            skip = next((True for submodule in submodules if file.startswith(submodule)), False)
            if not skip:
                project_vulnerabilities_fixed += await self.do_fix_vulnerable_file(file, self.files[file])
                project_files_fixed += 1
        return VulnerabilityFixReport(project_files_fixed, project_vulnerabilities_fixed)

    async def do_create_branch(self):
        await self.do_run_in(['git', 'checkout', '-b', branch_name])

    async def do_stage_changes(self):
        await self.do_run_in(['git', 'add', '.'])

    async def do_commit_changes(self):
        # TODO: Fix this commit message
        await self.do_run_in(['git', 'commit', '-m', 'TEST MESSAGE'])

    async def do_do_fork_repository(self):
        assert False, 'Don\'t fork yet!'
        await self.do_run_in(['hub', 'fork', '--remote-name', 'origin'])

    async def do_push_changes(self):
        await self.do_run_in(['git', 'push', 'origin', branch_name])

    async def do_create_pull_request(self):
        await self.do_run_in(['hub', 'pull-request', '-p', '--file', pr_message_file_absolute_path])


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


async def process_vulnerable_project(project: VulnerableProjectFiles) -> VulnerabilityFixReport:
    project.print()
    await project.do_clone()
    project_report: VulnerabilityFixReport = await project.do_fix_vulnerabilities()
    await project.do_create_branch()
    await project.do_stage_changes()
    # if project.project_name.lower().startswith('jlleitschuh'):
    #     ## TODO: Fix the commit message here!
    #     await project.do_commit_changes()
    #     await project.do_push_changes()
    #     await project.do_create_pull_request()
    return project_report


def is_archived_git_hub_repository(project: VulnerableProjectFiles) -> bool:
    return git_hub.get_repo(project.project_name).archived


async def do_run_everything():
    vulnerable_projects: List[VulnerableProjectFiles] = []
    for json_file in list_all_json_files():
        vulnerable = read_repository_and_file_names(json_file)
        vulnerable.print()
        if 'jlleitschuh' in vulnerable.project_name.lower():
            vulnerable_projects.append(vulnerable)

        if vulnerable.project_name.startswith('jenkinsci'):
            vulnerable_projects.append(vulnerable)

    print()
    print('Processing Projects:')
    projects_fixed = 0
    files_fixed = 0
    vulnerabilities_fixed = 0
    waiting_reports = []
    for vulnerable_project in vulnerable_projects:
        if is_archived_git_hub_repository(vulnerable_project):
            logging.info(f'Skipping project {vulnerable_project.project_name} since it is archived')
            continue
        waiting_reports.append(process_vulnerable_project(vulnerable_project))

    all_reports = await asyncio.gather(*waiting_reports)
    for report in all_reports:
        if report.vulnerabilities_fixed > 0:
            projects_fixed += 1
            files_fixed += report.files_fixed
            vulnerabilities_fixed += report.vulnerabilities_fixed

    print('Done!')
    print(f'Fixed {vulnerabilities_fixed} vulnerabilities in {files_fixed} files across {projects_fixed} projects!')


start = time.monotonic()
asyncio.run(do_run_everything())
end = time.monotonic()
duration_seconds = end - start
print(f'Execution took {duration_seconds} seconds')
