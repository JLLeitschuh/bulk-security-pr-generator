#!/usr/bin/python3

import asyncio
import aiofiles
import os
import json
import re
import logging
import logging.config
import pathlib
import shutil
import time
import textwrap
import yaml
from collections import Counter
from dataclasses import dataclass, asdict
from github import Github
from random import random
from typing import Generator, List, Dict, Optional

logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)

branch_name = 'fix/JLL/use_https_to_resolve_dependencies'
clone_repos_location = 'cloned_repos'
save_point_location = 'save_points'
pr_message_file_absolute_path = f'{str(pathlib.Path().absolute())}/PR_MESSAGE.md'

# Cleanup method to get rid of previous files
if os.path.isdir(clone_repos_location):
    shutil.rmtree(clone_repos_location)
os.mkdir(clone_repos_location)
if not os.path.isdir(save_point_location):
    os.mkdir(save_point_location)

p_fix_regex = \
    re.compile(
        r'(?:(?<=<repository>)|(?<=<pluginRepository>)|(?<=<snapshotRepository>))((?:(?!repository>).)*)(<url>\s*)http://(\S*)(\s*</url>)',
        re.IGNORECASE + re.MULTILINE + re.DOTALL
    )
replacement = r'\1\2https://\3\4'

with open(f'{os.path.expanduser("~")}/.config/hub') as hub_file:
    hub_config = yaml.safe_load(hub_file)

git_hub = Github(login_or_token=hub_config['github.com'][0]['oauth_token'])


def print_current_rate_limit():
    rate_limit = git_hub.get_rate_limit().core
    print(f'Current Rate Limit: {rate_limit}, reset time: {rate_limit.reset}')


print_current_rate_limit()


class ShallowUpdateNotAllowedException(Exception):
    pass


class CouldNotReadFromRemoteRepositoryException(Exception):
    pass


class PullRequestAlreadyExists(Exception):
    pass


async def subprocess_run(args: List[str], cwd: str) -> Optional[str]:
    proc = await asyncio.create_subprocess_exec(
        args[0],
        *args[1:],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )

    stdout, stderr = await proc.communicate()

    print(f'[{args!r} exited with {proc.returncode}]')
    if stdout:
        print(f'[stdout]\n{stdout.decode()}')

    if proc.returncode != 0:
        if stderr:
            msg = stderr.decode()
            error_msg = f'[stderr]\n{msg}'
            if 'timeout' in msg:
                raise TimeoutError(error_msg)
            if 'shallow update not allowed' in msg:
                raise ShallowUpdateNotAllowedException(error_msg)
            if 'Could not read from remote repository' in msg:
                raise CouldNotReadFromRemoteRepositoryException(error_msg)
            if 'A pull request already exists' in msg:
                raise PullRequestAlreadyExists(error_msg)
            raise RuntimeError(error_msg)
    else:
        if stderr:
            print(f'[stderr]\n{stderr.decode()}')

    if stdout:
        return stdout.decode()
    else:
        return None


@dataclass(frozen=True)
class VulnerabilityFixReport:
    files_fixed: int
    vulnerabilities_fixed: int


@dataclass
class VulnerableProjectFiles:
    project_name: str
    files: Dict[str, int]

    def project_file_name(self) -> str:
        return clone_repos_location + '/' + self.project_name.split('/')[1]

    def save_point_file_name(self) -> str:
        project_as_file_name = self.project_name.replace('/', '__')
        return f'{save_point_location}/g__{project_as_file_name}.json'

    def print(self):
        print(self.project_name)
        for file in self.files:
            print('\t', '/' + self.project_file_name() + file + ': ' + str(self.files[file]))

    @staticmethod
    async def do_resilient_hub_call(args: List[str], cwd: str, lock=None) -> Optional[str]:
        """
        Make a call to hub that is resilient to timeout exceptions.

        :return: stdout output if successful
        """

        async def do_call(wait_time) -> Optional[str]:
            try:
                if lock is not None:
                    async with lock:
                        # GitHub documentation says to wait 1 second between writes
                        await asyncio.sleep(1)
                        return await subprocess_run(args, cwd=cwd)
                else:
                    return await subprocess_run(args, cwd=cwd)
            except TimeoutError as e:
                # This serves a double purpose as informational and also a 'sane'
                # way to slow down this script reasonably
                print_current_rate_limit()
                await asyncio.sleep(wait_time)
                if wait_time > 16:
                    raise e
                return await do_call(wait_time * 2 + random())

        return await do_call(1)

    async def do_clone(self):
        # Deal with fskobjects https://stackoverflow.com/a/41029655/3708426
        await self.do_resilient_hub_call(
            [
                'hub',
                'clone',
                self.project_name,
                '--config',
                'transfer.fsckobjects=false',
                '--config',
                'receive.fsckobjects=false',
                '--config',
                'fetch.fsckobjects=false'
            ],
            cwd=clone_repos_location
        )

    async def do_run_in(self, args: List[str]) -> Optional[str]:
        assert args[0] != 'hub', 'This method is unsuitable for calling `hub`. Use `do_run_hub_in` instead!'
        return await subprocess_run(args, cwd=self.project_file_name())

    async def do_run_hub_in(self, args: List[str], lock) -> Optional[str]:
        return await self.do_resilient_hub_call(args=args, cwd=self.project_file_name(), lock=lock)

    async def do_fix_vulnerable_file(self, file: str, expected_fix_count: int) -> int:
        """
        Fixes the vulnerabilities in the file passed.

        :param file: The file to fix the vulnerabilities in.
        :param expected_fix_count: The expected number of vulnerabilities to be fixed.
        :return: The actual number of vulnerabilities fixed.
        """
        file_being_fixed: str = self.project_file_name() + file
        # Sanity check, verify the file still exists, the data may be out of date
        if not os.path.exists(file_being_fixed):
            logging.warning(
                'Fix for `%s` in file `%s` can not be applied as file does not exist!',
                self.project_name,
                file
            )
            return 0

        async with aiofiles.open(file_being_fixed, newline='') as vulnerableFile:
            contents: str = await vulnerableFile.read()

        new_contents, count = p_fix_regex.subn(replacement, contents)
        if count != expected_fix_count:
            logging.warning(
                'Fix for `%s` did match expected fix count: (expected: %d, actual: %d)',
                self.project_name,
                expected_fix_count,
                count
            )

        async with aiofiles.open(file_being_fixed, 'w', newline='') as vulnerableFile:
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
                file_vulnerabilities_fixed = await self.do_fix_vulnerable_file(file, self.files[file])
                if file_vulnerabilities_fixed > 0:
                    project_vulnerabilities_fixed += file_vulnerabilities_fixed
                    project_files_fixed += 1
        return VulnerabilityFixReport(project_files_fixed, project_vulnerabilities_fixed)

    async def do_create_branch(self):
        await self.do_run_in(['git', 'checkout', '-b', branch_name])

    async def do_stage_changes(self):
        await self.do_run_in(['git', 'add', '.'])

    async def do_commit_changes(self):
        msg = '''\
        Use HTTPS instead of HTTP to resolve dependencies
        
        This fixes a security vulnerability in this project where the `pom.xml`
        files were configuring Maven to resolve dependencies over HTTP instead of
        HTTPS.
        
        Signed-off-by: Jonathan Leitschuh <Jonathan.Leitschuh@gmail.com>
        '''
        await self.do_run_in(['git', 'commit', '-m', textwrap.dedent(msg)])

    async def do_do_fork_repository(self, lock):
        await self.do_run_hub_in(['hub', 'fork', '--remote-name', 'origin'], lock)

    async def do_push_changes(self, retry_count: int = 5):
        try:
            await self.do_run_in(['git', 'push', 'origin', branch_name, '--force'])
        except ShallowUpdateNotAllowedException as e:
            # A shallow update isn't allowed against this repo (I must have forked it before)
            await self.do_run_in(['git', 'fetch', '--unshallow'])
            # Now re-run the push
            await self.do_run_in(['git', 'push', 'origin', branch_name, '--force'])
        except CouldNotReadFromRemoteRepositoryException as e:
            logging.warning(f'Could not read from remote repository {5 - retry_count}/5')
            if retry_count <= 0:
                raise e
            else:
                # Forking is an async operation, so we may need to wait a bit for it
                await asyncio.sleep((5 - retry_count) * 2 + random())
                await self.do_push_changes(retry_count - 1)

    async def do_create_pull_request(self, lock) -> str:
        try:
            stdout = await self.do_run_hub_in(['hub', 'pull-request', '-p', '--file', pr_message_file_absolute_path], lock)
            pattern = re.compile(r'(https://.*)')
            match = pattern.search(stdout)
            return match.group(1)
        except PullRequestAlreadyExists as e:
            return 'ALREADY_EXISTS'

    async def do_create_save_point(self, report: VulnerabilityFixReport, pr_url: str):
        json_body = {
            'project_name': self.project_name,
            'files': self.files,
            'pull_request': pr_url,
            'report': asdict(report)
        }
        async with aiofiles.open(self.save_point_file_name(), 'w') as json_file_to_write:
            await json_file_to_write.write(json.dumps(json_body, indent=4))


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


async def process_vulnerable_project(project: VulnerableProjectFiles, lock) -> VulnerabilityFixReport:
    project.print()
    await project.do_clone()
    project_report: VulnerabilityFixReport = await project.do_fix_vulnerabilities()
    pr_url = ''
    # If the LGTM data is out-of-date, there can be cases where no vulnerabilities are fixed
    if project_report.vulnerabilities_fixed != 0:
        await project.do_create_branch()
        await project.do_stage_changes()
        await project.do_commit_changes()

        if not project.project_name.lower().startswith('jlleitschuh'):
            await project.do_do_fork_repository(lock)

        await project.do_push_changes()
        pr_url = await project.do_create_pull_request(lock)
    await project.do_create_save_point(project_report, pr_url)
    return project_report


async def process_vulnerable_project_checked(project: VulnerableProjectFiles, lock) -> VulnerabilityFixReport:
    try:
        return await process_vulnerable_project(project, lock)
    except BaseException as e:
        logging.error(f'Failed while processing project `{project.project_name}`. Exception type: {type(e)}.\n{e!s}')
        raise e


def is_archived_git_hub_repository(project: VulnerableProjectFiles) -> bool:
    return git_hub.get_repo(project.project_name).archived


async def do_run_everything():
    github_hub_lock = asyncio.Lock()
    vulnerable_projects: List[VulnerableProjectFiles] = []
    for json_file in list_all_json_files():
        vulnerable = read_repository_and_file_names(json_file)
        vulnerable.print()
        if vulnerable.project_name == 'apache/servicemix4-bundles' or \
                vulnerable.project_name == 'marcust/struts1' or \
                '/maven' in vulnerable.project_name:
            # TODO: Come back to this black listed project later
            # black listed project
            continue
        # if 'jlleitschuh' in vulnerable.project_name.lower():
        #     vulnerable_projects.append(vulnerable)

        # if vulnerable.project_name.startswith('apache/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        #
        # if vulnerable.project_name.startswith('google/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        #
        # if vulnerable.project_name.startswith('GoogleCloudPlatform/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        #
        # if vulnerable.project_name.startswith('microsoft/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        #
        # if vulnerable.project_name.startswith('jenkinsci/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        #
        # if vulnerable.project_name.startswith('52North/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        #
        # if vulnerable.project_name.startswith('eclipse/'):
        #     vulnerable_projects.append(vulnerable)
        #     continue
        lower_name = vulnerable.project_name.lower()
        if lower_name.startswith('k') or \
                lower_name.startswith('l') or \
                lower_name.startswith('m') or \
                lower_name.startswith('n'):
            vulnerable_projects.append(vulnerable)
            continue

    print()
    print(f'Loading Async Project Executions for {len(vulnerable_projects)} Projects:')
    waiting_reports = []
    for vulnerable_project in vulnerable_projects:
        if is_archived_git_hub_repository(vulnerable_project):
            logging.info(f'Skipping project {vulnerable_project.project_name} since it is archived')
            continue
        if os.path.exists(vulnerable_project.save_point_file_name()):
            logging.info(f'Skipping project {vulnerable_project.project_name} since save point file already exists')
            continue
        print(f'Loading Execution for: {vulnerable_project.project_name}')
        waiting_reports.append(process_vulnerable_project_checked(vulnerable_project, github_hub_lock))

    projects_fixed = 0
    files_fixed = 0
    vulnerabilities_fixed = 0
    print(f'Processing {len(waiting_reports)} Projects:')
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
print_current_rate_limit()
