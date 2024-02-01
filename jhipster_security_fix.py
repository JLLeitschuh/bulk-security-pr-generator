import pathlib
import textwrap
from dataclasses import dataclass
from typing import Optional

import aiofiles
import httpx

from vulnerability_fix_engine import VulnerabilityFixModule


@dataclass
class JHipsterVulnerabilityFixModule(VulnerabilityFixModule):
    branch_name: str = 'fix/JLL/jhipster_insecure_rng_vulnerability'
    clone_repos_location: str = 'cloned_repos'
    data_base_dir: str = 'jhipster_rng_vulnerability/data'
    save_point_location: str = 'jhipster_rng_vulnerability/save_points'
    pr_message_file_absolute_path: str = f'{str(pathlib.Path().absolute())}/jhipster_rng_vulnerability/PR_MESSAGE.md'
    commit_message: str = textwrap.dedent('''\
        CVE-2019-16303 - JHipster Vulnerability Fix - Use CSPRNG in RandomUtil
        
        This fixes a security vulnerability in this project where the `RandomUtil.java`
        file(s) were using an insecure Pseudo Random Number Generator (PRNG) instead of
        a Cryptographically Secure Pseudo Random Number Generator (CSPRNG) for 
        security sensitive data.
        
        Signed-off-by: Jonathan Leitschuh <Jonathan.Leitschuh@gmail.com>
        ''')
    post_url = 'https://us-central1-glassy-archway-286320.cloudfunctions.net/cwe338'
    timeout = httpx.Timeout(60.0, connect=60.0)
    ignored_project_names = [
        'jhipsterSampleApplication',
        'jhipster-sample-application',
        'jhipster',
        'jhipsterSampleApplication2',
        'jhipster-demo',
        'jhipster-sample'
    ]

    async def do_fix_file_contents(self, file_contents: str, retry_count: int = 0) -> str:
        retry_max: int = 5

        async def do_retry(exception: Optional[Exception]) -> str:
            if retry_count > retry_max:
                exception_msg = f'Failed to fix file contents after {retry_count} tries'
                if exception:
                    raise Exception(exception_msg) from exception
                else:
                    raise Exception(exception_msg)
            else:
                return await self.do_fix_file_contents(file_contents, retry_count + 1)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=self.post_url,
                    data=file_contents,
                    timeout=self.timeout
                )
            if response.status_code == 200:
                return response.text
            else:
                return await do_retry(None)
        except httpx.TimeoutException as e:
            return await do_retry(e)
        except httpx.NetworkError as e:
            return await do_retry(e)

    async def do_fix_vulnerable_file(self, project_name: str, file: str, expected_fix_count: int) -> int:
        async with aiofiles.open(file, newline='') as vulnerableFile:
            contents: str = await vulnerableFile.read()

        new_contents = await self.do_fix_file_contents(contents)
        if new_contents == contents:
            return 0

        async with aiofiles.open(file, 'w', newline='') as vulnerableFile:
            await vulnerableFile.write(new_contents)

        return expected_fix_count

    def should_accept_project(self, project_name: str) -> bool:
        for ignored_name in self.ignored_project_names:
            if ignored_name in project_name:
                return False
        return True
