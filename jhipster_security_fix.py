import pathlib
import textwrap
from dataclasses import dataclass

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

    async def do_fix_file_contents(self, file_contents: str, retry_count: int = 0) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url=self.post_url,
                data=file_contents,
                timeout=self.timeout
            )
        if response.status_code is 200:
            return response.text
        elif retry_count > 5:
            raise Exception(f'Failed to fix file contents after {retry_count} tries')
        else:
            return await self.do_fix_file_contents(file_contents, retry_count + 1)

    async def do_fix_vulnerable_file(self, project_name: str, file: str, expected_fix_count: int) -> int:
        async with aiofiles.open(file, newline='') as vulnerableFile:
            contents: str = await vulnerableFile.read()

        new_contents = await self.do_fix_file_contents(contents)
        if new_contents == contents:
            return 0

        async with aiofiles.open(file, 'w', newline='') as vulnerableFile:
            await vulnerableFile.write(new_contents)

        return expected_fix_count
