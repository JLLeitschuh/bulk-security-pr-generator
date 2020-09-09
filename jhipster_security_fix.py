import pathlib
from dataclasses import dataclass

import aiofiles
from requests_threads import AsyncSession

from vulnerability_fix_engine import VulnerabilityFixModule


@dataclass
class JHipsterVulnerabilityFixModule(VulnerabilityFixModule):
    branch_name: str = 'fix/JLL/jhipster_insecure_rng_vulnerability'
    clone_repos_location: str = 'cloned_repos'
    data_base_dir = 'insecure_jhipster_rng_data'
    save_point_location: str = 'save_points'
    pr_message_file_absolute_path: str = f'{str(pathlib.Path().absolute())}/PR_MESSAGE.md'
    post_url = 'https://us-central1-glassy-archway-286320.cloudfunctions.net/cwe338'
    session = AsyncSession(n=100)

    def do_fix_vulnerable_file(self, project_name: str, file: str, expected_fix_count: int) -> int:
        async with aiofiles.open(file, newline='') as vulnerableFile:
            contents: str = await vulnerableFile.read()
        # noinspection PyUnresolvedReferences
        new_contents = await self.session.post(
            self.post_url,
            contents
        )
        if new_contents == contents:
            return 0

        async with aiofiles.open(file, 'w', newline='') as vulnerableFile:
            await vulnerableFile.write(new_contents)

        return expected_fix_count
