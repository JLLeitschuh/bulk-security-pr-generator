import logging
import pathlib
import re
import textwrap
from dataclasses import dataclass

import aiofiles

from vulnerability_fix_engine import VulnerabilityFixModule


@dataclass
class PomVulnerabilityFixModule(VulnerabilityFixModule):
    branch_name: str = 'fix/JLL/use_https_to_resolve_dependencies'
    clone_repos_location: str = 'cloned_repos'
    data_base_dir = 'insecure_pom_data'
    save_point_location: str = 'save_points'
    pr_message_file_absolute_path: str = f'{str(pathlib.Path().absolute())}/PR_MESSAGE.md'
    commit_message: str = textwrap.dedent('''\
        Use HTTPS instead of HTTP to resolve dependencies
        
        This fixes a security vulnerability in this project where the `pom.xml`
        files were configuring Maven to resolve dependencies over HTTP instead of
        HTTPS.
        
        Signed-off-by: Jonathan Leitschuh <Jonathan.Leitschuh@gmail.com>
        ''')

    p_fix_regex = \
        re.compile(
            r'(?:(?<=<repository>)|(?<=<pluginRepository>)|(?<=<snapshotRepository>))((?:(?!repository>).)*)(<url>\s*)http://(\S*)(\s*</url>)',
            re.IGNORECASE + re.MULTILINE + re.DOTALL
        )
    replacement = r'\1\2https://\3\4'

    async def do_fix_vulnerable_file(self, project_name: str, file: str, expected_fix_count: int) -> int:
        async with aiofiles.open(file, newline='') as vulnerableFile:
            contents: str = await vulnerableFile.read()

        new_contents, count = self.p_fix_regex.subn(self.replacement, contents)
        if count != expected_fix_count:
            logging.warning(
                'Fix for `%s` did match expected fix count: (expected: %d, actual: %d)',
                project_name,
                expected_fix_count,
                count
            )

        async with aiofiles.open(file, 'w', newline='') as vulnerableFile:
            await vulnerableFile.write(new_contents)
        return count
