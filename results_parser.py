import os
import json
from typing import Generator


def list_all_json_files() -> Generator[str, None, None]:
    base_dir = 'save_points'
    directory = os.fsencode(base_dir)
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        if filename.startswith('g__') and filename.endswith('.json'):
            yield base_dir + '/' + filename


def read_results_data(json_file_name: str):
    with open(json_file_name) as jsonFile:
        data = json.load(jsonFile)
    return data


projects_fixed = 0
files_fixed = 0
vulnerabilities_fixed = 0

for file in list_all_json_files():
    data = read_results_data(file)
    if data['project_name'].startswith('JLLeitschuh'):
        continue
    report = data['report']
    if report['vulnerabilities_fixed'] > 0:
        projects_fixed += 1
        files_fixed += report['files_fixed']
        vulnerabilities_fixed += report['vulnerabilities_fixed']
        print(f' - {data["pull_request"]}')

print(f'Report: {vulnerabilities_fixed} vulnerabilities fixed in {files_fixed} files across {projects_fixed} projects!')
