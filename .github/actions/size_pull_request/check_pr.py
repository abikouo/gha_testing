#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) 2024 Aubin Bikouo <@abikouo>
# GNU General Public License v3.0+
#     (see https://www.gnu.org/licenses/gpl-3.0.txt)

from argparse import ArgumentParser
import subprocess
import re
import requests
import os
from collections import defaultdict


# const labels = {
#   XS: {
#     name: 'size/XS',
#     lines: 0,
#     color: '3CBF00',
#   },
#   S: {
#     name: 'size/S',
#     lines: 10,
#     color: '5D9801',
#   },
#   M: {
#     name: 'size/M',
#     lines: 30,
#     color: '7F7203',
#   },
#   L: {
#     name: 'size/L',
#     lines: 100,
#     color: 'A14C05',
#   },
#   XL: {
#     name: 'size/XL',
#     lines: 500,
#     color: 'C32607',
#   },
#   XXL: {
#     name: 'size/XXL',
#     lines: 1000,
#     color: 'E50009',
#   },
# };


def WriteComment(repository: str, pr_number: int, comment: str) -> None:
    url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"
    result = requests.post(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": "Bearer %s" % os.environ.get("GITHUB_TOKEN"),
        },
        json={"body": comment},
    )
    # Checking for Http status code '201' (created)
    if result.status_code != 201:
        raise RuntimeError(f"Post to URL {url} returned status code = {result.status_code}")


def RunDiff(path: str, repository: str, pr_number: int, base_ref: str) -> None:
    # List files
    git_diff_status = f"git --no-pager diff --cached origin/{base_ref} --name-status"
    proc = subprocess.Popen(git_diff_status, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, cwd=path)
    stdout, _ = proc.communicate()
    name_status = defaultdict(list)
    for i in stdout.decode().split("\n"):
        m = re.match('^(A|M|D)[\t](.+)', i)
        if m:
            name_status[m.group(1)].append(m.group(2))

    # Compute insertion/deletion
    insertions, deletions = 0, 0
    for type, files in name_status.items():
        if type == "D":
            continue
        for f in files:
            git_diff_stat = f"git --no-pager diff --cached --stat origin/{base_ref} -- {f}"
            proc = subprocess.Popen(git_diff_stat, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, cwd=path)
            stdout, _ = proc.communicate()
            m = re.search(f"(\d*) deletion[s]?\(\-\)", stdout.decode())
            if m:
                deletions += int(m.group(1))
            m = re.search(f"(\d*) insertion[s]?\(\+\)", stdout.decode())
            if m:
                insertions += int(m.group(1))
    WriteComment(repository, pr_number, f"files = {name_status} - insertions = {insertions} - deletions = {deletions}")


if __name__ == "__main__":
    """Check PR size and push corresponding message and/or add label."""
    parser = ArgumentParser()
    parser.add_argument("--path", required=True, help="Path to the repository.")
    parser.add_argument("--repository", required=True, help="Repository name org/name.")
    parser.add_argument("--pr-number", type=int, required=True, help="The pull request number.")
    parser.add_argument("--base-ref", required=True, help="The pull request base ref.")

    args = parser.parse_args()
    RunDiff(args.path, args.repository, args.pr_number, args.base_ref)
