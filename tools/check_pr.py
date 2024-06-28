# -*- coding: utf-8 -*-
# (c) 2024 Aubin Bikouo <@abikouo>
# GNU General Public License v3.0+
#     (see https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import re
import subprocess
from argparse import ArgumentParser
from collections import defaultdict
from typing import Dict
import tempfile

import requests

DEFAULT_PR_SIZE_THRESHOLD = {
    "XS": "0-50",
    "S": "51-200",
    "M": "201-400",
    "L": "401-700",
    "XL": "701",
}


def read_headers() -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": "Bearer %s" % os.environ.get("GITHUB_TOKEN"),
    }


def WriteComment(repository: str, pr_number: int, comment: str) -> None:
    url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"
    result = requests.post(
        url,
        headers=read_headers(),
        json={"body": comment},
    )
    # Successful call to the API will return '201' (created)
    if result.status_code != 201:
        raise RuntimeError(f"Post to URL {url} returned status code = {result.status_code}")


def AddLabelToPR(repository: str, pr_number: int, type: str) -> None:
    all_labels = [f"size/{k}" for k in DEFAULT_PR_SIZE_THRESHOLD.keys()]
    url_base = f"https://api.github.com/repos/{repository}/issues/{pr_number}/"

    # Read current labels
    response = requests.get(url_base + "labels", headers=read_headers())
    if response.status_code != 200:
        raise RuntimeError(
            f"Unable to retrieve labels from issue {repository}/{pr_number} - status_code = {response.status_code}"
        )

    pr_labels_to_remove = [x["name"] for x in response.json() if x["name"] in all_labels]

    # Remove labels from issue
    for label in pr_labels_to_remove:
        response = requests.delete(url_base + f"labels/{label}", headers=read_headers())
        if response.status_code != 200:
            raise RuntimeError(
                f"Unable to remove label '{label}' from issue {repository}/{pr_number} - status_code = {response.status_code}"
            )

    # add new label to pull request
    response = requests.put(url_base + "labels", headers=read_headers(), json={"labels": [f"size/{type}"]})
    if response.status_code != 200:
        raise RuntimeError(
            f"Unable to add label '{label}' to issue {repository}/{pr_number} - status_code = {response.status_code}"
        )


def LabelCommentPR(repository: str, pr_number: int, insertions: int, deletions: int) -> None:
    # Calculating PR Size:
    # The PR size is calculated using the formula: insertions + deletions * 0.5.
    # This calculation considers both the lines of code added and a weighted count of deletions to assess the overall size.
    pr_size = insertions + 0.5 * deletions
    for type, value in DEFAULT_PR_SIZE_THRESHOLD.items():
        v = value.split("-")
        max, min = None, int(v[0])
        if len(v) > 1:
            max = int(v[1])
        if pr_size < min:
            continue
        if max and max < pr_size:
            continue
        AddLabelToPR(repository, pr_number, type)
        if type == "XL":
            comment = (
                f"<b>This is a big Pull Request, we found {int(pr_size)} changes (additions and deletions).</b><br/>"
                "We strongly recommend that you break down this Pull Request into smaller ones to ease the review process."
            )
            WriteComment(repository, pr_number, comment)


def RunDiff(path: str, repository: str, pr_number: int, base_ref: str) -> None:
    # List files
    git_diff_status = f"git --no-pager diff --cached {base_ref} --name-status"
    proc = subprocess.Popen(
        git_diff_status,
        stdout=subprocess.PIPE,
        shell=True,
        cwd=path,
    )
    stdout = proc.communicate()
    name_status = defaultdict(list)
    for i in stdout.decode().split("\n"):
        m = re.match("^(A|M|D)[\t](.+)", i)
        if m:
            name_status[m.group(1)].append(m.group(2))

    # Calculate insertion/deletion
    insertions, deletions = 0, 0
    for type, files in name_status.items():
        if type == "D":
            continue
        for f in files:
            git_diff_stat = f"git --no-pager diff --cached --stat {base_ref} -- {f}"
            proc = subprocess.Popen(
                git_diff_stat,
                stdout=subprocess.PIPE,
                shell=True,
                cwd=path,
            )
            stdout = proc.communicate()
            m = re.search("(\\d*) deletion[s]?\\(\\-\\)", stdout.decode())
            if m:
                deletions += int(m.group(1))
            m = re.search("(\\d*) insertion[s]?\\(\\+\\)", stdout.decode())
            if m:
                insertions += int(m.group(1))
    LabelCommentPR(repository, pr_number, insertions, deletions)


def CheckPR(repository: str, pr_number: int) -> str:
    # Get pull request
    url = f"https://api.github.com/repos/{repository}/pulls/{pr_number}"
    response = requests.get(url, headers=read_headers())
    if response.status_code != 200:
        raise RuntimeError(f"unable to retrieve pull request '{url}' - status code = {response.status_code}")

    head_repo_url = response.json()["head"]["repo"]["html_url"]
    head_branch = response.json()["head"]["ref"]
    base_repo_url = response.json()["base"]["repo"]["html_url"]
    base_branch = response.json()["base"]["ref"]
    clone_path = "my_collection"

    with tempfile.TemporaryDirectory() as tmpdirname:
        # clone directory
        git_clone = f"git clone {head_repo_url} {clone_path}"
        proc = subprocess.Popen(git_clone, stderr=subprocess.PIPE, shell=True, cwd=tmpdirname)
        stderr = proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"failed to clone repository '{head_repo_url}' - stderr = '{stderr.decode()}'")
        collection_path = os.path.join(tmpdirname, clone_path)
        # add remote address for base repository
        git_remote = f"git remote add {base_repo_url} master && git fetch master"
        proc = subprocess.Popen(git_remote, stderr=subprocess.PIPE, shell=True, cwd=collection_path)
        if proc.returncode != 0:
            raise RuntimeError(f"Command '{git_remote}' failed with - stderr = '{stderr.decode()}'")

        # checkout head ref
        git_checkout = f"git checkout origin/{head_branch}"
        proc = subprocess.Popen(git_checkout, stderr=subprocess.PIPE, shell=True, cwd=collection_path)
        if proc.returncode != 0:
            raise RuntimeError(f"Command '{git_checkout}' failed with - stderr = '{stderr.decode()}'")

        RunDiff(collection_path, repository, pr_number, f"master/{base_branch}")


if __name__ == "__main__":
    """Check PR size and push corresponding message and/or add label."""
    parser = ArgumentParser()
    parser.add_argument("--repository", required=True, help="Repository name org/name.")
    parser.add_argument("--pr-number", type=int, required=True, help="Comma-separated list of pull request number.")

    args = parser.parse_args()
    for pr_number in args.pr_number:
        try:
            CheckPR(args.repository, int(pr_number))
        except:
            pass
