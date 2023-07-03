#!/usr/bin/python

import logging
import os
import re
import sys

from github import Github
import argparse
import re


FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("resolve_dependency")
logger.setLevel(logging.DEBUG)


def get_pr_merge_commit_sha(repository: str, pr_number: int) -> str:
    """Retrieve pull request merge commit sha.

    :param repository: The repository name
    :param pr_number: The pull request number
    :returns: The pull request merge commit sha if it exists
    :raises ValueError: if the pull request is not mergeable
    """
    access_token = os.environ.get("GITHUB_TOKEN")
    gh_obj = Github(access_token)
    repo = gh_obj.get_repo(repository)

    pr_obj = repo.get_pull(pr_number)
    if not pr_obj.mergeable:
        # raise an error when the pull request is not mergeable
        sys.tracebacklimit = -1
        raise ValueError(f"Pull request {pr_number} from {repository} is not mergeable")

    return pr_obj.merge_commit_sha


def main() -> None:
    """Run the script."""
    parser = argparse.ArgumentParser(description="check pull request code")
    parser.add_argument("--ref", required=True, help="link to the pull request. e.g: 'https://github.com/ansible-collections/amazon.cloud/pull/111'")

    args = parser.parse_args()
    m = re.match(r"^https://github.com/(.*)/pull/(\d+)$", args.ref)
    if not m:
        sys.tracebacklimit = -1
        raise ValueError("Wrong format for pull request: %s" % args.ref)


    logger.info(f"Repository [{m.group(1)}] id={m.group(2)}")

    token = os.environ.get("GITHUB_TOKEN")
    github_client = Github(token)
    github_repo = github_client.get_repo(m.group(1))

    github_pull = github_repo.get_pull(int(m.group(2)))
    if not github_pull.mergeable:
        # raise an error when the pull request is not mergeable
        sys.tracebacklimit = -1
        raise ValueError(f"Pull request {int(m.group(2))} from {m.group(1)} is not mergeable")

    logger.info(f"Pull request merge commit sha => [{github_pull.merge_commit_sha}]")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(str(github_output), "a", encoding="utf-8") as file_handler:
            file_handler.write(f"merge_commit_sha={github_pull.merge_commit_sha}\n")
            file_handler.write(f"repository={m.group(1)}\n")


if __name__ == "__main__":
    main()