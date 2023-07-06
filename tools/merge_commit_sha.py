#!/usr/bin/python
"""Script to check if a depends-on pull request has been defined into pull request body."""

import logging
import os
import re
import sys

from github import Github
from argparse import ArgumentParser


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
    parser = ArgumentParser(description="Retrieve merge commit sha for a pull request")
    parser.add_argument("-r", "--repo", help="Repository name")
    parser.add_argument("-n", "--number", help="Pull request number", type=int)

    args = parser.parse_args()
    print("Merge commit Sha => %s" % get_pr_merge_commit_sha(args.repo, args.number))


if __name__ == "__main__":
    main()
