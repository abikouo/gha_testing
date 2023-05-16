#!/usr/bin/env python3
"""Script to create tag on github repository."""

import logging
import os

from github import Github
from argparse import ArgumentParser


FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("compute_release_version")
logger.setLevel(logging.DEBUG)



def main() -> None:

    parser = ArgumentParser(description="create tag and push to remote repository")
    parser.add_argument("-t", "--tag", required=True, help="Tag name")
    parser.add_argument("-r", "--repository", required=True, help="Remote repository name e.g: 'abikouo/gha_testing'")
    parser.add_argument("-c", "--commit-sha", required=True, help="Commit sha from repository e.g: 'b8c4452'")

    args = parser.parse_args()

    access_token = os.environ.get("GITHUB_TOKEN")
    repository = args.repository
    tag = args.tag
    commit_sha = args.commit_sha

    logger.info("Release tag -> '%s'", tag)
    logger.info("Repository -> '%s'", repository)
    logger.info("Commit sha -> '%s'", commit_sha)

    gh_instance = Github(access_token)
    gh_repository = gh_instance.get_repo(repository)

    tag_message = f"tag created from commit {commit_sha}"
    gh_tag = gh_repository.create_git_tag(
        tag=tag, message=tag_message, type="commit", object=commit_sha
    )
    gh_repository.create_git_ref(f"refs/tags/{gh_tag.tag}", gh_tag.sha)


if __name__ == "__main__":
    main()
