#!/usr/bin/env python3
"""Script to create tag on github repository."""

import logging
import os
from github import Github


FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("compute_release_version")
logger.setLevel(logging.DEBUG)


def main() -> None:
    """Create tag and publish to Github repository."""

    access_token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("REPOSITORY")
    tag = os.environ.get("RELEASE_TAG")

    logger.info("Release tag -> '%s'", tag)
    logger.info("Repository -> '%s'", repository)

    gh_instance = Github(access_token)
    gh_repository = gh_instance.get_repo(repository)

    gh_tag = gh_repository.create_git_tag(tag=tag, message="", type="commit", object="314a625a5e1e02ac4fa7c984de8861bd9454de5d")
    gh_repository.create_git_ref('refs/tags/{}'.format(gh_tag.tag), gh_tag.sha)


if __name__ == "__main__":
    main()
