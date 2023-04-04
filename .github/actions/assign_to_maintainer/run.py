#!/usr/bin/python

import os
import logging

FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("assign_to_maintainer")
logger.setLevel(logging.DEBUG)


def main():

    pr_number = os.environ.get("PR_NUMBER")
    pr_repository = os.environ.get("PR_REPOSITORY")
    token = os.environ.get("GH_TOKEN")

    url = f"https://api.github.com/repos/{pr_repository}/issues/{pr_number}/assignees"

    logger.info("POST to URL => '%s'", url)

if __name__ == "__main__":
    main()