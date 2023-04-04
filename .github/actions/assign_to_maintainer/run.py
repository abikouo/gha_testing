#!/usr/bin/python

import os
import logging
import requests

FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("assign_to_maintainer")
logger.setLevel(logging.DEBUG)


def add_assignee(url, token, assignee):
    """
        curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}"
          -X POST
          -d '{"assignees": [assignee]}'
          https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/assignees
    """
    assignee = dict(assignees=[assignee])
    headers = dict(Authorization="token %s" % token)

    response = requests.post(url, json=assignee, headers=headers)
    logger.info("JSON Response => %s", response.json())


def main():

    pr_number = os.environ.get("PR_NUMBER")
    pr_repository = os.environ.get("PR_REPOSITORY")
    token = os.environ.get("GH_TOKEN")

    url = f"https://api.github.com/repos/{pr_repository}/issues/{pr_number}/assignees"

    logger.info("URL => '%s'", url)
    add_assignee(url, token, "abikouo")

if __name__ == "__main__":
    main()