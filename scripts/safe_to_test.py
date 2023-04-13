#!/usr/bin/python
"""Script to check if pull request can be tested.
   Either when the user is a collaborator or label 'safe to test' has been added to
   the pull request
"""

from github import Github, Repository, GithubException
import logging
import os
import sys


FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("safe_to_test")
logger.setLevel(logging.DEBUG)


SAFE_TO_TEST_LABEL = "safe to test"
SAFE_TO_TEST_LABEL_COLOR = "8aea94"


def main() -> None:
    """Run the script.
    """

    token = os.environ.get("GH_TOKEN", "")
    repository = os.environ.get("GH_REPOSITORY", "")
    pr_number = int(os.environ.get("GH_PR_NUMBER", "0"))
    event_label_name = os.environ.get("GH_EVENT_LABEL_NAME", "")
    event_action = os.environ.get("GH_EVENT_ACTION", "")

    gh_client = Github(token)
    gh_repo = gh_client.get_repo(repository)
    try:
        pr_instance = gh_repo.get_pull(pr_number)
    except GithubException as err:
        logger.error("failed to get pull request [%s#%d] info -> %s" % (repository, pr_number, err))
        sys.exit(1)

    author = pr_instance.raw_data["user"]["login"]
    is_collaborator = False
    if author in [collaborator.login for collaborator in gh_repo.get_collaborators()]:
        is_collaborator = True

    labels = [label.name for label in pr_instance.get_labels()]
    logger.info("Pull request labels: %s", labels)
    if SAFE_TO_TEST_LABEL in labels:
        if is_collaborator:
            logger.info("Pull request contains label '%s' from a collaborator author", SAFE_TO_TEST_LABEL)
            sys.exit(0)
        elif event_label_name != SAFE_TO_TEST_LABEL and event_action in ("synchronize", "reopened"):
            # Remove 'safe to test' label for non-collaborator author
            labels.remove(SAFE_TO_TEST_LABEL)
            pr_instance.set_labels(*labels)
    elif is_collaborator:
        # add label 'safe to test' when missing for collaborator's pull request
        # first create label into repository
        try:
            gh_repo.create_label(name=SAFE_TO_TEST_LABEL, color=SAFE_TO_TEST_LABEL_COLOR)
        except GithubException as err:
            if err.data.get("errors", [{}]).get("code") != "already_exists":
                raise
            logger.info("Label '%s' already exists into repository", SAFE_TO_TEST_LABEL)
        # update pull request labels
        labels.append(SAFE_TO_TEST_LABEL)
        pr_instance.set_labels(*labels)

    # check pull request labels
    pr_instance = gh_repo.get_pull(pr_number)
    if SAFE_TO_TEST_LABEL not in [label.name for label in pr_instance.get_labels()]:
        logger.info("Please contact a maintainer to add label '%s' in order to trigger tests.", SAFE_TO_TEST_LABEL)
        sys.exit(1)


if __name__ == "__main__":

    main()
