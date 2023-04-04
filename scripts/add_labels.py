#!/usr/bin/python

import os
import logging
from github import Github
from github import GithubException, UnknownObjectException


FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("labeller")
logger.setLevel(logging.DEBUG)


NEEDS_TRIAGE_LABEL = "needs_triage"
NEEDS_CONTRIBUTOR_LABEL = "new_contributor"
NEEDS_REVISION_LABEL = "needs_revision"
WIP_LABEL = "WIP"
NEEDS_REBASE_LABEL = "needs_rebase"


COLLECTION_LABELS = {
	NEEDS_CONTRIBUTOR_LABEL: {
		"color": "8aea94",
		"description": "Help guide this first time contributor"
	},
	NEEDS_TRIAGE_LABEL: {
		"color": "ededed"
	},
	NEEDS_REVISION_LABEL: {
		"color": "d9ef0b",
		"description": "This PR fails CI tests or a maintainer has requested a review/revision of the PR"
	},
	WIP_LABEL: {
		"color": "d9df0b",
		"description": "Work in progress"
	},
	NEEDS_REBASE_LABEL: {
		"color": "d9cf0b",
		"description": "https://docs.ansible.com/ansible/devel/dev_guide/developing_rebasing.html"
	}
}

class ManageLabels(object):

    def __init__(self, repository, access_token, event_action):

        self.client = Github(access_token)
        self.repo = self.client.get_repo(repository)
        self.action = event_action

    def _create_label(self, name):
        label = COLLECTION_LABELS.get(name, {})
        if label:
            try:
                self.repo.create_label(name=name, **label)
            except GithubException as err:
                if err.data['errors'][0]['code'] != 'already_exists':
                    raise
                logger.info("Label '%s' already exists into repository", name)

    def set_labels_to_issue(self, gh_issue):
        """set needs_triage label (for newly opened / reopened issues and PRs)"""
        existing_labels = [label.name for label in gh_issue.get_labels()]
        logger.info("Existing labels: %s" % existing_labels)
        if self.action in ('opened', 'reopened') and NEEDS_TRIAGE_LABEL not in existing_labels:
            logger.info("add label '%s' to issue", NEEDS_TRIAGE_LABEL)
            self._create_label(NEEDS_TRIAGE_LABEL)
            gh_issue.set_labels(NEEDS_TRIAGE_LABEL)

    def set_labels_to_pull_request(self, gh_pr):
        """
        - needs_triage (for newly opened / reopened issues and PRs)
        - new_contributor (PRs where the pull_request's author_association is FIRST_TIME_CONTRIBUTOR)
        - WIP (any time a PR's title startsWith "WIP")
        - needs_revision (changes have been requested on the PR)
        - needs_rebase (PR has a merge conflict that must be resolved)
        """
        pass

    def _get_event(self, event_number):
        try:
            # try event as pull request
            gh_pull = self.repo.get_pull(event_number)
            return gh_pull, False
        except UnknownObjectException:
            gh_issue = self.repo.get_issue(event_number)
            return gh_issue, True

    def run(self, event_number):

        gh_event, is_issue = self._get_event(event_number)
        logger.info("is event type issue: {}".format(is_issue))

        if is_issue:
            self.set_labels_to_issue(gh_event)

def main():

    access_token = os.environ.get("GH_TOKEN")
    event_repository = os.environ.get("GH_REPOSITORY")
    event_action = os.environ.get("GH_EVENT_ACTION") # Extracted ${{ github.event.action }}
    event_number = int(os.environ.get("GH_EVENT_NUMBER"))

    assignator = ManageLabels(repository=event_repository, access_token=access_token, event_action=event_action)
    assignator.run(event_number=event_number)
    
if __name__ == "__main__":
    main()