#!/usr/bin/python

import copy
import logging
import os
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Union

import requests
from github import (
    Github,
    GithubException,
    Issue,
    PullRequest,
    Repository,
    UnknownObjectException,
)

FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("labeller")
logger.setLevel(logging.DEBUG)


NEEDS_TRIAGE_LABEL = "needs_triage"
NEW_CONTRIBUTOR_LABEL = "new_contributor"
NEEDS_REVISION_LABEL = "needs_revision"
WIP_LABEL = "WIP"
NEEDS_REBASE_LABEL = "needs_rebase"


COLLECTION_LABELS = {
    NEW_CONTRIBUTOR_LABEL: {
        "color": "8aea94",
        "description": "Help guide this first time contributor",
    },
    NEEDS_TRIAGE_LABEL: {"color": "ededed"},
    NEEDS_REVISION_LABEL: {
        "color": "d9ef0b",
        "description": "This PR fails CI tests or a maintainer has requested a review/revision of the PR",
    },
    WIP_LABEL: {"color": "d9df0b", "description": "Work in progress"},
    NEEDS_REBASE_LABEL: {
        "color": "d9cf0b",
        "description": "https://docs.ansible.com/ansible/devel/dev_guide/developing_rebasing.html",
    },
}

API_ACCEPTS_HEADERS = [
    "application/json",
    "application/vnd.github.mockingbird-preview",
    "application/vnd.github.sailor-v-preview+json",
    "application/vnd.github.starfox-preview+json",
    "application/vnd.github.squirrel-girl-preview",
    "application/vnd.github.v3+json",
]


class GitHubEvent(object):
    all_labels = [
        NEEDS_TRIAGE_LABEL,
        NEW_CONTRIBUTOR_LABEL,
        NEEDS_REVISION_LABEL,
        WIP_LABEL,
        NEEDS_REBASE_LABEL,
    ]

    def __init__(
        self,
        repo: Repository,
        issue_or_pullrequest: Union[Issue.Issue, PullRequest.PullRequest],
        action: str,
    ) -> None:
        self.instance = issue_or_pullrequest
        self.raw_data = self.instance.raw_data
        self.submitter = self.raw_data["user"]["login"]
        self.repo = repo
        self.action = action
        self.existing_labels = [label.name for label in self.instance.get_labels()]

    def _create_repository_label(self, name):
        label = COLLECTION_LABELS.get(name, {})
        if label:
            try:
                self.repo.create_label(name=name, **label)
            except GithubException as err:
                if err.data["errors"][0]["code"] != "already_exists":
                    raise
                logger.info("Label '%s' already exists into repository", name)

    @staticmethod
    def merge_labels(existing_labels: List[str], *args: List[str]) -> List[str]:
        to_add = [label for label in args if label not in existing_labels]
        to_remove = [label for label in GitHubEvent.all_labels if label not in args]

        final_labels = copy.deepcopy(existing_labels)
        final_labels.extend(to_add)
        for label in to_remove:
            try:
                final_labels.remove(label)
            except ValueError:
                pass
        return final_labels

    def set_labels(self, *args: List[str]) -> None:
        final_labels = self.merge_labels(self.existing_labels, *args)

        if final_labels != self.existing_labels:
            for label in final_labels:
                if label not in self.existing_labels:
                    self._create_repository_label(label)
            self.instance.set_labels(*final_labels)

    def needs_triage(self) -> bool:
        """needs_triage (for newly opened / reopened issues and PRs)"""
        if self.action in ("opened", "reopened"):
            return True
        return False

    @property
    def closed(self) -> bool:
        return self.raw_data["state"] == "closed"

    def add_labels(self) -> None:
        pass


class GitHubPullRequest(GitHubEvent):
    def __init__(
        self, repo: Repository, pullrequest: PullRequest.PullRequest, action: str
    ) -> None:
        super(GitHubPullRequest, self).__init__(repo, pullrequest, action)
        self._mergeable_state_fetch = False

    def _get_reviews(self) -> Dict[str, Any]:
        endpoint_url = self.instance.url + "/reviews"
        response = requests.get(
            endpoint_url,
            headers={"Authorization": "Bearer %s" % os.environ.get("GH_TOKEN")},
        )
        reviews = sorted(
            [
                {
                    "author": rev["user"]["login"],
                    "submitted_at": datetime.fromisoformat(
                        rev["submitted_at"].replace("Z", "+00:00")
                    ),
                    "state": rev["state"],
                }
                for rev in response.json()
                if rev["user"]["login"] != self.submitter
            ],
            key=lambda d: d["submitted_at"],
        )

        # Calculate the final review state for each reviewer
        user_reviews = defaultdict(dict)
        for rev in reviews:
            author = rev["author"]
            user_reviews[author]["state"] = rev["state"]
            user_reviews[author]["submitted_at"] = rev["submitted_at"]
        return user_reviews

    def _get_merge_commits(self) -> List[str]:
        merge_commits = []
        commits = [x for x in self.instance.get_commits()]
        headers = {
            "Accept": ",".join(API_ACCEPTS_HEADERS),
            "Authorization": "Bearer %s" % os.environ.get("GH_TOKEN"),
        }
        for commit in commits:
            response = requests.get(commit.url, headers=headers).json()
            parents = response["parents"]
            message = response["commit"]["message"]
            if len(parents) > 1 or message.startswith("Merge branch"):
                merge_commits.append(commit)
        return merge_commits

    @property
    def mergeable_state(self) -> str:
        if not self._mergeable_state_fetch:
            # http://stackoverflow.com/a/30620973
            retries = 0
            while self.instance.mergeable_state == "unknown":
                retries += 1
                if retries >= 10:
                    logger.warning("exceeded fetch threshold for mergeable_state")
                    return None
                logging.warning(
                    "re-fetch[%s] PR#%s because mergeable state is unknown"
                    % (retries, self.instance.number)
                )
                time.sleep(1)
            self._mergeable_state_fetch = True

        return self.instance.mergeable_state

    def needs_revision_or_rebase(self) -> Dict[str, bool]:
        """
        - needs_revision (changes have been requested on the PR)
        - needs_rebase (PR has a merge conflict that must be resolved)
        """
        logger.info("mergeable state => %s", self.mergeable_state)
        result = {}
        if self.mergeable_state == "dirty":
            result[NEEDS_REVISION_LABEL] = True
            result[NEEDS_REBASE_LABEL] = True
        else:
            user_reviews = self._get_reviews()
            logger.info("User reviews => %s", user_reviews)
            changed_requested_by = [
                author
                for author, review in user_reviews.items()
                if review["state"] == "CHANGES_REQUESTED"
            ]
            logger.info("Changes requested by => %s", changed_requested_by)
            if changed_requested_by:
                result[NEEDS_REVISION_LABEL] = True

        if not result.get(NEEDS_REBASE_LABEL, False) and self._get_merge_commits():
            # Merge commits are bad, force a rebase
            result[NEEDS_REBASE_LABEL] = True

        return result

    def new_contributor(self) -> bool:
        """new_contributor (PRs where the pull_request's author_association is FIRST_TIME_CONTRIBUTOR)"""
        return self.raw_data.get("author_association") in ("NONE", "FIRST_TIME_CONTRIBUTOR")

    def wip(self) -> bool:
        """WIP (any time a PR's title startsWith "WIP")"""
        logger.info("PR title => %s", self.instance.title)
        return self.instance.title.startswith("WIP")

    def add_labels(self) -> None:
        logger.info("Existing labels => %s", self.existing_labels)
        labels = []
        if self.new_contributor():
            labels.append(NEW_CONTRIBUTOR_LABEL)
        if self.needs_triage():
            labels.append(NEEDS_TRIAGE_LABEL)
        if self.wip():
            labels.append(WIP_LABEL)
        labels += [
            item for item, value in self.needs_revision_or_rebase().items() if value
        ]

        logger.info("adding labels => %s", labels)
        self.set_labels(*labels)


class GitHubIssue(GitHubEvent):
    def __init__(self, repo: Repository, issue: Issue.Issue, action: str) -> None:
        super(GitHubIssue, self).__init__(repo, issue, action)
        self._mergeable_state_fetch = False

    def add_labels(self) -> None:
        """set needs_triage label (for newly opened / reopened issues and PRs)"""
        labels = []
        if self.needs_triage():
            labels.append(NEEDS_TRIAGE_LABEL)
        logger.info("adding labels => %s", labels)
        self.set_labels(*labels)


def run(
    repository: str, access_token: str, event_number: int, event_action: str
) -> None:
    gh_client = Github(access_token)
    gh_repo = gh_client.get_repo(repository)

    # Create instance: pull request or issue object
    try:
        # try event as pull request
        pullrequest = gh_repo.get_pull(event_number)
        instance = GitHubPullRequest(gh_repo, pullrequest, event_action)
    except UnknownObjectException:
        issue = gh_repo.get_issue(event_number)
        instance = GitHubIssue(gh_repo, issue, event_action)

    if not instance.closed:
        instance.add_labels()


def main():
    access_token = os.environ.get("GH_TOKEN")
    event_repository = os.environ.get("GH_REPOSITORY")
    event_action = os.environ.get("GH_EVENT_ACTION")
    event_number = int(os.environ.get("GH_EVENT_NUMBER"))

    run(event_repository, access_token, event_number, event_action)


if __name__ == "__main__":
    main()
