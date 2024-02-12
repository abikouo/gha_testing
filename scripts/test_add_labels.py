#!/usr/bin/env python3
"""Contains tests cases for add_labels modules."""


import pytest
from typing import List

from add_labels import GitHubEvent


@pytest.mark.parametrize(
    "bot_labels,existing_labels,final_labels",
    [
        (
            ["needs_triage"],
            ["needs_info", "has_pr", "new_issue"],
            ["needs_info", "has_pr", "new_issue", "needs_triage"],
        ),
        (
            ["needs_rebase", "new_contributor"],
            ["needs_triage", "new_contributor", "WIP", "to_merge"],
            ["needs_rebase", "new_contributor", "to_merge"],
        ),
    ]
)
def test_githubevent__build_labels(bot_labels: List[str], existing_labels: List[str], final_labels: List[str]) -> None:
    assert sorted(GitHubEvent.merge_labels(existing_labels, *bot_labels)) == sorted(final_labels)
