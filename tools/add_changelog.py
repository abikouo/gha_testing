#!/usr/bin/python

import re
import os
from collections import defaultdict
import yaml
import subprocess
import sys
import logging
from github import Github


FORMAT = '[%(asctime)s] - %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('add_changelog')
logger.setLevel(logging.DEBUG)


CHANGES_TYPE = (
    "release_summary", "breaking_changes", "major_changes", "minor_changes", "removed_features",
    "deprecated_features", "security_fixes", "bugfixes", "known_issues", "trivial",
)

PLUGINS_PREFIXES = (
    "plugins/modules", "plugins/action", "plugins/inventory", "plugins/lookup", "plugins/filter",
    "plugins/connection", "plugins/become", "plugins/cache", "plugins/callback", "plugins/cliconf",
    "plugins/httpapi", "plugins/netconf", "plugins/shell", "plugins/strategy", "plugins/terminal",
    "plugins/test", "plugins/vars",
)
DOCS_PREFIXES = ("docs/", "plugins/doc_fragments")


def run_command(cmd, **kwargs):
    params = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": True
    }
    params.update(kwargs)
    proc = subprocess.Popen(cmd, **params)
    out, err = proc.communicate()
    return proc.returncode, out, err


class ChangeLogValidator(object):

    CHANGELOG_RE = re.compile(r"^changelogs/fragments/(.*)\.(yaml|yml)$")

    def __init__(self, base_ref, labels):

        self.base_ref = base_ref
        self._changes = None
        self._changelogs = None
        self._labels = labels

    def _list_changes(self):
        cmd = "git diff origin/{0} --name-status".format(self.base_ref)
        logger.info("list changes: %s" % cmd)
        rc, out, err = run_command(cmd)
        if rc != 0:
            raise ValueError(err)

        for item in out.decode("utf-8").split("\n"):
            v = item.split("\t")
            if len(v) == 2:
                self._changes[v[0]].append(v[1])

        logger.info("changes -> %s" % dict(self._changes))

    @property
    def changes(self):
        if self._changes is None:
            self._changes = defaultdict(list)
            self._list_changes()
        return self._changes

    @staticmethod
    def test_changelog(change):
        return ChangeLogValidator.CHANGELOG_RE.match(change)

    @property
    def changelogs(self):
        if self._changelogs is None:
            self._changelogs = list(filter(self.test_changelog, self.changes))
        return self._changelogs

    def has_changelog(self):
        return bool(self.changelogs)

    def is_changelog_required(self):
        """
            changelog is not required for pull request adding new module/plugin
            or updating documentation
        """
        if 'skip-changelog' in self._labels:
            logger.info("Pull request contains label 'skip-changelog'")
            return False

        logger.info("check if changelog is required for this pull request")

        new_plugin = lambda y: any(y.startswith(x) for x in PLUGINS_PREFIXES)
        doc_update = lambda y: any(y.startswith(x) for x in DOCS_PREFIXES)

        # Validate Pull request add new modules and plugins
        if any([new_plugin(x) for x in self.changes["A"]]):
            return False

        # Validate documentation changes only
        if all([doc_update(x) for x in self.changes["A"] + self.changes["M"] + self.changes["D"]]):
            return False

        return True

    @staticmethod
    def is_valid_changelog(path):        
        try:
            # https://github.com/ansible-community/antsibull-changelog/blob/main/docs/changelogs.rst#changelog-fragment-categories
            
            with open(path, "rb") as f:
                result = list(yaml.safe_load_all(f))

            for section in result:
                for key in section.keys():
                    if key not in CHANGES_TYPE:
                        logger.info("Unexpected changelog section {0} from file {1}".format(key, os.path.basename(path)))
                        return False
                    if not isinstance(section[key], list):
                        logger.info(
                            "Changelog section {0} from file {1} must be a list, {2} found instead.".format(
                                key,
                                os.path.basename(path),
                                type(section[key])
                            )
                        )
                        return False
            return True
        except (IOError, yaml.YAMLError) as exc:
            logger.info("Error loading changelog file {0}: {1}".format(os.path.basename(path),exc))
            return False

    def has_valid_changelogs(self):
        return all(self.is_valid_changelog(c) for c in self.changelogs)


class GitHubRepo(object):

    CLOSES_REF_RE = re.compile(r"^closes[ ]*#([0-9]*)", re.MULTILINE | re.IGNORECASE)

    def __init__(self, repo_name, pr_number):

        self.pr_number = pr_number
        self.repo_name = repo_name
        
        access_token = os.environ.get("GITHUB_TOKEN")
        gh = Github(access_token)
        self.gh_repo = gh.get_repo(repo_name)
        # print(dir(self.gh_repo))
        self.gh_pr = self.gh_repo.get_pull(pr_number)

    @property
    def labels(self):
        return [i.name for i in self.gh_pr.labels]

    @property
    def body(self):
        return self.gh_pr.body

    @property
    def base_ref(self):
        return self.gh_pr.base.ref

    @property
    def title(self):
        return self.gh_pr.title

    @property
    def html_url(self):
        return self.gh_pr.html_url

    def create_changelog(self, changes):

        # find related issue
        issue_ref = self.CLOSES_REF_RE.findall(self.body)
        logger.info("Issue ref -> %s" % issue_ref)
        issues = {}
        for issue_id in issue_ref:
            issue = self.gh_repo.get_issue(int(issue_id))
            issues[issue_id] = {
                'labels': [i.name for i in issue.labels], 'url': issue.html_url
            }

        # Determine changelog type:
        # first based on pull request labels, any label with the following syntax 'changelog/xxxxxx'
        # e.g: changelog/breaking_changes to reference breaking changes
        change_type = None
        for item in self.labels:
            m = re.match(r"^changelog/(.*)", item)
            if m and m.group(1) in CHANGES_TYPE:
                change_type = m.group(1)

        if change_type is None and issues:
            # Determines changelog type from issue reference into the pull request
            for _, v in issues.items():
                if "type/enhancement" in v["labels"]:
                    change_type = "minor_changes"
                elif "type/bug" in v["labels"]:
                    change_type = "bugfixes"

        change_type = change_type or "minor_changes"
        logger.info("change type -> '%s'" % change_type)

        issue_ref_text = self.html_url if not issues else " ".join([v["url"] for _, v in issues.items()])
        logger.info("issue_ref_text -> '%s'" % issue_ref_text)
        change_details = []
        # link modification with plugin modified
        for f in changes["M"]:
            if any(f.startswith(x) for x in PLUGINS_PREFIXES):
                m = re.match(r"^plugins/(.*?)/(.*?)\.py", f)
                if m:
                    plugin_name = m.group(2) if m.group(1) == "modules" else m.group(1) + "/" + m.group(2)
                    change_details.append("{} - {} ({}).".format(
                        plugin_name, self.title, issue_ref_text
                    ))
        if not change_details:
            change_details.append("{0} ({1}).".format(self.title, issue_ref_text))
        logger.info("change details -> %s" % change_details)

        yaml_file_name = "changelogs/fragments/{}-{}.yaml".format(
            self.pr_number, self.title.replace(" ", "-")
        )
        logger.info("Changelog created -> '%s'" % yaml_file_name)
        result = {change_type: change_details}
        with open(yaml_file_name, 'w') as fd:
            yaml.dump(result, fd, default_flow_style=False, explicit_start=True)

def main():

    repository_name = os.environ.get("PR_REPOSITORY")
    pr_number = int(os.environ.get("PR_NUMBER"))

    gh_obj = GitHubRepo(repository_name, pr_number)

    validator = ChangeLogValidator(gh_obj.base_ref, gh_obj.labels)

    if not validator.is_changelog_required():
        # changelog not required
        logger.info(
            "Changelog not required as PR adds new modules and/or plugins or "\
            "contain only documentation changes."
        )
        sys.exit(0)

    if not validator.has_changelog():
        logger.info(
            "Missing changelog fragment. This is not required only if "\
            "PR adds new modules and plugins or contain only documentation changes. "\
            "Add label 'skip-changelog' to explicit skip changelog verification."
        )
        gh_obj.create_changelog(validator.changes)
    elif not validator.has_valid_changelogs():
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":

    main()