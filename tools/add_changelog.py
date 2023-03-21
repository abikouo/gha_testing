#!/usr/bin/python

import re
import os
from collections import defaultdict
import yaml
import subprocess
import sys
import logging

FORMAT = '[%(asctime)s] - %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('add_changelog')
logger.setLevel(logging.DEBUG)


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

    def __init__(self, base_ref):

        self.base_ref = base_ref
        self._changes = None
        self._changelogs = None

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
        logger.info("check if changelog is required for this pull request")
        PLUGINS_PREFIXES = (
            "plugins/modules", "plugins/action", "plugins/inventory", "plugins/lookup", "plugins/filter",
            "plugins/connection", "plugins/become", "plugins/cache", "plugins/callback", "plugins/cliconf",
            "plugins/httpapi", "plugins/netconf", "plugins/shell", "plugins/strategy", "plugins/terminal",
            "plugins/test", "plugins/vars",
        )
        DOCS_PREFIXES = ("docs/", "plugins/doc_fragments")

        new_plugin = lambda y: any(y.startswith(x) for x in PLUGINS_PREFIXES)
        doc_update = lambda y: any(y.startswith(x) for x in DOCS_PREFIXES)

        # Validate Pull request add new modules and plugins
        if any([new_plugin(x) for x in self.changes["A"]]):
            return True

        # Validate documentation changes only
        if all([doc_update(x) for x in self.changes["A"] + self.changes["M"] + self.changes["D"]]):
            return True

        return False

    @staticmethod
    def is_valid_changelog(path):        
        try:
            # https://github.com/ansible-community/antsibull-changelog/blob/main/docs/changelogs.rst#changelog-fragment-categories
            changes_type = (
                "release_summary", "breaking_changes", "major_changes", "minor_changes", "removed_features",
                "deprecated_features", "security_fixes", "bugfixes", "known_issues", "trivial",
            )
            with open(path, "rb") as f:
                result = list(yaml.safe_load_all(f))

            for section in result:
                for key in section.keys():
                    if key not in changes_type:
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


def main():

    base_ref = os.environ.get("PR_BASE_REF") or "main"
    logger.info("Base ref -> '%s'" % base_ref)
    validator = ChangeLogValidator(base_ref)

    if validator.is_changelog_required():
        # changelog not required
        logger.info(
            "Changelog not required as PR adds new modules and/or plugins or "\
            "contain only documentation changes."
        )
        return 0
    if not validator.has_changelog():
        logger.info(
            "Missing changelog fragment. This is not required only if "\
            "PR adds new modules and plugins or contain only documentation changes."
        )
        sys.exit(1)

    if not validator.has_valid_changelogs():
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":

    main()