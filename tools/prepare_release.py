#!/usr/bin/env python3

import logging
from packaging import version
import yaml
import os
from pathlib import PosixPath
from argparse import ArgumentParser


FORMAT = "[%(asctime)s] - %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("compute_release_version")
logger.setLevel(logging.DEBUG)


def main() -> None:

    parser = ArgumentParser(
        description="Update version into galaxy.yml"
    )
    
    parser.add_argument(
        "--path",
        help="Path to the directory, default to the current directory",
        type=PosixPath,
        required=True,
    )

    args = parser.parse_args()

    release_version = os.environ.get("RELEASE_VERSION")
    logger.info("Release version => '%s'", release_version)
    # validate version
    version.Version(release_version)

    with (args.path / "galaxy.yml").open() as file_read:
        content = yaml.safe_load(file_read)

    logger.info("content before releasing -> %s", content)
    content['version'] = release_version
    logger.info("content after releasing -> %s", content)
    with (args.path / "galaxy.yml").open("w", encoding ="utf-8") as file_write:
        yaml.dump(content, file_write, default_flow_style=False)

if __name__ == "__main__":
    main()