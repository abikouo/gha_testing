#!/usr/bin/env python3

import logging
from packaging import version
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
        "--release-version",
        help="The release version to test against",
        required=True,
    )

    args = parser.parse_args()

    logger.info("Release version => '%s'", args.release_version)
    # validate version
    version.Version(args.release_version)

if __name__ == "__main__":
    main()