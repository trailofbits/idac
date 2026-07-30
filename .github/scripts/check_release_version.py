# /// script
# dependencies = ["packaging"]
# ///
"""Validate RELEASE_VERSION against RELEASE_TAGS."""

import os
import sys

from packaging.version import InvalidVersion, Version

release = Version(os.environ["RELEASE_VERSION"])
if release.local is not None:
    sys.exit(f"v{release} is a local version and cannot be published to PyPI")

versions = []
for tag in os.environ["RELEASE_TAGS"].split():
    try:
        versions.append(Version(tag))
    except InvalidVersion:
        pass

if release in versions:
    sys.exit(f"v{release} has already been released")

latest = max(versions, default=None)
if latest is not None and release < latest:
    sys.exit(f"v{release} is not newer than the latest release, v{latest}")
