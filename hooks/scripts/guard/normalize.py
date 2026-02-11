# ABOUTME: Command normalization for the PreToolUse pipeline.
# ABOUTME: Strips path prefixes, collapses whitespace, handles env wrappers.
import re

# Matches a leading absolute path to a binary (e.g., /usr/bin/git -> git)
_PATH_PREFIX = re.compile(r'(?:^|(?<=\s))(/[a-zA-Z0-9_./-]+/)')

# Matches env prefix with VAR=val assignments
_ENV_PREFIX = re.compile(r'^env\s+(?:[A-Za-z_][A-Za-z0-9_]*(?:=\S+|=\'[^\']*\'|="[^"]*")\s+)*')

# Multiple whitespace characters (spaces, tabs)
_MULTI_WS = re.compile(r'[ \t]+')


def normalize(command: str) -> str:
    """Normalize a shell command for pattern matching.

    Applies three transformations:
    1. Strip leading/trailing whitespace
    2. Collapse internal whitespace (tabs and multiple spaces -> single space)
    3. Strip absolute path prefixes from executables
    4. Strip env VAR=val prefixes
    """
    # Strip leading/trailing whitespace
    cmd = command.strip()

    # Collapse whitespace
    cmd = _MULTI_WS.sub(' ', cmd)

    # Strip path prefixes from executables
    cmd = _PATH_PREFIX.sub('', cmd)

    # Strip env prefix
    cmd = _ENV_PREFIX.sub('', cmd)

    return cmd
