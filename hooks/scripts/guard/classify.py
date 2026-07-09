# ABOUTME: Context classification for shell commands.
# ABOUTME: Distinguishes executed code from string literals, comments, and safe arguments.
# Defer annotation evaluation so PEP 604 unions (int | None) do not raise at
# import time on Python 3.9 — a guard that fails to import would fail OPEN.
from __future__ import annotations

import re

# Variable assignment: VAR="value" — the quoted string is data, not code.
_VAR_ASSIGNMENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=$')

# Commands whose arguments are data, not code. Patterns in their quoted
# arguments should not trigger the guard.
_SAFE_WRAPPERS = {
    "echo", "printf", "cat", "grep", "egrep", "fgrep", "rg", "ag",
    "sed", "awk", "head", "tail", "less", "more", "wc",
    "tee", "sort", "uniq", "cut", "tr", "xargs",
    "test", "[",
}

# Flags whose arguments are data, not code. Quoted strings following
# these flags are blanked before pattern matching.
_DATA_FLAGS = {"-m", "--message", "--notes", "--body", "--title"}

# `bash -c "..."` and `eval "..."` are not matched here. Because bash/sh/eval are
# not safe wrappers, get_effective_command leaves their quoted argument intact, so
# any dangerous pattern inside is caught by the Tier 1 / Tier 2 rules directly.

# A temporary environment-variable prefix, e.g. `FOO=1 BAR="a b" `, that bash
# allows in front of the command it runs.
_ENV_ASSIGN = r'(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|\'[^\']*\'|\S*)\s+)*'

# Pipe-to-shell: output piped to an interpreter that reads stdin as code.
# Matches a bare interpreter or one taking flags (e.g. `| bash -s`, `| sudo bash`,
# `| FOO=1 bash`, `| python3 -`). The negative lookahead lets a script-file
# argument through, so `cat data | python3 process.py` (piping data into a
# script) is not flagged.
_PIPE_TO_SHELL = re.compile(
    r'\|\s*(?:sudo\s+|doas\s+)?' + _ENV_ASSIGN +
    r'(?:bash|sh|zsh|dash|python3?|node|ruby|perl)'
    r'\b(?!\s+[^\s|;&<>-])'
)

# Process substitution with network download: shell <(curl/wget ...)
# Executes arbitrary remote code, functionally identical to pipe-to-shell
_PROCESS_SUB_DOWNLOAD = re.compile(
    r'(?:bash|sh|zsh|dash|source|\.)\s+<\(.*(?:curl|wget)\s'
)

# Inline interpreter patterns: python -c, ruby -e, perl -e, node -e, php -r.
# Intervening flags are allowed (e.g. `python3 -I -c`, `ruby -w -e`) so a flag
# between the interpreter and the inline-code switch cannot defeat the match.
_INTERPRETER_BRIDGE = re.compile(
    r'(?:python3?|python2|ruby|perl|node|php)\s+(?:-\S+\s+)*(?:-c|-e|-r)\s+'
)

# Language-specific destructive patterns (checked in bridge arguments)
_LANG_DESTRUCTIVE = [
    # Python
    re.compile(r'os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|shutil\.move'),
    # Ruby
    re.compile(r'FileUtils\.rm_rf|FileUtils\.rm_r|File\.delete|Dir\.rmdir'),
    # Perl
    re.compile(r'unlink|rmdir|rmtree|File::Path'),
    # Node.js
    re.compile(r'rmSync|rmdirSync|unlinkSync|rm\s*\(|rimraf'),
    # PHP
    re.compile(r'unlink|rmdir|array_map.*unlink'),
]


# Shell expansions that run or interpolate at runtime. Inside double quotes,
# command substitution `$( )` and backticks execute, and `${...}` interpolates —
# so a double-quoted region containing one of these is not inert data.
_EXPANSION = ('$(', '${', '`')


def _has_expansion(text: str) -> bool:
    return any(marker in text for marker in _EXPANSION)


def find_quoted_regions(command: str) -> list[tuple[int, int, str]]:
    """Find all quoted regions in a command.

    Returns list of (start, end, quote_char) tuples.
    Handles single quotes (no escaping) and double quotes (backslash escaping).
    """
    regions = []
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "'":
            # Single quote: ends at next single quote, no escaping
            end = command.find("'", i + 1)
            if end == -1:
                end = len(command)
            regions.append((i, end + 1, "'"))
            i = end + 1
        elif ch == '"':
            # Double quote: ends at next unescaped double quote
            j = i + 1
            while j < len(command):
                if command[j] == '\\':
                    j += 2
                elif command[j] == '"':
                    break
                else:
                    j += 1
            regions.append((i, j + 1, '"'))
            i = j + 1
        else:
            i += 1
    return regions


def find_comment_start(command: str, quoted: list[tuple[int, int, str]]) -> int | None:
    """Find the position of an unquoted # that starts a shell comment.

    A '#' inside a ${...} parameter expansion (e.g. the length operator in
    ${#PATH}) is not a comment, so ${...} spans are skipped. Returns the index
    of the comment '#', or None if there is no comment.
    """
    def in_quote(i: int) -> bool:
        return any(start <= i < end for start, end, _ in quoted)

    depth = 0  # ${...} nesting depth
    i = 0
    n = len(command)
    while i < n:
        if not in_quote(i):
            if command[i] == '$' and i + 1 < n and command[i + 1] == '{':
                depth += 1
                i += 2
                continue
            if command[i] == '}' and depth > 0:
                depth -= 1
            elif command[i] == '#' and depth == 0:
                return i
        i += 1
    return None


def _preceding_context(command: str, pos: int) -> str:
    """Get the text before position pos for context analysis."""
    return command[:pos].rstrip()


def is_safe_wrapper_arg(command: str, region_start: int) -> bool:
    """Check if a quoted region is an argument to a safe wrapper command.

    Looks at the command context before the quoted string to determine
    if it's an argument to echo, printf, grep, git commit -m, etc.
    """
    preceding = _preceding_context(command, region_start)

    # Check for data flags (-m, --message, --notes, --body, --title)
    for flag in _DATA_FLAGS:
        if preceding.endswith(flag):
            return True

    # Check for variable assignment: VAR="value"
    if _VAR_ASSIGNMENT.search(preceding):
        return True

    # Get the first word of the current command segment
    # Split on command separators to find the current segment
    segment_start = 0
    for sep in [' && ', ' || ', '; ']:
        last = preceding.rfind(sep)
        if last >= 0:
            segment_start = max(segment_start, last + len(sep))

    # Also check pipe (but pipe to bash/sh is a bridge, handled elsewhere)
    pipe_pos = preceding.rfind(' | ')
    if pipe_pos >= 0:
        segment_start = max(segment_start, pipe_pos + 3)

    segment = preceding[segment_start:].strip()
    first_word = segment.split()[0] if segment.split() else ""

    # Strip path prefix from first word
    if '/' in first_word:
        first_word = first_word.rsplit('/', 1)[-1]

    return first_word in _SAFE_WRAPPERS


def get_effective_command(command: str) -> str:
    """Return command with safe quoted strings and comments replaced by spaces.

    This is the "effective" command text where patterns should be matched.
    Safe quoted regions (echo args, grep patterns, git -m messages, etc.)
    are blanked out. Execution bridge arguments are preserved.
    """
    quoted = find_quoted_regions(command)
    comment_start = find_comment_start(command, quoted)

    # Build list of regions to blank
    blank_regions = []

    for start, end, quote in quoted:
        # Skip quoted regions that are after a comment
        if comment_start is not None and start >= comment_start:
            continue
        # Only blank if this is an argument to a safe wrapper
        if not is_safe_wrapper_arg(command, start):
            continue
        # A double-quoted region with a shell expansion runs or interpolates at
        # runtime, so it is not inert data — leave it intact for the tier rules.
        # Single quotes never expand, so they are still safe to blank.
        if quote == '"' and _has_expansion(command[start:end]):
            continue
        blank_regions.append((start, end))

    # Blank comment region
    if comment_start is not None:
        blank_regions.append((comment_start, len(command)))

    if not blank_regions:
        return command

    # Sort by start position and apply blanking
    blank_regions.sort()
    result = list(command)
    for start, end in blank_regions:
        for i in range(start, min(end, len(result))):
            result[i] = ' '

    return ''.join(result)


def check_execution_bridges(command: str) -> tuple[bool, str] | None:
    """Check if the command contains execution bridges with dangerous content.

    Returns (is_dangerous, reason) if a bridge with dangerous content is found,
    or None if no dangerous bridge detected.
    """
    # Pipe to shell: always dangerous (we can't know what's piped)
    if _PIPE_TO_SHELL.search(command):
        return (True, "Piping output to a shell interpreter executes arbitrary code.")

    # Process substitution with download: shell <(curl/wget ...) executes remote code
    if _PROCESS_SUB_DOWNLOAD.search(command):
        return (True, "Process substitution with network download executes arbitrary remote code.")

    # Check inline interpreters for language-specific destructive patterns
    for match in _INTERPRETER_BRIDGE.finditer(command):
        # Extract the argument (next quoted string or word)
        after = command[match.end():]
        arg = _extract_argument(after)
        if arg:
            for pattern in _LANG_DESTRUCTIVE:
                if pattern.search(arg):
                    return (True,
                            f"Destructive operation detected in inline script: {arg[:60]}")

    return None


def _extract_argument(text: str) -> str | None:
    """Extract a quoted or unquoted argument from the start of text."""
    text = text.lstrip()
    if not text:
        return None

    if text[0] in ('"', "'"):
        quote = text[0]
        end = text.find(quote, 1)
        if end >= 0:
            return text[1:end]
        return text[1:]

    # Unquoted: take until whitespace
    end = 0
    while end < len(text) and text[end] not in ' \t;|&':
        end += 1
    return text[:end] if end > 0 else None
