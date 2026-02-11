# ABOUTME: Context classification for shell commands.
# ABOUTME: Distinguishes executed code from string literals, comments, and safe arguments.
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

# git subcommands where -m/--message arguments are data
_GIT_MESSAGE_FLAGS = {"-m", "--message"}

# Execution bridges: commands that execute their string argument as code
_SHELL_BRIDGES = re.compile(
    r'(?:^|&&|\|\||;)\s*'           # command start
    r'(?:bash|sh|zsh|dash)\s+-c\s+'  # shell -c
)

_EVAL_BRIDGE = re.compile(
    r'(?:^|&&|\|\||;)\s*'  # command start
    r'eval\s+'             # eval
)

# Pipe-to-shell: output piped to a shell interpreter
_PIPE_TO_SHELL = re.compile(
    r'\|\s*(?:bash|sh|zsh|dash)\s*(?:$|;|&&|\|\|)'
)

# Inline interpreter patterns: python -c, ruby -e, perl -e, node -e
_INTERPRETER_BRIDGE = re.compile(
    r'(?:python3?|python2|ruby|perl|node)\s+(?:-c|-e)\s+'
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
    """Find the position of unquoted # (comment start).

    Returns the index of # or None if no comment found.
    """
    for i, ch in enumerate(command):
        if ch == '#':
            # Check if this # is inside any quoted region
            in_quote = any(start <= i < end for start, end, _ in quoted)
            if not in_quote:
                return i
    return None


def _preceding_word(command: str, pos: int) -> str:
    """Get the word immediately before position pos, skipping whitespace."""
    i = pos - 1
    while i >= 0 and command[i] in ' \t':
        i -= 1
    end = i + 1
    while i >= 0 and command[i] not in ' \t;|&':
        i -= 1
    return command[i + 1:end]


def _preceding_context(command: str, pos: int) -> str:
    """Get the text before position pos for context analysis."""
    return command[:pos].rstrip()


def is_safe_wrapper_arg(command: str, region_start: int) -> bool:
    """Check if a quoted region is an argument to a safe wrapper command.

    Looks at the command context before the quoted string to determine
    if it's an argument to echo, printf, grep, git commit -m, etc.
    """
    preceding = _preceding_context(command, region_start)

    # Check for git -m/--message flags
    for flag in _GIT_MESSAGE_FLAGS:
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

    for start, end, _ in quoted:
        # Skip quoted regions that are after a comment
        if comment_start is not None and start >= comment_start:
            continue
        # Only blank if this is an argument to a safe wrapper
        if is_safe_wrapper_arg(command, start):
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
