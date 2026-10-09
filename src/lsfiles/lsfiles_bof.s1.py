from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class LsfilesBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("lsfiles", base_binary_name="lsfiles")

        self.parser.description = (
            "Enumerate files in a directory with wildcard pattern support. "
            "Supports wildcards in both paths and filenames. "
            "Lists only the target directory by default; use -r to recurse. "
            "Can optionally include directory entries in output. "
            "Streams output as files are discovered and provides summary statistics."
        )

        # Positional argument: target directory (supports wildcards)
        self.parser.add_argument(
            "path",
            help="Target directory path to enumerate. Supports wildcards (e.g., C:\\Users, C:\\Users\\*, C:\\Windows\\System32)"
        )

        # Optional arguments
        self.parser.add_argument(
            "--pattern",
            "-p",
            default="*",
            help="Wildcard pattern to filter files (e.g., *.exe, *.log, *.txt). Default: * (all files)"
        )

        self.parser.add_argument(
            "--exclude",
            "-e",
            action="append",
            dest="exclude_patterns",
            metavar="PATTERN",
            help="Exclude files matching pattern. Can be used multiple times (e.g., --exclude *.tmp --exclude *.log)"
        )

        self.parser.add_argument(
            "--exclude-path",
            action="append",
            dest="exclude_path_patterns",
            metavar="PATH_PATTERN",
            help="Exclude full paths matching pattern and skip recursing into matching directories"
        )

        self.parser.add_argument(
            "--recursive",
            "-r",
            action="store_true",
            help="Recurse into subdirectories (default: current directory only)"
        )

        self.parser.add_argument(
            "--max-depth",
            "-d",
            type=int,
            default=None,
            metavar="DEPTH",
            help="Maximum recursion depth (-1 for unlimited). Implies -r. Default: 0 (current directory only)"
        )

        self.parser.add_argument(
            "--max-results",
            "-mr",
            type=int,
            default=1000,
            metavar="COUNT",
            help="Maximum number of results to return (files, plus directories when --include-dirs is used). Use -1 for unlimited. Default: 1000"
        )

        self.parser.add_argument(
            "--include-dirs",
            "--dirs",
            action="store_true",
            help="Include directory entries in output (directories are still traversed for recursion regardless)"
        )

        self.parser.add_argument(
            "--date-filter",
            "-df",
            default="",
            metavar="DATE",
            help="Filter files by modification date. Formats: YYYY, YYYY-MM, or YYYY-MM-DD (e.g., 2025, 2025-11, 2025-11-13)"
        )

        self.parser.add_argument(
            "--min-size",
            "-mins",
            type=int,
            default=-1,
            metavar="BYTES",
            help="Minimum file size in bytes. Use -1 for no minimum. Default: -1"
        )

        self.parser.add_argument(
            "--max-size",
            "-maxs",
            type=int,
            default=-1,
            metavar="BYTES",
            help="Maximum file size in bytes. Use -1 for no maximum. Default: -1"
        )

        self.parser.add_argument(
            "--suppress-errors",
            "-s",
            action="store_true",
            help="Suppress error messages for access denied or other file system errors"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  lsfiles C:\\Users\\target\\Desktop\n"
            "  lsfiles C:\\Users -r --pattern *.zip\n"
            "  lsfiles C:\\Users\\* --pattern *.zip\n"
            "  lsfiles C:\\Windows -r --pattern *.exe\n"
            "  lsfiles C:\\Temp --pattern *.log --suppress-errors\n"
            "  lsfiles \"C:\\Program Files\" --pattern *.dll --max-depth 2\n"
            "  lsfiles C:\\Users\\*\\Downloads --pattern *.exe --date-filter 2025\n"
            "  lsfiles C:\\Windows\\*\\config --pattern *.ini --date-filter 2025-11\n"
            "  lsfiles C:\\Temp --pattern * --date-filter 2025-11-13\n"
            "  lsfiles C:\\Users --pattern *.zip --min-size 1048576\n"
            "  lsfiles C:\\Temp --pattern *.log --max-size 1024\n"
            "  lsfiles C:\\Repo -r --exclude-path *\\\\.git\\\\*\n"
            "  lsfiles \\\\test\\dept --include-dirs\n\n"
            "Path wildcards:\n"
            "  * - Matches any directory name (e.g., C:\\Users\\* searches all user dirs)\n"
            "  ? - Matches any single character in directory name\n"
            "  Examples: C:\\Users\\*, C:\\Windows\\System??\\, C:\\*\\Temp\n\n"
            "Filename pattern wildcards:\n"
            "  * - Matches any sequence of characters\n"
            "  ? - Matches any single character\n"
            "  Examples: *.exe, test*.log, file?.txt, *report*.pdf\n\n"
            "Notes:\n"
            "  - BOF streams output as files are discovered (not batch mode)\n"
            "  - Path wildcards are expanded before recursive enumeration\n"
            "  - File timestamps are converted to local system time\n"
            "  - Summary includes total files found, optional directory count, total size, and error count\n"
            "  - Large directories may produce significant output\n"
            "  - Use --suppress-errors to reduce noise in heavily restricted areas\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        # Validate path is not empty
        if not parser_arguments.path or parser_arguments.path.strip() == "":
            raise TaskInvalidArgumentsException("Path cannot be empty")

        # Validate pattern is not empty
        if not parser_arguments.pattern or parser_arguments.pattern.strip() == "":
            raise TaskInvalidArgumentsException("Pattern cannot be empty. Use '*' for all files.")

        # Validate max depth
        if parser_arguments.max_depth is not None and parser_arguments.max_depth < -1:
            raise TaskInvalidArgumentsException(
                f"Invalid max-depth: {parser_arguments.max_depth}. Must be -1 (unlimited) or >= 0."
            )

        # Validate max results
        if parser_arguments.max_results < -1:
            raise TaskInvalidArgumentsException(
                f"Invalid max-results: {parser_arguments.max_results}. Must be -1 (unlimited) or >= 0."
            )

        # Validate min size
        if parser_arguments.min_size < -1:
            raise TaskInvalidArgumentsException(
                f"Invalid min-size: {parser_arguments.min_size}. Must be -1 (no minimum) or >= 0."
            )

        # Validate max size
        if parser_arguments.max_size < -1:
            raise TaskInvalidArgumentsException(
                f"Invalid max-size: {parser_arguments.max_size}. Must be -1 (no maximum) or >= 0."
            )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # Extract arguments — strip surrounding quotes that OC2 may pass through
        target_path = parser_arguments.path.strip('"').strip("'")
        pattern = parser_arguments.pattern if parser_arguments.pattern else "*"

        # Build pipe-delimited exclude patterns string
        exclude_patterns = ""
        if parser_arguments.exclude_patterns:
            exclude_patterns = "|".join(parser_arguments.exclude_patterns)

        suppress_errors = 1 if parser_arguments.suppress_errors else 0
        max_results = parser_arguments.max_results
        include_dirs = 1 if parser_arguments.include_dirs else 0
        exclude_path_patterns = ""
        if parser_arguments.exclude_path_patterns:
            exclude_path_patterns = "|".join(parser_arguments.exclude_path_patterns)

        # Resolve recursion: -d implies recursion; -r without -d means unlimited
        if parser_arguments.max_depth is not None:
            # -d was explicitly set, use it as-is (implies recursion)
            max_depth = parser_arguments.max_depth
        elif parser_arguments.recursive:
            # -r without explicit -d: unlimited recursion
            max_depth = -1
        else:
            # No -r, no -d: current directory only
            max_depth = 0
        date_filter = parser_arguments.date_filter if parser_arguments.date_filter else ""
        min_size = parser_arguments.min_size
        max_size = parser_arguments.max_size

        # BOF expects: ZZZZiiiiZii
        # (targetPath: wstring, pattern: wstring, excludePatterns: wstring, excludePathPatterns: wstring, suppressErrors: int, maxDepth: int, maxResults: int, includeDirs: int, dateFilter: wstring, minSize: int, maxSize: int)
        return [
            (BOFArgumentEncoding.WSTR, target_path),
            (BOFArgumentEncoding.WSTR, pattern),
            (BOFArgumentEncoding.WSTR, exclude_patterns),
            (BOFArgumentEncoding.WSTR, exclude_path_patterns),
            (BOFArgumentEncoding.INT, suppress_errors),
            (BOFArgumentEncoding.INT, max_depth),
            (BOFArgumentEncoding.INT, max_results),
            (BOFArgumentEncoding.INT, include_dirs),
            (BOFArgumentEncoding.WSTR, date_filter),
            (BOFArgumentEncoding.INT, min_size),
            (BOFArgumentEncoding.INT, max_size),
        ]
