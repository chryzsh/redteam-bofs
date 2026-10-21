import os
import re
from dataclasses import dataclass
from typing import List, Tuple

from outflank_stage1.implant.enums import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))

# OC2's argv tokenizer is quote-respecting but quote-preserving: if the operator
# types `--program-args "/z C:\foo"` the value the wrapper receives still has the
# literal outer `"` characters around it. Passed verbatim to put_Arguments() that
# turns into a single quoted argv[1] (msiexec etc. then ignore the embedded
# switch). We strip one layer of matching outer quotes everywhere a string value
# comes in. This also collapses `""` / `''` placeholders to empty strings, which
# the legacy CNA syntax relied on.
TRIGGER_TYPES = {"onetime", "daily", "logon", "startup", "lock", "unlock"}
CONTEXT_TYPES = ["current", "current+", "creds", "creds+", "system"]
WINDOWS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|%[^%]+%[\\/]|\.{1,2}[\\/])")
TASK_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
TASK_DELAY_RE = re.compile(r"^P(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedArguments:
    task_name: str
    host_name: str
    program_path: str
    program_arguments: str
    trigger_type: str
    start_time: str = ""
    expire_time: str = ""
    days_interval: int = 0
    delay: str = ""
    user_id: str = ""
    repeat_task: str = ""
    context_type: str = "current"
    user_name: str = ""
    user_password: str = ""


class AddTaskSchedulerBOF(BaseBOFTask):
    def __init__(self):
        # x64-only: sync-bofs.sh cross-compiles addtaskscheduler.x64.o only.
        super().__init__(
            "addtaskscheduler",
            base_binary_name="addtaskscheduler",
            supported_architectures=[ImplantArch.INTEL_X64],
        )
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Create a scheduled task on the current system or a remote host. "
            "Use --host and --program-args in OC2 to avoid empty placeholder parsing issues."
        )

        # Keep the argparse surface permissive; the BOF-specific parser below handles the
        # legacy CNA-style positional format plus the safer OC2 flag-based format.
        self.parser.add_argument(
            "arguments",
            nargs="*",
            help="Task name, program path, trigger type, and optional trigger arguments",
        )
        self.parser.add_argument(
            "--host",
            default=None,
            help="Remote host FQDN. Omit for the current system.",
        )
        self.parser.add_argument(
            "--program-args",
            dest="program_args",
            default=None,
            help="Arguments passed to the scheduled program.",
        )
        self.parser.add_argument(
            "--start-time",
            default=None,
            help="Trigger start time in format 2023-03-24T12:08:00.",
        )
        self.parser.add_argument(
            "--expire-time",
            default=None,
            help="Daily trigger expiration time in format 2023-03-24T12:08:00.",
        )
        self.parser.add_argument(
            "--days-interval",
            type=int,
            default=None,
            help="Daily trigger interval in days.",
        )
        self.parser.add_argument(
            "--delay",
            default=None,
            help="Trigger delay in Task Scheduler ISO-8601 format such as PT5M or PT2H.",
        )
        self.parser.add_argument(
            "--user-id",
            default=None,
            help="User for logon/lock/unlock triggers. Omit for all users/current context.",
        )
        self.parser.add_argument(
            "--repeat-task",
            default=None,
            help='One-time trigger repetition interval, for example "PT2H".',
        )
        self.parser.add_argument(
            "--context",
            choices=CONTEXT_TYPES,
            default="current",
            help=(
                "Account the task runs as. current: current user, only while logged on. "
                "current+: same, highest privileges. creds/creds+: --username/--password, "
                "whether logged on or not (+ = highest privileges). system: SYSTEM. Default: current."
            ),
        )
        self.parser.add_argument(
            "--username",
            default=None,
            help="Account for --context creds/creds+, e.g. example.local\\john.",
        )
        self.parser.add_argument(
            "--password",
            default=None,
            help="Plaintext password for --username.",
        )

        self.parser.epilog = (
            "Recommended OC2 syntax:\n"
            "  addtaskscheduler <taskName> <programPath> <triggerType> [trigger args] [--host HOST] [--program-args ARGS] [--context CONTEXT]\n\n"
            "Examples:\n"
            "  system:   addtaskscheduler Updater C:\\Windows\\System32\\cmd.exe startup --program-args \"/c calc.exe\" --delay PT5M --context system\n"
            "  creds:    addtaskscheduler Updater C:\\Data\\app.exe logon --context creds --username example.local\\john --password Welcome01\n"
            "  onetime:  addtaskscheduler TestTask C:\\Windows\\System32\\cmd.exe onetime --program-args \"/c calc.exe\" --start-time 2023-03-24T12:08:00 --repeat-task PT2H\n"
            "  daily:    addtaskscheduler TestTask C:\\Windows\\System32\\cmd.exe daily --start-time 2023-03-24T12:08:00 --expire-time 2023-03-28T12:14:00 --days-interval 1 --delay PT2H\n"
            "  logon:    addtaskscheduler NewTask C:\\Users\\Public\\legit.exe logon --host DB01.example.local --user-id Testdomain\\Administrator\n"
            "  startup:  addtaskscheduler OneDrive C:\\Data\\OneDrive.exe startup --delay PT5M\n"
            "  lock:     addtaskscheduler LockTask C:\\Windows\\System32\\cmd.exe lock --delay PT5M\n"
            "  unlock:   addtaskscheduler OneDrive C:\\Data\\OneDrive.exe unlock --user-id Testdomain\\Administrator --delay PT5M\n\n"
            "Legacy CNA-style positional syntax is still supported when it is unambiguous."
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parsed_arguments = self._parse_arguments(arguments)

        if not parsed_arguments.task_name:
            raise TaskInvalidArgumentsException("Please specify a name for the new scheduled task.")

        if not parsed_arguments.program_path:
            raise TaskInvalidArgumentsException("Please specify the path to the program that you want to run.")

        if parsed_arguments.trigger_type in {"onetime", "daily"} and not parsed_arguments.start_time:
            raise TaskInvalidArgumentsException(
                f"The '{parsed_arguments.trigger_type}' trigger requires a start time in format: 2023-03-24T12:08:00"
            )

        if parsed_arguments.days_interval < 0:
            raise TaskInvalidArgumentsException("days-interval must be zero or a positive integer.")

        if parsed_arguments.context_type in {"creds", "creds+"}:
            if not parsed_arguments.user_name or not parsed_arguments.user_password:
                raise TaskInvalidArgumentsException(
                    f"--context {parsed_arguments.context_type} requires --username and --password."
                )
        elif parsed_arguments.user_name or parsed_arguments.user_password:
            raise TaskInvalidArgumentsException(
                "--username/--password only apply to --context creds or creds+."
            )

    def run(self, arguments: List[str]):
        parsed_arguments = self._parse_arguments(arguments)
        target = parsed_arguments.host_name if parsed_arguments.host_name else "local system"

        self.append_response(
            f"[*] Creating scheduled task '{parsed_arguments.task_name}' "
            f"on {target} (trigger: {parsed_arguments.trigger_type}, context: {parsed_arguments.context_type})\n"
        )
        super().run(arguments)

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parsed_arguments = self._parse_arguments(arguments)

        # Cobalt Strike bof_pack formats (upstream added contextType and userName/userPassword):
        # onetime: ZZzZZzZZZZ
        # daily:   ZZzZZzZZiZZZ
        # logon:   ZZzZZzZZZ
        # startup: ZZzZZzZZZ
        # lock:    ZZzZZzZZZZ
        # unlock:  ZZzZZzZZZZ
        base_args = [
            (BOFArgumentEncoding.WSTR, parsed_arguments.task_name),
            (BOFArgumentEncoding.WSTR, parsed_arguments.host_name),
            (BOFArgumentEncoding.STR, parsed_arguments.context_type),
            (BOFArgumentEncoding.WSTR, parsed_arguments.program_path),
            (BOFArgumentEncoding.WSTR, parsed_arguments.program_arguments),
            (BOFArgumentEncoding.STR, parsed_arguments.trigger_type),
        ]
        cred_args = [
            (BOFArgumentEncoding.WSTR, parsed_arguments.user_name),
            (BOFArgumentEncoding.WSTR, parsed_arguments.user_password),
        ]

        if parsed_arguments.trigger_type == "onetime":
            return base_args + [
                (BOFArgumentEncoding.WSTR, parsed_arguments.start_time),
                (BOFArgumentEncoding.WSTR, parsed_arguments.repeat_task),
            ] + cred_args

        if parsed_arguments.trigger_type == "daily":
            return base_args + [
                (BOFArgumentEncoding.WSTR, parsed_arguments.start_time),
                (BOFArgumentEncoding.WSTR, parsed_arguments.expire_time),
                (BOFArgumentEncoding.INT, parsed_arguments.days_interval),
                (BOFArgumentEncoding.WSTR, parsed_arguments.delay),
            ] + cred_args

        if parsed_arguments.trigger_type == "logon":
            return base_args + [
                (BOFArgumentEncoding.WSTR, parsed_arguments.user_id),
            ] + cred_args

        if parsed_arguments.trigger_type == "startup":
            return base_args + [
                (BOFArgumentEncoding.WSTR, parsed_arguments.delay),
            ] + cred_args

        if parsed_arguments.trigger_type in {"lock", "unlock"}:
            return base_args + [
                (BOFArgumentEncoding.WSTR, parsed_arguments.user_id),
                (BOFArgumentEncoding.WSTR, parsed_arguments.delay),
            ] + cred_args

        return base_args + cred_args

    def _parse_arguments(self, arguments: List[str]) -> ParsedArguments:
        parser_arguments = self.parser.parse_args(arguments)

        raw_tokens = [self._strip_outer_quotes(token) for token in parser_arguments.arguments]
        parser_arguments.arguments = raw_tokens
        for attr in (
            "host", "program_args", "start_time", "expire_time",
            "delay", "user_id", "repeat_task", "username", "password",
        ):
            value = getattr(parser_arguments, attr, None)
            if isinstance(value, str):
                setattr(parser_arguments, attr, self._strip_outer_quotes(value))

        if len(raw_tokens) < 3:
            raise TaskInvalidArgumentsException(
                "Not enough arguments. Recommended syntax: "
                "addtaskscheduler <taskName> <programPath> <triggerType> [trigger args] "
                "[--host HOST] [--program-args ARGS]"
            )

        if len(raw_tokens) >= 3 and raw_tokens[2] in TRIGGER_TYPES:
            return self._parse_oc2_style(raw_tokens, parser_arguments)

        return self._parse_legacy_style(raw_tokens, parser_arguments)

    def _parse_oc2_style(self, raw_tokens: List[str], parser_arguments) -> ParsedArguments:
        task_name = raw_tokens[0]
        program_path = raw_tokens[1]
        trigger_type = raw_tokens[2]

        if trigger_type not in TRIGGER_TYPES:
            raise TaskInvalidArgumentsException(
                "Please specify one of the following trigger options: onetime | daily | logon | startup | lock | unlock"
            )

        return self._build_parsed_arguments(
            task_name=task_name,
            host_name=parser_arguments.host or "",
            program_path=program_path,
            program_arguments=parser_arguments.program_args or "",
            trigger_type=trigger_type,
            trigger_tokens=raw_tokens[3:],
            parser_arguments=parser_arguments,
        )

    def _parse_legacy_style(self, raw_tokens: List[str], parser_arguments) -> ParsedArguments:
        trigger_index = self._find_trigger_index(raw_tokens)
        task_name = raw_tokens[0]
        trigger_type = raw_tokens[trigger_index]
        core_tokens = raw_tokens[1:trigger_index]

        host_name, program_path, program_arguments = self._resolve_core_arguments(
            core_tokens,
            parser_arguments.host,
            parser_arguments.program_args,
        )

        return self._build_parsed_arguments(
            task_name=task_name,
            host_name=host_name,
            program_path=program_path,
            program_arguments=program_arguments,
            trigger_type=trigger_type,
            trigger_tokens=raw_tokens[trigger_index + 1:],
            parser_arguments=parser_arguments,
        )

    def _build_parsed_arguments(
        self,
        task_name: str,
        host_name: str,
        program_path: str,
        program_arguments: str,
        trigger_type: str,
        trigger_tokens: List[str],
        parser_arguments,
    ) -> ParsedArguments:
        self._validate_flag_compatibility(trigger_type, parser_arguments)

        trigger_values = self._resolve_trigger_arguments(trigger_type, trigger_tokens, parser_arguments)

        return ParsedArguments(
            task_name=task_name,
            host_name=host_name,
            program_path=program_path,
            program_arguments=program_arguments,
            trigger_type=trigger_type,
            context_type=parser_arguments.context,
            user_name=parser_arguments.username or "",
            user_password=parser_arguments.password or "",
            **trigger_values,
        )

    def _find_trigger_index(self, raw_tokens: List[str]) -> int:
        candidates = []

        for index, token in enumerate(raw_tokens[1:], start=1):
            if token not in TRIGGER_TYPES:
                continue

            core_count = index - 1
            trigger_arg_count = len(raw_tokens) - index - 1

            if 1 <= core_count <= 3 and trigger_arg_count <= self._max_trigger_tokens(token):
                candidates.append(index)

        if not candidates:
            raise TaskInvalidArgumentsException(
                "Unable to locate a supported trigger type in the command. "
                "Use onetime, daily, logon, startup, lock, or unlock."
            )

        return candidates[-1]

    def _resolve_core_arguments(
        self,
        core_tokens: List[str],
        host_override: str,
        program_args_override: str,
    ) -> Tuple[str, str, str]:
        if not 1 <= len(core_tokens) <= 3:
            raise TaskInvalidArgumentsException(
                "Unable to determine host, program path, and program arguments from the provided positional arguments."
            )

        candidates = []

        if len(core_tokens) == 1:
            candidates.append(("", core_tokens[0], ""))
        elif len(core_tokens) == 2:
            candidates.extend(
                [
                    ("", core_tokens[0], core_tokens[1]),
                    (core_tokens[0], core_tokens[1], ""),
                ]
            )
            if core_tokens[0] == "":
                candidates.append(("", core_tokens[1], ""))
            if core_tokens[1] == "":
                candidates.append(("", core_tokens[0], ""))
        else:
            candidates.append((core_tokens[0], core_tokens[1], core_tokens[2]))
            if core_tokens[0] == "":
                candidates.append(("", core_tokens[1], core_tokens[2]))
            if core_tokens[2] == "":
                candidates.append((core_tokens[0], core_tokens[1], ""))
            if core_tokens[0] == "" and core_tokens[2] == "":
                candidates.append(("", core_tokens[1], ""))

        unique_candidates = []
        seen = set()
        for host_name, program_path, program_arguments in candidates:
            final_host_name = host_override if host_override is not None else host_name
            final_program_arguments = program_args_override if program_args_override is not None else program_arguments
            final_candidate = (final_host_name, program_path, final_program_arguments)

            if host_override is not None and host_name not in {"", host_override}:
                continue

            if program_args_override is not None and program_arguments not in {"", program_args_override}:
                continue

            if final_candidate not in seen:
                seen.add(final_candidate)
                unique_candidates.append(final_candidate)

        if not unique_candidates:
            raise TaskInvalidArgumentsException(
                "The provided positional arguments conflict with --host or --program-args."
            )

        ranked_candidates = sorted(
            unique_candidates,
            key=lambda candidate: self._score_core_candidate(*candidate),
            reverse=True,
        )

        if len(ranked_candidates) > 1:
            best_score = self._score_core_candidate(*ranked_candidates[0])
            runner_up_score = self._score_core_candidate(*ranked_candidates[1])

            if best_score == runner_up_score:
                raise TaskInvalidArgumentsException(
                    "Ambiguous positional arguments. Use the safer OC2 syntax with "
                    "--host and/or --program-args to disambiguate."
                )

        return ranked_candidates[0]

    def _score_core_candidate(self, host_name: str, program_path: str, program_arguments: str) -> int:
        score = 0

        if not host_name:
            score += 2
        elif self._looks_like_path(host_name):
            score -= 4
        else:
            score += 2

        if self._looks_like_path(program_path):
            score += 4
        elif program_path:
            score += 1

        if not program_arguments:
            score += 1
        elif self._looks_like_program_arguments(program_arguments):
            score += 2
        elif self._looks_like_path(program_arguments):
            score += 1

        return score

    def _resolve_trigger_arguments(self, trigger_type: str, trigger_tokens: List[str], parser_arguments) -> dict:
        if len(trigger_tokens) > self._max_trigger_tokens(trigger_type):
            raise TaskInvalidArgumentsException(
                f"Too many trigger-specific arguments provided for '{trigger_type}'."
            )

        if trigger_type == "onetime":
            start_time = parser_arguments.start_time or ""
            repeat_task = parser_arguments.repeat_task or ""
            remaining = list(trigger_tokens)

            if not start_time and remaining:
                start_time = remaining.pop(0)
            if not repeat_task and remaining:
                repeat_task = remaining.pop(0)

            if remaining:
                raise TaskInvalidArgumentsException("Too many one-time trigger arguments were provided.")

            return {
                "start_time": start_time,
                "repeat_task": repeat_task,
            }

        if trigger_type == "daily":
            start_time = parser_arguments.start_time or ""
            expire_time = parser_arguments.expire_time or ""
            days_interval = parser_arguments.days_interval if parser_arguments.days_interval is not None else 0
            delay = parser_arguments.delay or ""
            remaining = list(trigger_tokens)

            if not start_time and remaining:
                start_time = remaining.pop(0)

            for token in remaining:
                if not expire_time and self._looks_like_task_time(token):
                    expire_time = token
                    continue

                if parser_arguments.days_interval is None and days_interval == 0:
                    try:
                        days_interval = int(token)
                        continue
                    except ValueError:
                        pass

                if not delay and self._looks_like_delay(token):
                    delay = token
                    continue

                if not expire_time:
                    expire_time = token
                    continue

                if not delay:
                    delay = token
                    continue

                raise TaskInvalidArgumentsException("Too many daily trigger arguments were provided.")

            return {
                "start_time": start_time,
                "expire_time": expire_time,
                "days_interval": days_interval,
                "delay": delay,
            }

        if trigger_type == "logon":
            user_id = parser_arguments.user_id or ""
            remaining = list(trigger_tokens)

            if not user_id and remaining:
                user_id = remaining.pop(0)

            if remaining:
                raise TaskInvalidArgumentsException("Too many logon trigger arguments were provided.")

            return {
                "user_id": user_id,
            }

        if trigger_type == "startup":
            delay = parser_arguments.delay or ""
            remaining = list(trigger_tokens)

            if not delay and remaining:
                delay = remaining.pop(0)

            if remaining:
                raise TaskInvalidArgumentsException("Too many startup trigger arguments were provided.")

            return {
                "delay": delay,
            }

        if trigger_type in {"lock", "unlock"}:
            user_id = parser_arguments.user_id or ""
            delay = parser_arguments.delay or ""
            remaining = list(trigger_tokens)

            if not user_id and not delay and len(remaining) == 1:
                if self._looks_like_delay(remaining[0]):
                    delay = remaining.pop(0)
                else:
                    user_id = remaining.pop(0)

            if not user_id and remaining:
                user_id = remaining.pop(0)
            if not delay and remaining:
                delay = remaining.pop(0)

            if remaining:
                raise TaskInvalidArgumentsException(f"Too many {trigger_type} trigger arguments were provided.")

            return {
                "user_id": user_id,
                "delay": delay,
            }

        raise TaskInvalidArgumentsException(
            "Specified triggerType is not supported. Use onetime, daily, logon, startup, lock, or unlock."
        )

    def _validate_flag_compatibility(self, trigger_type: str, parser_arguments):
        allowed_fields = {
            "onetime": {"start_time", "repeat_task"},
            "daily": {"start_time", "expire_time", "days_interval", "delay"},
            "logon": {"user_id"},
            "startup": {"delay"},
            "lock": {"user_id", "delay"},
            "unlock": {"user_id", "delay"},
        }[trigger_type]

        provided_fields = {
            "start_time": parser_arguments.start_time is not None,
            "expire_time": parser_arguments.expire_time is not None,
            "days_interval": parser_arguments.days_interval is not None,
            "delay": parser_arguments.delay is not None,
            "user_id": parser_arguments.user_id is not None,
            "repeat_task": parser_arguments.repeat_task is not None,
        }

        invalid_fields = [
            field_name.replace("_", "-")
            for field_name, is_provided in provided_fields.items()
            if is_provided and field_name not in allowed_fields
        ]

        if invalid_fields:
            invalid_flags = ", ".join(f"--{field_name}" for field_name in sorted(invalid_fields))
            raise TaskInvalidArgumentsException(
                f"{invalid_flags} cannot be used with the '{trigger_type}' trigger."
            )

    def _max_trigger_tokens(self, trigger_type: str) -> int:
        return {
            "onetime": 2,
            "daily": 4,
            "logon": 1,
            "startup": 1,
            "lock": 2,
            "unlock": 2,
        }[trigger_type]

    def _looks_like_path(self, value: str) -> bool:
        return bool(value) and (
            bool(WINDOWS_PATH_RE.match(value))
            or value.lower().endswith((".exe", ".com", ".cmd", ".bat", ".ps1", ".dll", ".msi"))
        )

    def _looks_like_program_arguments(self, value: str) -> bool:
        return bool(value) and (
            value.startswith("/")
            or value.startswith("-")
            or " " in value
            or self._looks_like_delay(value)
        )

    def _looks_like_task_time(self, value: str) -> bool:
        return bool(TASK_TIME_RE.match(value))

    def _looks_like_delay(self, value: str) -> bool:
        return bool(TASK_DELAY_RE.match(value))

    def _strip_outer_quotes(self, value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            return value[1:-1]
        return value
