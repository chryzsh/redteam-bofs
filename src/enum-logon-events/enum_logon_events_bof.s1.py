from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


LOGON_TYPE_ALIASES = {
    "interactive": 2,
    "console": 2,
    "network": 3,
    "smb": 3,
    "batch": 4,
    "service": 5,
    "unlock": 7,
    "cleartext": 8,
    "networkcleartext": 8,
    "newcreds": 9,
    "newcredentials": 9,
    "runas": 9,
    "rdp": 10,
    "remote": 10,
    "remoteinteractive": 10,
    "cached": 11,
    "cachedinteractive": 11,
    "cachedremote": 12,
    "cachedunlock": 13,
}

VALID_LOGON_TYPES = {2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13}


def parse_logon_type(value: str) -> int:
    text = value.strip().lower()
    if text in ("", "all", "any", "0"):
        return 0
    if text in LOGON_TYPE_ALIASES:
        return LOGON_TYPE_ALIASES[text]
    try:
        number = int(text)
    except ValueError:
        raise TaskInvalidArgumentsException(
            f"Invalid logon type '{value}'. Use a number (2-13) or one of: "
            f"{', '.join(sorted(LOGON_TYPE_ALIASES))}"
        )
    if number not in VALID_LOGON_TYPES:
        raise TaskInvalidArgumentsException(
            f"Invalid logon type {number}. Valid: {', '.join(str(t) for t in sorted(VALID_LOGON_TYPES))}"
        )
    return number


class EnumLogonEventsBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("enum-logon-events", base_binary_name="enum-logon-events")

        self.parser.description = (
            "Enumerate Windows Security Event Log Event ID 4624 (successful logon events). "
            "Identifies lateral movement patterns, authentication methods, and logon sources. "
            "Requires administrator privileges to access the Security event log."
        )

        self.parser.add_argument(
            "--days",
            "-d",
            type=int,
            default=7,
            help="Number of days to query (1-30, default: 7)"
        )

        self.parser.add_argument(
            "--max-events",
            "-m",
            type=int,
            default=500,
            help="Maximum number of events to display (10-5000, default: 500)"
        )

        self.parser.add_argument(
            "--logon-type",
            "-t",
            default="all",
            help=(
                "Only show one logon type: a number (2-13) or an alias such as "
                "rdp (10), network (3), interactive (2), runas (9), cached (11). "
                "Default: all"
            )
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  enum-logon-events                            # Last 7 days, max 500 events\n"
            "  enum-logon-events --days 1                   # Last 24 hours\n"
            "  enum-logon-events --days 30 --max-events 1000 # Last 30 days, up to 1000 events\n"
            "  enum-logon-events -d 3 -m 200               # Last 3 days, max 200 events\n"
            "  enum-logon-events --logon-type rdp           # RDP logons only (type 10)\n"
            "  enum-logon-events -t 3 -d 1                  # Network logons in the last 24 hours\n\n"
            "Event Information Displayed:\n"
            "  - Timestamp (local time)\n"
            "  - Logon type (Interactive, Network, RemoteInteractive, etc.)\n"
            "  - Target user (who logged in)\n"
            "  - Source IP address (for network/remote logons)\n"
            "  - Authentication method (NTLM v1, NTLM v2, Kerberos)\n\n"
            "Logon Types (number, alias):\n"
            "  - 2  interactive:  Local keyboard/console logon\n"
            "  - 3  network:      SMB, network share access\n"
            "  - 4  batch:        Scheduled task\n"
            "  - 5  service:      Windows service startup\n"
            "  - 7  unlock:       Workstation unlock\n"
            "  - 8  cleartext:    Network logon with cleartext password (IIS basic auth)\n"
            "  - 9  runas:        NewCredentials (runas /netonly)\n"
            "  - 10 rdp:          RemoteInteractive (RDP)\n"
            "  - 11 cached:       CachedInteractive (offline domain logon)\n"
            "  - 12 cachedremote, 13 cachedunlock\n\n"
            "Notes:\n"
            "  - --max-events caps displayed events; the BOF stops after scanning 20000\n"
            "    events regardless, so narrow with --days or --logon-type on busy servers\n"
            "  - The logon type goes into the XPath query, so the event log service does\n"
            "    the filtering and the beacon only renders matching events\n\n"
            "Filtered Accounts (not displayed):\n"
            "  - SYSTEM, LOCAL SERVICE, NETWORK SERVICE\n"
            "  - Computer accounts (ending with $)\n"
            "  - ANONYMOUS LOGON\n"
            "  - UMFD-X, DWM-X accounts\n\n"
            "Security Notes:\n"
            "  - NTLM v1 indicates weak authentication (can be cracked)\n"
            "  - Network logons show lateral movement patterns\n"
            "  - Source IPs identify authentication sources\n\n"
            "Requirements:\n"
            "  - Administrator privileges (Security log access)\n"
            "  - Event ID 4624 must be enabled in audit policy\n\n"
            "OPSEC Considerations:\n"
            "  - Read-only operation on Security event log\n"
            "  - Same access as Event Viewer or Get-WinEvent\n"
            "  - Security log access may be audited (Event ID 4663)\n"
            "  - Execution time depends on event count (up to 5-10 seconds for 500 events)\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        parser_arguments = self.parser.parse_args(arguments)

        # Validate days
        if parser_arguments.days < 1 or parser_arguments.days > 30:
            raise TaskInvalidArgumentsException(
                f"Invalid days value: {parser_arguments.days}. Must be between 1 and 30."
            )

        # Validate max_events
        if parser_arguments.max_events < 10 or parser_arguments.max_events > 5000:
            raise TaskInvalidArgumentsException(
                f"Invalid max-events value: {parser_arguments.max_events}. Must be between 10 and 5000."
            )

        # Raises TaskInvalidArgumentsException on a bad value
        parse_logon_type(parser_arguments.logon_type)

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # BOF expects: iii (INT days, INT maxEvents, INT logonType; 0 = all)
        return [
            (BOFArgumentEncoding.INT, parser_arguments.days),
            (BOFArgumentEncoding.INT, parser_arguments.max_events),
            (BOFArgumentEncoding.INT, parse_logon_type(parser_arguments.logon_type)),
        ]
