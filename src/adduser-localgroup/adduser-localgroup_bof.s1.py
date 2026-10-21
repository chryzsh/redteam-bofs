from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


def _unc(computername: str) -> str:
    """
    Strip quotes and prepend a leading \\\\ to the server name if it is
    missing, so operators can type `dc01.corp.local` instead of
    `\\\\dc01.corp.local`. Empty and "." (local computer) pass through.
    """
    name = (computername or "").strip('"').strip("'")
    if name and name != "." and not name.startswith("\\\\"):
        name = "\\\\" + name
    return name


class AdduserLocalgroupBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "adduser-localgroup",
            base_binary_name="adduser-localgroup",
            base_binary_path="."
        )

        self.parser.description = (
            "Add a user (local or domain) to a local group on a computer."
        )

        self.parser.add_argument(
            "groupname",
            help="Local group name. Quote names with spaces (e.g., 'Remote Desktop Users').",
        )

        self.parser.add_argument(
            "username",
            help="User to add - can be local user (e.g., 'john') or domain user (e.g., 'DOMAIN\\john')",
        )

        self.parser.add_argument(
            "computername",
            nargs="?",
            default="",
            help="Target computer name (e.g., 'COMPUTER01'; default: local computer). The leading \\\\ is optional. Omit for local.",
        )

        self.parser.epilog = (
            "adduser-localgroup adds a user to a local group on a Windows computer.\n"
            "The user can be either a local user or a domain user, but the group must be local.\n"
            "The leading \\\\ on the computer name is optional.\n\n"
            "Example usage:\n"
            "  - Add local user to Administrators group:\n"
            "    adduser-localgroup Administrators john\n\n"
            "  - Add domain user to local group:\n"
            "    adduser-localgroup Administrators DOMAIN\\john\n\n"
            "  - Add user on remote computer:\n"
            "    adduser-localgroup 'Remote Desktop Users' john COMPUTER01\n\n"
            "  - Add domain user to remote computer's local group:\n"
            "    adduser-localgroup Administrators CORP\\alice SERVER01\n\n"
            "  - Multi-word group names must be quoted:\n"
            "    adduser-localgroup 'Remote Desktop Users' john COMPUTER01"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        # Encode arguments as wide strings (WSTR) for the BOF
        # Strip surrounding quotes that OC2 may pass through for args with spaces
        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.groupname.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, parser_arguments.username.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, _unc(parser_arguments.computername)),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)

        groupname = parser_arguments.groupname.strip('"').strip("'")
        username = parser_arguments.username.strip('"').strip("'")
        computername = _unc(parser_arguments.computername)

        if computername and computername != ".":
            target_desc = f"on {computername}"
        else:
            target_desc = "on local computer"

        self.append_response(
            f"adduser-localgroup - Adding user '{username}' "
            f"to group '{groupname}' {target_desc}...\n"
        )

        # Execute the BOF
        super().run(arguments)
