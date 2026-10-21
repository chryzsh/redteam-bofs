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


def _strip_domain_prefix(username: str) -> Tuple[str, str]:
    """
    NetGroupDelUser only accepts the bare SAM account name. Strip
    `DOMAIN\\user` and `user@domain` forms so operators can paste
    either without the call failing with code 2221.

    Returns (sam_account_name, notice_message).
    """
    cleaned = username.strip('"').strip("'")
    if "\\" in cleaned:
        sam = cleaned.split("\\", 1)[1]
        return sam, f"[!] Stripped DOMAIN\\ prefix from username: '{cleaned}' -> '{sam}'\n"
    if "@" in cleaned:
        sam = cleaned.split("@", 1)[0]
        return sam, f"[!] Stripped UPN suffix from username: '{cleaned}' -> '{sam}'\n"
    return cleaned, ""


class RemoveuserDomaingroupBOF(BaseBOFTask):
    def __init__(self):
        super().__init__(
            "removeuser-domaingroup",
            base_binary_name="removeuser-domaingroup",
            base_binary_path="."
        )

        self.parser.description = (
            "Remove a domain user from a domain group (global, universal, domain-local, or builtin). Must target a DC."
        )

        self.parser.add_argument(
            "groupname",
            help="Domain group name (e.g., 'Domain Admins')",
        )

        self.parser.add_argument(
            "username",
            help="User to remove (SAM account name, e.g., 'jsmith'). DOMAIN\\user and user@domain forms are auto-stripped.",
        )

        self.parser.add_argument(
            "--computer",
            dest="computername",
            default="",
            help="DC name/FQDN (e.g., 'dc01.corp.local'). The leading \\\\ is optional. Omit only when running on the DC itself.",
        )

        self.parser.epilog = (
            "removeuser-domaingroup tries NetGroupDelUser first (global/universal groups).\n"
            "If the group is not found, it retries on the same DC with NetLocalGroupDelMembers,\n"
            "which covers domain-local and builtin groups (Administrators, Account Operators,\n"
            "Remote Desktop Users, DL-* groups). The output says which call succeeded.\n"
            "The target must be a domain controller for the user's domain. The leading \\\\\n"
            "on the DC name is optional.\n\n"
            "Example usage:\n"
            "  - Remove user from a global group on the DC:\n"
            "    removeuser-domaingroup 'Domain Admins' jsmith --computer dc01.corp.local\n\n"
            "  - Remove user from a builtin or domain-local group (falls back automatically):\n"
            "    removeuser-domaingroup 'Account Operators' jsmith --computer dc01.corp.local\n\n"
            "  - DOMAIN\\ prefix is auto-stripped:\n"
            "    removeuser-domaingroup 'GG-Sysadmins' CORP\\alice --computer dc01.corp.local"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        sam_username, _ = _strip_domain_prefix(parser_arguments.username)

        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.groupname.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, sam_username),
            (BOFArgumentEncoding.WSTR, _unc(parser_arguments.computername)),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)
        sam_username, notice = _strip_domain_prefix(parser_arguments.username)

        if notice:
            self.append_response(notice)

        computername = _unc(parser_arguments.computername)

        if computername and computername != ".":
            target_desc = f"on DC {computername}"
        else:
            target_desc = "on local computer (must be a DC)"

        self.append_response(
            f"removeuser-domaingroup - Removing user '{sam_username}' "
            f"from domain group '{parser_arguments.groupname}' {target_desc}...\n"
        )

        super().run(arguments)
