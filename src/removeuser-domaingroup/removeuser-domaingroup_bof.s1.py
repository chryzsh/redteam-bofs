from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


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
            "Remove a domain user from a global or universal domain group. Must target a DC."
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
            help="DC name/FQDN (e.g., '\\\\dc01.corp.local'). Omit only when running on the DC itself.",
        )

        self.parser.epilog = (
            "removeuser-domaingroup wraps NetGroupDelUser. It only operates on global/universal\n"
            "AD groups, and the target must be a domain controller for the user's domain.\n"
            "For domain-local groups, use removeuser-localgroup --computer \\\\<dc> instead.\n\n"
            "Example usage:\n"
            "  - Remove user from a global group on the DC:\n"
            "    removeuser-domaingroup 'Domain Admins' jsmith --computer \\\\dc01.corp.local\n\n"
            "  - DOMAIN\\ prefix is auto-stripped:\n"
            "    removeuser-domaingroup 'GG-Sysadmins' CORP\\alice --computer \\\\dc01.corp.local"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)
        sam_username, _ = _strip_domain_prefix(parser_arguments.username)

        return [
            (BOFArgumentEncoding.WSTR, parser_arguments.groupname.strip('"').strip("'")),
            (BOFArgumentEncoding.WSTR, sam_username),
            (BOFArgumentEncoding.WSTR, parser_arguments.computername.strip('"').strip("'")),
        ]

    def run(self, arguments: List[str]):
        parser_arguments = self.parser.parse_args(arguments)
        sam_username, notice = _strip_domain_prefix(parser_arguments.username)

        if notice:
            self.append_response(notice)

        if parser_arguments.computername and parser_arguments.computername not in ["", "."]:
            target_desc = f"on DC {parser_arguments.computername}"
        else:
            target_desc = "on local computer (must be a DC)"

        self.append_response(
            f"removeuser-domaingroup - Removing user '{sam_username}' "
            f"from domain group '{parser_arguments.groupname}' {target_desc}...\n"
        )

        super().run(arguments)
