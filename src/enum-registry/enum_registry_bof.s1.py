"""
OC2 BOF Script for Enum Registry

This script provides the OC2 interface for the enum-registry BOF, which gathers
intelligence from the Windows Registry.

Targets:
- RDP connection history
- Installed software enumeration
- Environment variables (System and User)
- WSL/Docker detection

Author: Generated for enum-registry BOF
Date: 2025-11-15
"""

from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class EnumRegistryBOF(BaseBOFTask):
    """
    Enum Registry BOF - Gather intelligence from Windows Registry
    """

    def __init__(self):
        super().__init__(
            "enum-registry",
            base_binary_name="enum-registry"
        )

        self.parser.description = (
            "Gather intelligence from Windows Registry including RDP history, "
            "installed software, environment variables, and WSL/Docker detection. "
            "Per-user data is read from every loaded hive under HKEY_USERS, so with "
            "admin rights it covers all logged-on users."
        )

        # Intel type filters
        self.parser.add_argument(
            "--rdp",
            action="store_true",
            help="Enumerate RDP connection history"
        )

        self.parser.add_argument(
            "--software",
            action="store_true",
            help="Enumerate installed software"
        )

        self.parser.add_argument(
            "--env",
            action="store_true",
            help="Enumerate environment variables"
        )

        self.parser.add_argument(
            "--wsl",
            action="store_true",
            help="Detect WSL and Docker installations"
        )

        self.parser.add_argument(
            "--all",
            action="store_true",
            help="Gather all registry intelligence (default if no filters specified)"
        )

        # Epilog with examples
        self.parser.epilog = (
            "Example usage:\n"
            "  enum-registry                         # Gather all registry intelligence\n"
            "  enum-registry --rdp                   # RDP connection history only\n"
            "  enum-registry --software              # Installed software only\n"
            "  enum-registry --rdp --software        # RDP history and software\n"
            "  enum-registry --env                   # Environment variables only\n"
            "  enum-registry --wsl                   # WSL/Docker detection only\n"
            "  enum-registry --all                   # Explicit all (same as no flags)\n\n"
            "Intel Types:\n"
            "  RDP History:\n"
            "    - Terminal Server Client\\Servers registry keys\n"
            "    - Default MRU list (Most Recently Used)\n"
            "    - One section per loaded user hive, SID resolved to DOMAIN\\user\n\n"
            "  Software:\n"
            "    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\n"
            "    - Includes both 64-bit and 32-bit applications\n"
            "    - Displays software name and version\n"
            "    - May require elevated privileges for complete enumeration\n\n"
            "  Environment Variables:\n"
            "    - System environment variables (HKLM)\n"
            "    - User environment variables for every loaded hive (HKEY_USERS\\<SID>)\n"
            "    - Includes PATH, JAVA_HOME, and custom variables\n\n"
            "  WSL/Docker:\n"
            "    - Detects Windows Subsystem for Linux installations per loaded user hive\n"
            "    - Enumerates WSL distributions\n"
            "    - Detects Docker Desktop installation\n\n"
            "Notes:\n"
            "  - All operations are read-only registry queries\n"
            "  - Fast execution (no file I/O, pure registry ops)\n"
            "  - Software enumeration may show fewer items without admin rights\n"
            "  - RDP, user environment and WSL walk HKEY_USERS: only logged-on users have\n"
            "    a loaded hive, and without admin other users' hives report access denied\n"
            "  - Falls back to HKEY_CURRENT_USER if HKEY_USERS cannot be enumerated\n\n"
            "OPSEC Considerations:\n"
            "  - Registry access is logged by some security tools\n"
            "  - Generally lower profile than file system enumeration\n"
            "  - No file writes or network activity\n"
            "  - Quick execution time (<1 second typically)\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        """
        Encode arguments for the enum-registry BOF.

        BOF expects: i
        - i: intelTypeFlags (int bitmask)
        """
        parser_arguments = self.parser.parse_args(arguments)

        # Determine intel type flags
        # Bit flags from entry.c:
        # INTEL_TYPE_RDP      = 0x01
        # INTEL_TYPE_SOFTWARE = 0x02
        # INTEL_TYPE_ENV      = 0x04
        # INTEL_TYPE_WSL      = 0x08
        # INTEL_TYPE_ALL      = 0xFF

        intel_flags = 0

        if parser_arguments.all:
            intel_flags = 0xFF  # INTEL_TYPE_ALL
        else:
            # Check individual flags
            if parser_arguments.rdp:
                intel_flags |= 0x01  # INTEL_TYPE_RDP
            if parser_arguments.software:
                intel_flags |= 0x02  # INTEL_TYPE_SOFTWARE
            if parser_arguments.env:
                intel_flags |= 0x04  # INTEL_TYPE_ENV
            if parser_arguments.wsl:
                intel_flags |= 0x08  # INTEL_TYPE_WSL

            # If no flags specified, default to all
            if intel_flags == 0:
                intel_flags = 0xFF  # INTEL_TYPE_ALL

        return [
            (BOFArgumentEncoding.INT, intel_flags)
        ]

    def run(self, arguments: List[str]):
        """Execute the enum-registry BOF"""
        parser_arguments = self.parser.parse_args(arguments)

        # Display collection configuration
        intel_types = []
        if parser_arguments.all or (
            not parser_arguments.rdp
            and not parser_arguments.software
            and not parser_arguments.env
            and not parser_arguments.wsl
        ):
            intel_types.append("All registry intelligence")
        else:
            if parser_arguments.rdp:
                intel_types.append("RDP history")
            if parser_arguments.software:
                intel_types.append("Installed software")
            if parser_arguments.env:
                intel_types.append("Environment variables")
            if parser_arguments.wsl:
                intel_types.append("WSL/Docker")

        self.append_response(
            f"[*] Registry Intel - Gathering: {', '.join(intel_types)}\n\n"
        )

        # Execute the BOF
        super().run(arguments)
