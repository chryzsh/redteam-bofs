from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


class CredguardCheckBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("credguard-check", base_binary_name="credguard-check")

        self.parser.description = (
            "Check Windows security features (Credential Guard, HVCI, LSA Protection, VBS)"
        )

        self.parser.epilog = (
            "Description:\n"
            "  Checks the status of Windows security features by querying registry keys:\n"
            "    - Credential Guard (LsaCfgFlags)\n"
            "    - HVCI/Memory Integrity (HypervisorEnforcedCodeIntegrity)\n"
            "    - LSA Protection (RunAsPPL)\n"
            "    - VBS (Virtualization-Based Security)\n\n"
            "Example usage:\n"
            "  credguard-check\n\n"
            "Notes:\n"
            "  - This BOF queries registry keys to determine the status of security features\n"
            "  - [+] indicates the feature is ENABLED\n"
            "  - [-] indicates the feature is DISABLED or NOT CONFIGURED\n"
            "  - Credential Guard: Checks Lsa\\LsaCfgFlags (1=UEFI lock, 2=no UEFI lock, 0=disabled)\n"
            "  - HVCI: Checks DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled\n"
            "  - LSA Protection: Checks Lsa\\RunAsPPL (1=enabled with UEFI, 2=enabled without UEFI)\n"
            "  - VBS: Checks DeviceGuard\\EnableVirtualizationBasedSecurity\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        """
        Encode arguments for the BOF.

        This BOF takes no arguments.
        BOF expects: (empty - no arguments)
        """
        # No arguments needed for this BOF
        return []
