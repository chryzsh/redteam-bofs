import os
from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.base_task import BaseTask
from outflank_stage1.task.enums import BOFArgumentEncoding, BOFType


# ============================================
# Individual Privilege Escalation Checks
# ============================================
#
# PrivKit uses unique BOF filenames, so keep OC2 resolution at the project
# root. This avoids runtime breakage when deployment tooling flattens files.

_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))


class _PrivKitBaseBOF(BaseBOFTask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_base_path(_SCRIPT_BASE_PATH)


class AlwaysInstallElevatedCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-alwaysinstallelevated",
            base_binary_name="AlwaysInstallElevatedCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for AlwaysInstallElevated privilege escalation vulnerability. "
            "If enabled in both HKCU and HKLM, any user can install MSI packages with SYSTEM privileges."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-alwaysinstallelevated\n\n"
            "Checks:\n"
            "  HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated\n"
            "  HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated\n"
        )

    # BOF expects: no arguments (go is called with NULL)
    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class AutoLogonCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-autologon",
            base_binary_name="AutoLogonCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for stored Autologon credentials in the Winlogon registry key. "
            "If AutoAdminLogon=1 and DefaultPassword is set, credentials are exposed."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-autologon\n\n"
            "Registry location:\n"
            "  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class CredentialManagerCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-credmanager",
            base_binary_name="CredentialManagerCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Enumerate credentials from Windows Credential Manager for the current user context. "
            "Shows target, username, and password. Running as SYSTEM will not show user credentials."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-credmanager\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class HijackablePathCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-hijackablepath",
            base_binary_name="HijackablePathCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for writable directories in the system PATH. "
            "Writable PATH directories can be abused for DLL hijacking or binary planting."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-hijackablepath\n\n"
            "Registry location:\n"
            "  HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class ModifiableAutorunCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-modifiableautorun",
            base_binary_name="ModifiableAutorunCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for modifiable autorun executables in Run/RunOnce registry keys. "
            "Writable autorun binaries can be replaced for privilege escalation."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-modifiableautorun\n\n"
            "Checked locations:\n"
            "  HKLM and HKCU: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  HKLM and HKCU: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n"
            "  HKLM and HKCU: SOFTWARE\\Wow6432Node\\...\\Run (x64 systems)\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class ModifiableSVCCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-modifiablesvc",
            base_binary_name="ModifiableSVCCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for services with modifiable permissions (DACL). "
            "If a service is modifiable, its binary path can be changed for privilege escalation."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-modifiablesvc\n\n"
            "Checked permissions:\n"
            "  SERVICE_CHANGE_CONFIG, WRITE_DAC, WRITE_OWNER,\n"
            "  GENERIC_ALL, GENERIC_WRITE, SERVICE_ALL_ACCESS\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class TokenPrivilegesCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-tokenprivileges",
            base_binary_name="TokenPrivilegesCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Enumerate current process token privileges and their enabled/disabled status."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-tokenprivileges\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class UnquotedSVCPathCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-unquotedsvcpath",
            base_binary_name="UnquotedSVCPathCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for unquoted service paths with spaces. "
            "Unquoted paths containing spaces can be exploited for privilege escalation."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-unquotedsvcpath\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class PowerShellHistoryCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-pshistory",
            base_binary_name="PowerShellHistoryCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check for PowerShell PSReadLine history file. "
            "This file may contain sensitive commands, credentials, or secrets."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-pshistory\n\n"
            "File location:\n"
            "  %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


class UACStatusCheckBOF(_PrivKitBaseBOF):
    def __init__(self, bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(
            "privkit-uacstatus",
            base_binary_name="UACStatusCheck",
            base_binary_path=".",
            bof_type=bof_type,
        )

        self.parser.description = (
            "Check UAC status, integrity level, and local admin group membership. "
            "Determines if UAC bypass may be possible."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privkit-uacstatus\n\n"
            "Checks performed:\n"
            "  EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop,\n"
            "  Token Integrity Level, Local Administrators group membership\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        return []


# ============================================
# PrivCheck - Run All Checks
# ============================================

_CHECKS = [
    ("AlwaysInstallElevatedCheck", AlwaysInstallElevatedCheckBOF),
    ("AutoLogonCheck", AutoLogonCheckBOF),
    ("CredentialManagerCheck", CredentialManagerCheckBOF),
    ("HijackablePathCheck", HijackablePathCheckBOF),
    ("ModifiableAutorunCheck", ModifiableAutorunCheckBOF),
    ("ModifiableSVCCheck", ModifiableSVCCheckBOF),
    ("TokenPrivilegesCheck", TokenPrivilegesCheckBOF),
    ("UnquotedSVCPathCheck", UnquotedSVCPathCheckBOF),
    ("PowerShellHistoryCheck", PowerShellHistoryCheckBOF),
    ("UACStatusCheck", UACStatusCheckBOF),
]


class PrivCheckTask(BaseTask):
    """Run all PrivKit privilege escalation checks in sequence.

    Queues each individual checker BOF as a separate task on the agent so
    they execute one after another with full BOF lifecycle support.
    """

    def __init__(self):
        super().__init__("privcheck")

        self.parser.description = (
            "Run all PrivKit privilege escalation checks in sequence (10 checks total)."
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  privcheck\n\n"
            "Runs the following checks:\n"
            "  1. AlwaysInstallElevatedCheck    (privkit-alwaysinstallelevated)\n"
            "  2. AutoLogonCheck                (privkit-autologon)\n"
            "  3. CredentialManagerCheck         (privkit-credmanager)\n"
            "  4. HijackablePathCheck            (privkit-hijackablepath)\n"
            "  5. ModifiableAutorunCheck         (privkit-modifiableautorun)\n"
            "  6. ModifiableSVCCheck             (privkit-modifiablesvc)\n"
            "  7. TokenPrivilegesCheck           (privkit-tokenprivileges)\n"
            "  8. UnquotedSVCPathCheck           (privkit-unquotedsvcpath)\n"
            "  9. PowerShellHistoryCheck         (privkit-pshistory)\n"
            "  10. UACStatusCheck                (privkit-uacstatus)\n\n"
            "Individual checks are also available as separate commands\n"
            "(prefixed with privkit-).\n"
        )

    def run(self, arguments: List[str]):
        self.append_response(
            "==================================================\n"
            "  PrivCheck - Privilege Escalation Checks\n"
            "  BOF by @merterpreter && @nickvourd\n"
            "==================================================\n\n"
        )

        total = len(_CHECKS)
        for idx, (name, cls) in enumerate(_CHECKS, 1):
            task = cls(bof_type=BOFType.DEFAULT_NON_THREADED)
            task.set_base_path(self.get_base_path() or _SCRIPT_BASE_PATH)
            task.append_response(f"[{idx}/{total}] Running {name}...\n")
            self.add_task_after(task)

        self.append_response(
            f"Queued {total} privilege escalation checks.\n"
        )
