
from pathlib import Path

from edk2toolext.invocables.edk2_setup import RequiredSubmodule, SetupSettingsManager


class Settings(SetupSettingsManager):

    def GetWorkspaceRoot(self):
        return str(Path(__file__).resolve().parent / "MU_BASECORE")

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        rs = []
        rs.append(RequiredSubmodule("UnitTestFrameworkPkg/Library/GoogleTestLib/googletest", False))
        rs.append(RequiredSubmodule("MdeModulePkg/Universal/RegularExpressionDxe/oniguruma", False))
        rs.append(RequiredSubmodule("MdeModulePkg/Library/BrotliCustomDecompressLib/brotli", False))
        rs.append(RequiredSubmodule("UnitTestFrameworkPkg/Library/SubhookLib/subhook", False))
        rs.append(RequiredSubmodule("MdePkg/Library/BaseFdtLib/libfdt", False))
        rs.append(RequiredSubmodule("MdePkg/Library/MipiSysTLib/mipisyst", False))
        rs.append(RequiredSubmodule("SecurityPkg/DeviceSecurity/SpdmLib/libspdm", False))
        return rs