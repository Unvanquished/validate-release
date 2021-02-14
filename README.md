Script that checks an Unvanquished release for various possible mistakes.

Optional dependencies (pip): `macholib`, `pefile`

Usage:

    validate_release.py <release zip file> <version number>

The script has been tested on Linux and Windows. `readelf` even works on Windows if you have MinGW installed: for some reason, they ship a readelf which works on (only) Linux binaries.

Checks performed:
- All native binaries are built with ASLR
- All Breakpad symbol files exist and have some of the expected content
- Hashes in `pkg/md5sums` match the packages
- Normal file permissions for Unices (ones like on the NaCl files in 0.51.1 could prevent making an installation usable by someone other than the owner)

Running the script on the 0.51.1 release produces the following output:

    # python3 validate_release.py unvanquished_0.51.1.zip 0.51.1
    File 'nacl_loader' in unvanquished_0.51.1/linux-amd64.zip has odd permissions 0o700
    File 'irt_core-x86_64.nexe' in unvanquished_0.51.1/linux-amd64.zip has odd permissions 0o600
    File 'nacl_helper_bootstrap' in unvanquished_0.51.1/linux-amd64.zip has odd permissions 0o700
    Linux binary 'daemon' appears not to be PIE
    Linux binary 'daemonded' appears not to be PIE
    Linux binary 'daemon-tty' appears not to be PIE
    Mac binary 'daemon' is not PIE
    Mac binary 'daemon' has unwanted rpaths {b'/Users/harshmodi/code/Unvanquished/daemon/external_deps/macosx64-4/lib', b'/Users/harshmodi/code/Unvanquished/daemon/external_deps/macosx64-4'}
    Mac binary 'daemonded' is not PIE
    Mac binary 'daemonded' has unwanted rpaths {b'/Users/harshmodi/code/Unvanquished/daemon/external_deps/macosx64-4/lib', b'/Users/harshmodi/code/Unvanquished/daemon/external_deps/macosx64-4'}
    Mac binary 'daemon-tty' is not PIE
    Mac binary 'daemon-tty' has unwanted rpaths {b'/Users/harshmodi/code/Unvanquished/daemon/external_deps/macosx64-4/lib', b'/Users/harshmodi/code/Unvanquished/daemon/external_deps/macosx64-4'}
    32-bit Windows binary 'daemonded.exe' has broken ASLR due to stripped relocs
    32-bit Windows binary 'daemon-tty.exe' has broken ASLR due to stripped relocs
    64-bit Windows binary 'daemon.exe' lacks High-Entropy VA flag
    64-bit Windows binary 'daemonded.exe' has broken ASLR due to stripped relocs
    64-bit Windows binary 'daemon-tty.exe' has broken ASLR due to stripped relocs
    Symbol file 'symbols/daemon-tty/943FEC32CDACF42E86E04FD87004F21E0/daemon-tty.sym' doesn't appear to actually have symbols (mistakenly used stripped binary?)
    Symbol file 'symbols/daemon/F8A1F45833C1977CD13657473592668C0/daemon.sym' doesn't appear to actually have symbols (mistakenly used stripped binary?)
    Symbol file 'symbols/daemonded/8B93DD8B64AA4CB9D7590EBCBD6CACA50/daemonded.sym' doesn't appear to actually have symbols (mistakenly used stripped binary?)
    Missing md5sums file in pkg/
