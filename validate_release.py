#! /usr/bin/env python3

import collections
import contextlib
import functools
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import zipfile

try:
    import pefile
except ImportError:
    pefile = None
try:
    from macholib import MachO, mach_o
except ImportError:
    MachO = None
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.gnuversions import GNUVerNeedSection
    from elftools.elf.sections import NoteSection
except ImportError:
    ELFFile = None


@contextlib.contextmanager
def TempUnzip(z, filename):
    try:
        tempdir = tempfile.TemporaryDirectory()
        yield z.extract(filename, path=tempdir.name)
    finally:
        tempdir.cleanup()

# https://unix.stackexchange.com/a/14727
def CheckUnixPermissions(z):
    normal = 0o644, 0o755
    symlink = 0o120777 # Alternative permissions for symlink
    for info in z.infolist():
        permissions = info.external_attr >> 16
        if permissions & 0o7777 not in normal and permissions != symlink:
            yield f"File '{info.filename}' in {z.filename} has odd permissions {oct(permissions)}"

def LinuxCheckSymbolVersions(elf, binary, arch):
    # Target supported versions are from Debian 10 Buster
    lib_versions = {
        'amd64': (('GLIBC', '2.27'), ('GLIBCXX', '3.4.25')),
        'i686':  (('GLIBC', '2.28'), ('GLIBCXX', '3.4.25')),
        'arm64': (('GLIBC', '2.27'), ('GLIBCXX', '3.4.25')),
        'armhf': None, # Not yet implemented for 32-bit ARM
    }
    if arch not in lib_versions:
        yield f'Unknown Linux architecture {arch}'
        return
    if not lib_versions[arch]:
        return
    v = lambda version: tuple(int(n) for n in version.split('.'))
    maxes = collections.defaultdict(lambda: '0')
    for section in elf.iter_sections():
        if not isinstance(section, GNUVerNeedSection):
            continue
        for _, auxiliaries in section.iter_versions():
            for aux in auxiliaries:
                lib, _, version = aux.name.partition('_')
                if v(version) > v(maxes[lib]):
                    maxes[lib] = version
    for lib, version in lib_versions[arch]:
        if maxes[lib] == '0':
            yield f"Can't detect symbol versions for {lib} on Linux binary {binary} ({arch})"
        elif v(maxes[lib]) > v(version):
            yield f'Linux binary {binary} ({arch}) depends on a too-new symbol version {lib}_{maxes[lib]}'

def GetElfBuildId(elf):
    for section in elf.iter_sections():
        if not isinstance(section, NoteSection):
            continue
        for note in section.iter_notes():
            if note['n_type'] == 'NT_GNU_BUILD_ID':
                # Idiotic byte-swapping procedure from FileId::ConvertIdentifierToString
                # in breakpad/src/common/linux/file_id.cc
                bytes = (3,2,1,0, 5,4, 7,6, 8,9,10,11,12,13,14,15)
                return ''.join(note['n_desc'][2*i: 2*i + 2] for i in bytes).upper() + '0'

def StoreBuildId(id, os, triple, symids):
    if id is None:
        yield f'Missing build ID for {os} binary {triple[2]}'
    elif triple in symids:
        yield f'Multiple binaries for {triple}'
    else:
        symids[triple] = id

def LinuxCheckBinary(z, arch, binary, symids):
    elf = ELFFile(z.open(binary))
    yield from StoreBuildId(GetElfBuildId(elf), 'Linux', ('Linux', arch, binary), symids)

    # Check ASLR
    if elf.header.e_type != 'ET_DYN':
        yield f"Linux {arch} binary '{binary}' is not PIE (type is {elf.header.e_type})"

    # Check dynamic dependency changes (from 0.51.1 baseline)
    deps = set()
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            # ld binary name contains annoying arch strings
            if tag.entry.d_tag == 'DT_NEEDED' and not tag.needed.startswith('ld-linux'):
                deps.add(tag.needed)
    expected = {
        'libc.so.6',
        'libdl.so.2',
        'libgcc_s.so.1',
        'libm.so.6',
        'libpthread.so.0',
        'librt.so.1',
        'libstdc++.so.6',
    }
    if binary == 'daemon':
        expected.add('libGL.so.1')
    added = deps - expected
    removed = expected - deps
    if added or removed:
        changes = ['+' + x for x in added] + ['-' + x for x in removed]
        yield f"Linux {arch} binary {binary} dynamic dependencies changed: " + ', '.join(changes)

    # Check libc and libstdc++ symbol versions
    yield from LinuxCheckSymbolVersions(elf, binary, arch)

def WindowsCheckBinary(z, arch, binary, symids):
    # Partially based on https://gist.github.com/wdormann/dcdba9840701c879115f9aa5c1ef86dc
    with z.open(binary) as f:
        bin = f.read()
    pe = pefile.PE(data=bin)
    bitness = [32, 64][arch == 'amd64']
    assert (bitness == 32) == pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE
    if not pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        yield f"Windows {arch} binary '{binary}' does not have ASLR (DYNAMICBASE)"
    elif pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED:
        # https://nvd.nist.gov/vuln/detail/CVE-2018-5392
        yield f"Windows {arch} binary '{binary}' has broken ASLR due to stripped relocs"
    elif bitness == 64 and not pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:
        yield f"Windows {arch} binary '{binary}' lacks High-Entropy VA flag"

    # Get build ID
    try:
        entry = pe.DIRECTORY_ENTRY_DEBUG[0].entry
    except AttributeError:
        id = None
    else:
        id = '%08X%04X%04X%s%X' % (entry.Signature_Data1, entry.Signature_Data2, entry.Signature_Data3,
                                   '%02X' * 8 % tuple(entry.Signature_Data4), entry.Age)
    yield from StoreBuildId(id, f'{bitness}-bit Windows', ('windows', arch, binary), symids)

def MacCheckBinary(z, arch, binary):
    with TempUnzip(z, 'Unvanquished.app/Contents/MacOS/' + binary) as path:
        macho = MachO.MachO(path)
        header, = macho.headers

        # Check PIE
        MH_PIE = 0x200000
        if not header.header.flags & MH_PIE:
            yield f"macOS {arch} binary '{binary}' is not PIE"

        # Check rpath
        rpaths = {command[2].rstrip(b'\0').rstrip(b'/')
                  for command in header.commands
                  if isinstance(command[1], mach_o.rpath_command)}
        rpaths.discard(b'@executable_path')
        if rpaths:
            yield f"macOS {arch} binary '{binary}' has unwanted rpaths {rpaths}"

ENGINE_PLATFORMS = [
    'linux-amd64',
    'linux-i686',
    'linux-arm64',
    'linux-armhf',
    'macos-amd64',
    'windows-amd64',
    'windows-i686',
]

ENGINE_BINARIES = ['daemon', 'daemonded', 'daemon-tty']


def CheckLinux(z, arch, symids):
    yield from CheckUnixPermissions(z)
    if not ELFFile:
        yield 'Missing pip package: pyelftools. Unable to analyze Linux or NaCl binaries without it.'
        return
    for binary in ENGINE_BINARIES:
        yield from LinuxCheckBinary(z, arch, binary, symids)

def CheckMac(z, arch, _):
    yield from CheckUnixPermissions(z)
    if not MachO:
        yield 'Missing pip package: macholib. Unable to analyze Mac binaries without it.'
        return
    for binary in ENGINE_BINARIES:
        yield from MacCheckBinary(z, arch, binary)

def CheckWindows(z, arch, symids):
    if not pefile:
        yield 'Missing pip package: pefile. Unable to analyze Windows binaries without it.'
        return
    for binary in ENGINE_BINARIES:
        yield from WindowsCheckBinary(z, arch, f'{binary}.exe', symids)
    if arch == 'i686':
        for exe in {'nacl_loader.exe', 'nacl_loader-amd64.exe'} - set(z.namelist()):
            yield f'{z.filename} missing {exe}'
    elif arch == 'amd64':
        if 'nacl_loader.exe' not in z.namelist():
            yield z.filename + ' missing nacl_loader.exe'
        if 'nacl_loader-amd64.exe' in z.namelist():
            yield z.filename + ' should not have nacl_loader-amd64.exe'

SYSTEM_CHECKERS = {
    'linux': CheckLinux,
    'macos': CheckMac,
    'windows': CheckWindows,
}

def CheckSymbols(z, symids):
    expected = {
        ('Linux', 'i686', 'daemon'),
        ('Linux', 'i686', 'daemonded'),
        ('Linux', 'i686', 'daemon-tty'),
        ('Linux', 'amd64', 'daemon'),
        ('Linux', 'amd64', 'daemonded'),
        ('Linux', 'amd64', 'daemon-tty'),
        ('Linux', 'armhf', 'daemon'),
        ('Linux', 'armhf', 'daemonded'),
        ('Linux', 'armhf', 'daemon-tty'),
        ('Linux', 'arm64', 'daemon'),
        ('Linux', 'arm64', 'daemonded'),
        ('Linux', 'arm64', 'daemon-tty'),
        ('windows', 'i686', 'daemon.exe'),
        ('windows', 'i686', 'daemonded.exe'),
        ('windows', 'i686', 'daemon-tty.exe'),
        ('windows', 'amd64', 'daemon.exe'),
        ('windows', 'amd64', 'daemonded.exe'),
        ('windows', 'amd64', 'daemon-tty.exe'),
        ('NaCl', 'armhf', 'cgame'),
        ('NaCl', 'i686', 'cgame'),
        ('NaCl', 'amd64', 'cgame'),
        ('NaCl', 'armhf', 'sgame'),
        ('NaCl', 'i686', 'sgame'),
        ('NaCl', 'amd64', 'sgame'),
    }
    for triple in symids:
        assert triple in expected
    for filename in z.namelist():
        if not filename.endswith('.sym'):
            continue
        m = re.fullmatch(r'([^/]+)/([0-9A-F]+)/([^/]+)\.sym', filename)
        if not m:
            yield 'Symbol filename %r does not match expected pattern' % filename
            continue
        f = z.open(filename)
        header = next(f).decode('ascii').split()
        if len(header) != 5 or header[0] != 'MODULE':
            yield 'Symbol file %r does not have a valid first line (module record)' % filename
            continue
        if m.group(2) != header[3]:
            yield 'Build ID in %r module line (%s) does not match that in the path (%s)' % (m.group(2), header[3])
        anything = False
        binary = header[4]
        if binary != m.group(1) or binary != m.group(3):
            yield 'Binary name inside %r (%s) does not match either the directory or filename' % (filename, binary)
        anything = False
        nacl_binary = None
        for line in f:
            # Arbitrarily chosen function that should appear in all binaries
            if b'tinyformat' in line:
                anything = True
            elif b'CG_Rocket_' in line:
                nacl_binary = 'cgame'
            elif b'G_admin_' in line:
                nacl_binary = 'sgame'
        if not anything:
            yield "Symbol file %r doesn't appear to actually have symbols (mistakenly used stripped binary?)" % filename
        system = header[1]
        if binary == 'main.nexe':
            if not nacl_binary:
                yield "Can't identify the binary in symbol file " + filename
                continue
            system = 'NaCl' # NaCl symbol files have "Linux" as the OS
            binary = nacl_binary
        try:
            arch = {
                'arm': 'armhf',
                'arm64': 'arm64',
                'x86': 'i686',
                'x86_64': 'amd64',
            }[header[2]]
        except KeyError:
            yield 'Unexpected NaCl architecture %r in %r' % (header[2], filename)
            continue
        triple = (system, arch, binary)
        if triple in expected:
            if triple in symids and header[3] != symids[triple]:
                yield f'Symbol file for {triple} has build ID {header[3]} but binary has {symids[triple]}'
            expected.remove(triple)
        else:
            yield 'Unexpected system/arch/binary combination ' + str(triple)
    for missing in expected:
        yield 'No symbols found for ' + str(missing)

def CheckMd5sums(z, base, dpks):
    try:
        sums = z.open(base + 'md5sums')
    except KeyError:
        yield 'Missing md5sums file in pkg/'
        return
    dpks = set(dpks)
    for line in sums:
        md5, _, name = line.strip().decode('ascii').partition(' *')
        if not name:
            yield 'Bad line in md5sums: ' + repr(line)
            continue
        if name not in dpks:
            yield 'md5sums has file %r which does not exist in pkg/' % name
            continue
        dpks.remove(name)
        content = z.open(base + name).read()
        actual = hashlib.md5(content).digest().hex()
        if md5 != actual:
            yield 'md5sums says hash of %s is %s, but actual is %s' % (name, md5, actual)
    for unmatched in dpks:
        yield 'Missing md5sums entry for file: ' + unmatched

def IsValidVfsPath(path):
    for component in path.split('/'):
        for part in component.split('.'):
            if not part:
                return False
            for c in part:
                if not ('a' <= c <= 'z' or 'A' <= c <= 'Z' or '0' <= c <= '9' or c in '-_+~'):
                    return False
    return True

# See ParseDeps in daemon/src/common/FileSystem.cpp
def ParseDeps(dpk, out):
    try:
        info = dpk.getinfo('DEPS')
    except KeyError:
        return
    with dpk.open(info) as deps:
        for line in deps:
            line = line.decode('utf-8')
            fields = line.split()
            if not fields:
                continue
            if len(fields) > 2:
                yield f'Bad DEPS line in {dpk.filename}: {repr(line)}'
            if len(fields) == 1:
                out.append((fields[0], None))
            else:
                out.append((fields[0], fields[1]))

def AnalyzeDpk(dpk, unv, symids, deps):
    dpk = zipfile.ZipFile(dpk)
    yield from ParseDeps(dpk, deps)
    for filename in dpk.namelist():
        if filename.endswith('/'):
            continue
        name, _, ext = filename.rpartition('.')
        if ext == '7z':
            yield f'Unwanted file "{filename}" found in {dpk.filename}'
            continue
        if not IsValidVfsPath(filename):
            yield f'{repr(filename)} in {dpk.filename} has a name invalid for the VFS'
            continue
        if ext != 'nexe' or not ELFFile:
            continue
        match = re.fullmatch('([cs]game)-(i686|amd64|armhf)', name)
        if not match or unv == 0:
            yield f'Unexpected nexe "{filename}" in {dpk.filename}'
        elif unv == 1:
            id = GetElfBuildId(ELFFile(dpk.open(filename)))
            yield from StoreBuildId(id, 'NaCl', ('NaCl', match.group(2), match.group(1)), symids)

# See VersionCmp in daemon/src/common/FileSystem.cpp
def VersionCompareKey(version):
    key = []
    for num, char in re.findall(r'([0-9]+)|(.)', version):
        if num:
            key += [0, int(num)]
        elif 'a' <= char.lower() < 'z':
            key.append(ord(char))
        elif char == '~':
            key.append(-1)
        else:
            key.append(ord(char) + 256)
    if key[-1] == 0: # Having a zero number at the end does not affect the sorting, e.g. "a00" == "a"
        key.pop()
    else:
        key.append(0)
    return key

def LookUpPak(name, version, depmap):
    if version is None:
        version = max((version for n, version in depmap if n == name), key=VersionCompareKey, default=None)
    if (name, version) in depmap:
        return name, version
    return None

def PakFilename(pak):
    name, version = pak
    return f'{name}_{version}.dpk'

def CheckDependencyGraph(depmap):
    visited = set()
    stack = []
    def VisitPak(spec):
        pak = LookUpPak(*spec, depmap)
        if not pak:
            yield PakFilename(stack[-1]) + ' has nonexistent dependency ' + str(spec)
            return
        if pak in stack:
            yield 'Pak dependency cycle: ' + ' -> '.join(map(PakFilename, stack[stack.index(pak):] + [pak]))
            return
        if pak in visited:
            return
        visited.add(pak)
        stack.append(pak)
        for dep in depmap[pak]:
            yield from VisitPak(dep)
        stack.pop()

    for root in {name for name, _ in depmap if name in ['unvanquished', 'res-leveleditor'] or name.startswith('map-')}:
        yield from VisitPak((root, None))
    for leftover in set(depmap) - visited:
        yield 'No pak depends on ' + PakFilename(leftover)

def CheckPkg(z, base, number, symids):
    base += 'pkg/'
    depmap = {}
    for fullname in z.namelist():
        if not fullname.startswith(base) or fullname == base:
            continue
        name = fullname[len(base):]
        m = re.fullmatch(r'([^_/]+)_([^_/]+)\.dpk', name)
        if m:
            if '-dirty' in m.group(2):
                yield 'Dirty version string detected: ' + name
            deps = []
            if m.group(1) != 'unvanquished':
                unv = 0
            elif m.group(2) == number:
                unv = 1
            else:
                unv = 2
            yield from AnalyzeDpk(z.open(fullname), unv, symids, deps)
            depmap[m.group(1), m.group(2)] = deps
        elif name != 'md5sums':
            yield 'Unexpected filename in pkg/ ' + repr(name)
    unvanquished = LookUpPak('unvanquished', None, depmap)
    release = base.split('/')[0].split('_')[1]
    if unvanquished is None:
        yield "Missing 'unvanquished' package"
    elif unvanquished[1] != release:
        yield f'Release version is {release} but highest Unvanquished package is {unvanquished[1]}'
    yield from CheckDependencyGraph(depmap)
    yield from CheckMd5sums(z, base, [PakFilename(pak) for pak in depmap])

def CheckRelease(filename, number):
    z = zipfile.ZipFile(filename)
    yield from CheckUnixPermissions(z)
    root = 'unvanquished_' + number + '/'
    symids = {}
    yield from CheckPkg(z, root, number, symids)
    for base in ENGINE_PLATFORMS + ['symbols_' + number]:
        name = root + base + '.zip'
        try:
            info = z.getinfo(name)
        except KeyError:
            yield 'Missing file: ' + name
        else:
            zz = zipfile.ZipFile(z.open(info))
            if base.startswith('symbols_'):
                yield from CheckSymbols(zz, symids)
            else:
                system, arch = base.split('-')
                yield from SYSTEM_CHECKERS[system](zz, arch, symids)
    try:
        z.getinfo(root + 'README.txt')
    except KeyError:
        yield 'README.txt is missing'

def UsageError():
    sys.exit('Usage: validate_release.py <path to universal zip> [<version number>]\n'
             '       validate_release.py <path to symbols zip> [symbols]\n'
             '       validate_release.py <path to platform-specific zip> [linux-amd64 | macos-amd64 | windows-i686 | windows-amd64]')

def GuessArg2(filename):
    """Try to guess the desired action from the zip file name."""
    filename = os.path.basename(filename)
    if not filename.endswith('.zip'):
        return None
    name = filename[:-4]
    if name in ENGINE_PLATFORMS:
        return name
    if re.match(r'^unvanquished_[^_]+$', name):
        return name.split('_')[1]
    if re.match(r'symbols_[^_]+$', name):
        return 'symbols'
    return None

if __name__ == '__main__':
    if len(sys.argv) == 2:
        arg2 = GuessArg2(sys.argv[1])
        if arg2 is None:
            print('Could not guess desired action from filename.', file=sys.stderr)
            UsageError()
    elif len(sys.argv) == 3:
        arg2 = sys.argv[2]
    else:
        UsageError()
    if arg2 in ENGINE_PLATFORMS:
        print('Checking the zip for platform %s' % arg2, file=sys.stderr)
        system, arch = arg2.split('-')
        generator = SYSTEM_CHECKERS[system](zipfile.ZipFile(sys.argv[1]), arch, {})
    elif arg2 == 'symbols':
        print('Checking the symbols zip', file=sys.stderr)
        generator = CheckSymbols(zipfile.ZipFile(sys.argv[1]), {})
    else:
        print('Checking the universal zip (version = %r)' % arg2, file=sys.stderr)
        generator = CheckRelease(sys.argv[1], arg2)
    for error in generator:
        print(error)
