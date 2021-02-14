#!/usr/bin/python3

import contextlib
import hashlib
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
    for info in z.infolist():
        permissions = (info.external_attr >> 16) & 0o7777
        if permissions not in normal:
            yield f"File '{info.filename}' in {z.filename} has odd permissions {oct(permissions)}"

def LinuxCheckAslr(z, binary):
    if not ELFFile:
        return
    elf = ELFFile(z.open(binary))
    if elf.header.e_type != 'ET_DYN':
        yield f"Linux binary '{binary}' is not PIE (type is {elf.header.e_type})"

def WindowsCheckAslr(z, binary, bitness):
    # Partially based on https://gist.github.com/wdormann/dcdba9840701c879115f9aa5c1ef86dc
    if not pefile:
        return
    with z.open(binary) as f:
        bin = f.read()
    pe = pefile.PE(data=bin)
    assert (bitness == 32) == pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE
    if not pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        yield f"{bitness}-bit Windows binary '{binary}' does not have ASLR (DYNAMICBASE)"
    elif pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED:
        # https://nvd.nist.gov/vuln/detail/CVE-2018-5392
        yield f"{bitness}-bit Windows binary '{binary}' has broken ASLR due to stripped relocs"
    elif bitness == 64 and not pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:
        yield f"64-bit Windows binary '{binary}' lacks High-Entropy VA flag"

def MacCheckBinary(z, binary):
    if not MachO:
        return
    with TempUnzip(z, 'Unvanquished.app/Contents/MacOS/' + binary) as path:
        macho = MachO.MachO(path)
        header, = macho.headers

        # Check PIE
        MH_PIE = 0x200000
        if not header.header.flags & MH_PIE:
            yield f"Mac binary '{binary}' is not PIE"

        # Check rpath
        rpaths = {command[2].rstrip(b'\0').rstrip(b'/')
                  for command in header.commands
                  if isinstance(command[1], mach_o.rpath_command)}
        rpaths.discard(b'@executable_path')
        if rpaths:
            yield f"Mac binary '{binary}' has unwanted rpaths {rpaths}"

def Linux(z):
    yield from CheckUnixPermissions(z)
    yield from LinuxCheckAslr(z, 'daemon')
    yield from LinuxCheckAslr(z, 'daemonded')
    yield from LinuxCheckAslr(z, 'daemon-tty')

def Mac(z):
    yield from CheckUnixPermissions(z)
    yield from MacCheckBinary(z, 'daemon')
    yield from MacCheckBinary(z, 'daemonded')
    yield from MacCheckBinary(z, 'daemon-tty')

def Windows32(z):
    yield from WindowsCheckAslr(z, 'daemon.exe', 32)
    yield from WindowsCheckAslr(z, 'daemonded.exe', 32)
    yield from WindowsCheckAslr(z, 'daemon-tty.exe', 32)

def Windows64(z):
    yield from WindowsCheckAslr(z, 'daemon.exe', 64)
    yield from WindowsCheckAslr(z, 'daemonded.exe', 64)
    yield from WindowsCheckAslr(z, 'daemon-tty.exe', 64)

def Symbols(z):
    expected = {
        ('Linux', 'x86_64', 'daemon'),
        ('Linux', 'x86_64', 'daemonded'),
        ('Linux', 'x86_64', 'daemon-tty'),
        ('windows', 'x86', 'daemon.exe'),
        ('windows', 'x86', 'daemonded.exe'),
        ('windows', 'x86', 'daemon-tty.exe'),
        ('windows', 'x86_64', 'daemon.exe'),
        ('windows', 'x86_64', 'daemonded.exe'),
        ('windows', 'x86_64', 'daemon-tty.exe'),
        ('NaCl', 'x86', 'cgame'),
        ('NaCl', 'x86_64', 'cgame'),
        ('NaCl', 'x86', 'sgame'),
        ('NaCl', 'x86_64', 'sgame'),
    }
    for filename in z.namelist():
        if not filename.endswith('.sym'):
            continue
        m = re.fullmatch(r'symbols/([^/]+)/([0-9A-F]+)/([^/]+)\.sym', filename)
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
        platform = header[1]
        if binary == 'main.nexe':
            if not nacl_binary:
                continue # Can't identify binary
            platform = 'NaCl' # NaCl symbol files have "Linux" as the OS
            binary = nacl_binary
        triple = (platform, header[2], binary)
        if triple in expected:
            expected.remove(triple)
        else:
            yield 'Unexpected platform/arch/binary combination ' + str(triple)
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

def CheckPkg(z, base):
    base += 'pkg/'
    dpks = []
    for name in z.namelist():
        if not name.startswith(base) or name == base:
            continue
        name = name[len(base):]
        if re.fullmatch(r'[^/]+\.dpk', name):
            dpks.append(name)
        elif name != 'md5sums':
            yield 'Unexpected filename in pkg/ ' + repr(name)
    unvanquished = base.split('/')[0] + '.dpk'
    if unvanquished not in dpks:
        yield 'Expected there to be a package named ' + unvanquished
    yield from CheckMd5sums(z, base, dpks)
    # TODO: Check DEPS files inside dpks?

def CheckDependencies():
    if not pefile:
        yield 'Missing pip package: pefile. Unable to analyze Windows binaries without it.'
    if not MachO:
        yield 'Missing pip package: macholib. Unable to analyze Mac binaries without it.'
    if not ELFFile:
        yield 'Missing pip package: pyelftools. Unable to analyze Linux binaries without it.'

def CheckRelease(filename, number):
    yield from CheckDependencies()
    z = zipfile.ZipFile(filename)
    base = 'unvanquished_' + number + '/'
    for name, checker in (
        ('linux-amd64', Linux),
        ('macos-amd64', Mac),
        ('windows-i686', Windows32),
        ('windows-amd64', Windows64),
        ('symbols_' + number, Symbols),
    ):
        name = base + name + '.zip'
        try:
            info = z.getinfo(name)
        except KeyError:
            yield 'Missing file: ' + name
        else:
            yield from checker(zipfile.ZipFile(z.open(info)))
    yield from CheckPkg(z, base)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('Sample usage: validate_release.py some/path/unvanquished_1.2.3.zip 1.2.3')
    for error in CheckRelease(*sys.argv[1:]):
        print(error)
