#!/usr/bin/python3

import io
import os
import zipfile

def AddFile(zip, file, arcname):
    if isinstance(file, str):
        file = open(file, 'rb')
    info = zipfile.ZipInfo(arcname)
    info.external_attr = 0o100755 << 16
    zip.writestr(info, file.read())

dirname = os.path.dirname(__file__)
for testcase in ('passing-example_1.2', 'lacking-aslr_1.2'):
    location = os.path.join(dirname, testcase)
    base = os.path.join(location, 'unvanquished_1.2')
    pkg = os.path.join(base, 'pkg')
    z = zipfile.ZipFile(os.path.join(dirname, testcase + '.zip'), 'w')
    for x in os.listdir(pkg):
        AddFile(z, os.path.join(pkg, x), 'unvanquished_1.2/pkg/' + x)

    for subdir in 'linux-amd64', 'macos-amd64', 'windows-i686', 'windows-amd64', 'symbols_1.2':
        stream = io.BytesIO()
        walk = os.path.join(base, subdir)
        if not os.path.exists(walk):
            continue
        with zipfile.ZipFile(stream, 'w') as subzip:
            for dirpath, _, filenames in os.walk(walk):
                for filename in filenames:
                    filename = os.path.join(dirpath, filename)
                    AddFile(subzip, filename, os.path.relpath(filename, walk))
        stream.seek(0)
        AddFile(z, stream, 'unvanquished_1.2/' + subdir + '.zip')
