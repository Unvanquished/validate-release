#!/usr/bin/python3

import io
import os
import zipfile

def AddFile(zip, file, arcname):
    if isinstance(file, str):
        file = open(file, 'rb')
    info = zipfile.ZipInfo(arcname)
    info.external_attr = 0o100755 << 16
    info.create_system = 3 # "Host OS" = "*nix"
    zip.writestr(info, file.read())

def PopulateZip(zip, top):
    for dir, dirnames, filenames in os.walk(top):
        dirnames.sort() # Make deterministic zips
        filenames.sort()
        reldir = os.path.relpath(dir, top)
        for filename in filenames:
            filename = os.path.join(dir, filename)
            AddFile(zip, filename, os.path.relpath(filename, top))
        for i, dirname in reversed(list(enumerate(dirnames))):
            if dirname.endswith('.dir'):
                del dirnames[i]
                dirname = os.path.join(dir, dirname)
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, 'w') as subzip:
                    PopulateZip(subzip, dirname)
                stream.seek(0)
                AddFile(zip, stream, os.path.relpath(dirname[:-4], top))

testdata = os.path.dirname(os.path.join('.', __file__))
for testcase in os.listdir(testdata):
    if not testcase.endswith('.dir'):
        continue
    with zipfile.ZipFile(os.path.join(testdata, testcase[:-4]), 'w') as z:
        PopulateZip(z, os.path.join(testdata, testcase))
