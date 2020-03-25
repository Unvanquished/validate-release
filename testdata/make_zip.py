#!/usr/bin/python3

import io
import os
import zipfile

dirname = os.path.dirname(__file__)
location = os.path.join(dirname, 'passing-example_1.2')
base = os.path.join(location, 'unvanquished_1.2')
pkg = os.path.join(base, 'pkg')
z = zipfile.ZipFile(os.path.join(dirname, 'passing-example_1.2.zip'), 'w')
for x in os.listdir(pkg):
    z.write(os.path.join(pkg, x), arcname='unvanquished_1.2/pkg/' + x)

for subdir in 'linux-amd64', 'macos-amd64', 'windows-i686', 'windows-amd64', 'symbols_1.2':
    stream = io.BytesIO()
    walk = os.path.join(base, subdir)
    with zipfile.ZipFile(stream, 'w') as subzip:
        for dirpath, _, filenames in os.walk(walk):
            for filename in filenames:
                filename = os.path.join(dirpath, filename)
                subzip.write(filename, arcname=os.path.relpath(filename, walk))
    stream.seek(0)
    z.writestr('unvanquished_1.2/' + subdir + '.zip', stream.read())
