#! /usr/bin/env python3
'''
- Download the latest & unstable Jadx
- Unpack it into ~/tools/jadx
- Chmod +x binaries
'''

import re
import requests
import zipfile
import logging
import traceback
import fileinput
import os

HOME = os.environ['HOME']
DST_FOLDER = f"{HOME}/tools/jadx/"

def download_file(url, file_name):
    with open(file_name, "wb") as file:
        response = requests.get(url)
        file.write(response.content)

page = requests.get('https://bintray.com/skylot/jadx/unstable/_latestVersion#files')
version = str(re.findall("'version': \S+", page.text))
number = version.split(":")[-1]
version = re.sub(r'[^a-fA-F0-9.-]', '', number)
assert(version != "")

print(f"file: jadx-{version}.zip")
download_file(
    f"https://bintray.com/skylot/jadx/download_file?file_path=jadx-{version}.zip",
    f"/tmp/jadx-{version}.zip"
)

print(f"Extracting to: {DST_FOLDER}")
try:
    zf = zipfile.ZipFile(f"/tmp/jadx-{version}.zip", 'r')
    zf.extractall(DST_FOLDER)
    zf.close()
except Exception as e:
    tb = traceback.format_exc()
    logging.error(f"error extracting {apk}: {e}\n{tb}")

jadx = os.path.join(DST_FOLDER,"bin/jadx")
jadx_gui = os.path.join(DST_FOLDER,"bin/jadx-gui")
os.chmod(jadx, 0o775)
os.chmod(jadx_gui, 0o775)

for line in fileinput.input([jadx], inplace=True):
    print(line.replace('-Xmx4g', '-Xmx8g'), end='')
for line in fileinput.input([jadx_gui], inplace=True):
    print(line.replace('-Xmx4g', '-Xmx8g'), end='')