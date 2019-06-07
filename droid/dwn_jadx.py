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

global version
HOME       = os.environ['HOME']
DST_FOLDER = f"{HOME}/tools/jadx/"
JADX       = os.path.join(DST_FOLDER,"bin/jadx")
JADX_GUI   = os.path.join(DST_FOLDER,"bin/jadx-gui")


def download_file(url, file_name):
    print(f"Temporal file: {file_name}")
    with open(file_name, "wb") as file:
        response = requests.get(url)
        file.write(response.content)


def get_latest_jadx_version():
    page = requests.get('https://bintray.com/skylot/jadx/unstable/_latestVersion#files')
    version = str(re.findall("'version': \S+", page.text))
    number = version.split(":")[-1]
    version = re.sub(r'[^a-fA-F0-9.-]', '', number)
    assert(version != "")

    return version


def extract_zip():
    print(f"Extracting {ZIP_FILE_TMP_PATH} into {DST_FOLDER}")
    try:
        zf = zipfile.ZipFile(ZIP_FILE_TMP_PATH, 'r')
        zf.extractall(DST_FOLDER)
        zf.close()
    except Exception as e:
        tb = traceback.format_exc()
        logging.error(f"error extracting {ZIP_FILE_TMP_PATH}: {e}\n{tb}")


def chmod_exec():
    print("Making JADX executable")
    os.chmod(JADX, 0o775)
    os.chmod(JADX_GUI, 0o775)


def increase_jvm_mem():
    print("Increment JVM_OPTIONS to 8GM RAM")
    for line in fileinput.input([JADX], inplace=True):
        print(line.replace('-Xmx4g', '-Xmx8g'), end='')
    for line in fileinput.input([JADX_GUI], inplace=True):
        print(line.replace('-Xmx4g', '-Xmx8g'), end='')


def add_to_path():
    bashrc = f"{HOME}/.bashrc"
    if "jadx" in open(bashrc).read():
        print("JADX is in PATH")
    else:
        print("JADX was NOT in PATH")
        with open(bashrc, "a") as f:
            f.write("export PATH=~/tools/jadx/bin:$PATH")
            print("JADX is in PATH")


def create_install_folder():
    if not os.path.exists(DST_FOLDER):
        try:
            os.mkdir(f"{HOME}/tools")
        except Exception as e:
            pass
        os.mkdir(DST_FOLDER)
        print(f"Folder created: {DST_FOLDER}")


def main():
    global ZIP_FILE, ZIP_FILE_TMP_PATH

    version = get_latest_jadx_version()

    ZIP_FILE = f"jadx-{version}.zip"
    ZIP_FILE_TMP_PATH = f"/tmp/{ZIP_FILE}"

    download_file(
        f"https://bintray.com/skylot/jadx/download_file?file_path={ZIP_FILE}",
        ZIP_FILE_TMP_PATH
    )
    create_install_folder()
    extract_zip()
    chmod_exec()
    increase_jvm_mem()
    add_to_path()


if __name__ == '__main__':
    main()