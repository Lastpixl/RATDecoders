#!/usr/bin/python
import zipfile
import os
import argparse
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
import logging

log = logging.getLogger("ratdecoder." + __name__)


def extract_config(apkfile):
    a = apk.APK(apkfile)
    d = dvm.DalvikVMFormat(a.get_dex())
    for cls in d.get_classes():
        if 'Lmy/app/client/ProcessCommand;'.lower() in cls.get_name().lower():
            c2Found = False
            portFound = False
            c2 = ""
            port = ""
            string = None
            for method in cls.get_methods():
                if method.name == 'loadPreferences':
                    for inst in method.get_instructions():
                        if inst.get_name() == 'const-string':
                            string = inst.get_output().split(',')[-1].strip(" '")
                            if c2Found is True:
                                c2 = string
                                c2Found = False
                            if string == 'ip':
                                c2Found = True
                            if string == 'port':
                                portFound = True
                        if inst.get_name() == 'const/16':
                            if portFound is True:
                                string = inst.get_output().split(',')[-1].strip(" '")
                                port = string
                        if c2 and port:
                            break
            server = ""
            if port:
                server = "{0}:{1}".format(c2, str(port))
            else:
                server = c2
            log.debug('Extracting from %s' % apkfile)
            log.debug('C&C: [ %s ]\n' % server)


def check_apk_file(apk_file):
    bJar = False
    try:
        zf = zipfile.ZipFile(apk_file, 'r')
        lst = zf.infolist()
        for zi in lst:
            fn = zi.filename
            if fn.lower() == 'androidmanifest.xml':
                bJar = True
                return bJar
    except:
        return bJar


def logo():
    log.info('\n')
    log.info(' ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __   ')
    log.info('/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \  ')
    log.info('\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \ ')
    log.info(' \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\\\"\_\\')
    log.info('  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/')
    log.info('\n')
    log.info(" Find the C&C for this Androrat mallie!")
    log.info(" Jacob Soo")
    log.info(" Copyright (c) 2016\n")


if __name__ == "__main__":
    description = 'C&C Extraction tool for Androrat.'
    parser = argparse.ArgumentParser(
        description=description,
        epilog='--file and --directory are mutually exclusive')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-f', '--file', action='store', nargs=1, dest='szFilename',
        help='filename', metavar="filename")
    group.add_argument(
        '-d', '--directory', action='store', nargs=1, dest='szDirectory',
        help='Location of directory.', metavar='directory')

    args = parser.parse_args()
    Filename = args.szFilename
    Directory = args.szDirectory
    is_file = False
    is_dir = False
    try:
        is_file = os.path.isfile(Filename[0])
    except:
        pass
    try:
        is_dir = os.path.isdir(Directory[0])
    except:
        pass
    logo()
    if Filename is not None and is_file:
        if check_apk_file(Filename[0]) is True:
            extract_config(Filename[0])
        else:
            log.error("This is not a valid apk file: %s" % Filename[0])
    if Directory is not None and is_dir:
        for root, directories, filenames in os.walk(Directory[0]):
            for filename in filenames:
                szFile = os.path.join(root, filename)
                if check_apk_file(szFile) is True:
                    extract_config(szFile)
                else:
                    log.error("This is not a valid apk file: %s" % szFile)
