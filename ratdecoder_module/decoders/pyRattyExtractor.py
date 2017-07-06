import zipfile
import os
import base64
import argparse
import logging

log = logging.getLogger("ratdecoder." + __name__)


def extract_config(zip):
    """
    This extracts the C&C information from Ratty.
    https://github.com/Sogomn/Ratty
    """
    c2 = []
    bFile = False
    fh = open(zip, 'rb')
    z = zipfile.ZipFile(fh)
    for name in z.namelist():
        if name == "data":
            bFile = True
            data = z.read(name)
            try:
                data = base64.b64decode(data)
                for i in range(len(data)):
                    c2.append(chr(ord(data[i]) ^ 0x38))

                log.debug("Found it: %s" % zip)
                log.debug("C2: %s" % ''.join(c2))
            except:
                log.debug("Probably corrupted Base64 string.")
    if bFile is False:
        log.debug("No such file")
    log.debug("Task Completed\n")
    fh.close()


def check_jar_classes(jar_file):
    """
    Shitty Check whether file is a jar file.
    """
    bJar = False
    try:
        zf = zipfile.ZipFile(jar_file, 'r')
        lst = zf.infolist()
        for zi in lst:
            fn = zi.filename
            if fn.endswith('.class'):
                bJar = True
                return bJar
    except:
        return False


def logo():
    """
    Ascii Logos like the 90s. :P
    """
    log.info('\n')
    log.info(' ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __   ')
    log.info('/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \  ')
    log.info('\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \ ')
    log.info(' \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\\\"\_\\')
    log.info('  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/')
    log.info('\n')
    log.info(' Find the C&C for this Ratty mallie!')
    log.info(' Jacob Soo')
    log.info(' Copyright (c) 2016\n')


if __name__ == "__main__":
    description = 'C&C Extraction tool for Ratty (https://github.com/Sogomn/Ratty).'
    parser = argparse.ArgumentParser(description=description,
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
        extract_config(Filename[0])
    else:
        log.error("You probably have supplied an invalid file.")
    if Directory is not None and is_dir:
        for root, directories, filenames in os.walk(Directory[0]):
            for filename in filenames:
                szFile = os.path.join(root, filename)
                if check_jar_classes(szFile) is True:
                    extract_config(szFile)
                else:
                    log.error("This is not a valid Jar file: %s." % szFile)
