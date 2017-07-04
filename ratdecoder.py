#!/usr/bin/env python
import os
import sys
import importlib
import json
import hashlib
import yara
import subprocess
import tempfile
import logging
from optparse import OptionParser

from decoders import JavaDropper
logging.basicConfig()
log = logging.getLogger('ratdecoder')

__description__ = 'RAT Config Extractor'
__author__ = 'Kevin Breen, https://techanarchy.net, https://malwareconfig.com'
__version__ = '1.0'
__date__ = '2016/04'
rule_file = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                         'yaraRules', 'yaraRules.yar')


def unpack(raw_data):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(raw_data)
    f.close()
    try:
        subprocess.call("(upx -q -q -q -d %s)" % f.name, shell=True)
    except Exception as e:
        log.warning('UPX Error {0}'.format(e))
        return
    new_data = open(f.name, 'rb').read()
    os.unlink(f.name)
    return new_data


def yara_scan(raw_data):
    """
    Returns the Rule Name
    """
    yara_rules = yara.compile(rule_file)
    matches = yara_rules.match(data=raw_data)
    if len(matches) > 0:
        return str(matches[0])
    else:
        return


def run(raw_data):
    # Get some hashes
    md5 = hashlib.md5(raw_data).hexdigest()
    sha256 = hashlib.sha256(raw_data).hexdigest()

    log.info("MD5: {0}".format(md5))
    log.info("SHA256: {0}".format(sha256))

    # Yara Scan
    family = yara_scan(raw_data)

    # UPX Check and unpack
    if family == 'UPX':
        log.info("Found UPX Packed sample, Attempting to unpack")
        raw_data = unpack(raw_data)
        family = yara_scan(raw_data)

        if family == 'UPX':
            # Failed to unpack
            log.warning("Failed to unpack UPX")
            return

    # Java Dropper Check
    if family == 'JavaDropper':
        log.info("Found Java Dropped, attemping to unpack")
        raw_data = JavaDropper.run(raw_data)
        if raw_data:
            family = yara_scan(raw_data)

        if family == 'JavaDropper':
            log.warning("Failed to unpack JavaDropper")
            return

    if not family:
        log.warning("Unable to match your sample to a decoder")
        return

    # Import decoder
    try:
        module = importlib.import_module('decoders.{0}'.format(family))
        log.info("Identified family: {0}. Importing decoder.".format(family))
    except ImportError:
        log.warning('Unable to import decoder {0}'.format(family))
        return {"Family": family}

    # Get config data
    try:
        config_data = module.config(raw_data)
    except Exception as e:
        log.error('Conf Data error with {0}. Due to {1}'.format(family, e))
        return {"Family": family}

    config_data["Family"] = family
    # remove keys having empty/None values
    config_data = {k: v for k, v in config_data.iteritems() if v}
    return config_data


def print_output(config_dict, output, json_format):
    if not config_dict:
        log.info("No results")
        return
    if output:
        with open(output, 'a') as out:
            log.info("Printing Config to Output")
            if json_format:
                json.dump(config_dict, out)
            else:
                for key, value in sorted(config_dict.iteritems()):
                    out.write("Key: {0}\t Value: {1}".format(key, value))
            out.write('*'*20)
            log.info("End of Config")
    else:
        log.info("Printing Config to screen")
        if json_format:
            print json.dumps(config_dict)
        else:
            for key, value in sorted(config_dict.iteritems()):
                print "Key: {0}\t Value: {1}".format(key, value)
        log.info("End of Config")


if __name__ == "__main__":
    parser = OptionParser(usage='usage: %prog file / dir\n' + __description__, version='%prog ' + __version__)
    parser.add_option("-r", "--recursive", action='store_true', default=False, help="Recursive Mode")
    parser.add_option("-f", "--family", help="Force a specific family")
    parser.add_option("-l", "--list", action="store_true", default=False, help="List Available Decoders")
    parser.add_option("-q", "--quieter", action="count", default=False, help="Be quieter (may be used several times)")
    parser.add_option("-o", "--output", help="Output Config elements to file.")
    parser.add_option("-j", "--json", action="store_true", default=False, help="Output results as json")
    (options, args) = parser.parse_args()

    # Process "quieter" option
    log.setLevel(15 + options.quieter * 10)

    # Print list
    if options.list:
        print "Listing Available Decoders"
        for filename in os.listdir('decoders'):
            print "  - {0}".format(filename)
        sys.exit()

    # We need at least one arg
    if len(args) < 1:
        log.error("Not enough Arguments, Need at least file path")
        parser.print_help()
        sys.exit()

    # Check for file or dir
    is_file = os.path.isfile(args[0])
    is_dir = os.path.isdir(args[0])

    if options.recursive:
        if not is_dir:
            log.error("Recursive requires a directory not a file")
            sys.exit()

        # Read all the things
        for filename in os.listdir(args[0]):
            file_data = open(os.path.join(args[0], filename), 'rb').read()
            log.info("Reading {0}".format(filename))
            config_data = run(file_data)
            print_output(config_data, options.output, options.json)

    else:
        if not is_file:
            log.error("You did not provide a valid file.")
            sys.exit()

        # Read in the file.
        file_data = open(args[0], 'rb').read()
        log.info("Reading {0}".format(args[0]))
        config_data = run(file_data)
        print_output(config_data, options.output, options.json)
