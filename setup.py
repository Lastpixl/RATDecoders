#! /usr/bin/env python2

from setuptools import setup
from glob import glob

setup(
    name='ratdecoder',
    version='0.1',
    packages=['ratdecoder_module', 'ratdecoder_module/decoders'],
    scripts=['ratdecoder.py'],
    package_data={'ratdecoder_module': ['yaraRules/*.yar']},

    # Metadata
    author='kevthehermit',
    url='https://github.com/kevthehermit/RATDecoders',
    description='Tools to decode configuration settings from common RATs',
)
