#!/usr/bin/env python

from distutils.core import setup

setup(name='Simplesploit',
        version='0.1',
        description='Simple exploit development framework',
        author='Zachary Cutlip',
        package_dir = {'':'src'},
        packages=['simplesploit',
            'simplesploit.common',
            'simplesploit.overflow_development',
            'simplesploit.payloads',
            'simplesploit.payloads.mips',
            'simplesploit.encoders',
            'simplesploit.servers']
        )

