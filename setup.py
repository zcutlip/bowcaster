#!/usr/bin/env python

from distutils.core import setup

setup(name='Crossbow',
        version='0.1',
        description='Simple exploit development framework',
        author='Zachary Cutlip',
        package_dir = {'':'src'},
        packages=['crossbow',
            'crossbow.common',
            'crossbow.overflow_development',
            'crossbow.payloads',
            'crossbow.payloads.mips',
            'crossbow.encoders',
            'crossbow.servers']
        )

