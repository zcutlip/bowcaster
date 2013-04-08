#!/usr/bin/env python
# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 


from distutils.core import setup

setup(name='Crossbow',
        version='0.1',
        description='Lightweight, cross-platform exploit development framework',
        long_description=open('README.txt').read(),
        author='Zachary Cutlip',
        author_email="uid000@gmail.com",
        package_dir = {'':'src'},
        package_data={'':['contrib/C/*','contrib/asm/mips/*']},
        packages=['crossbow',
            'crossbow.common',
            'crossbow.overflow_development',
            'crossbow.payloads',
            'crossbow.payloads.mips',
            'crossbow.encoders',
            'crossbow.servers',
            'crossbow.clients']
        )

