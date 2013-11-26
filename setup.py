#!/usr/bin/env python
# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 


from distutils.core import setup

setup(name='Bowcaster',
        version='0.1',
        description='Lightweight, cross-platform exploit development framework',
        long_description=open('README.txt').read(),
        author='Zachary Cutlip',
        author_email="uid000@gmail.com",
        package_dir = {'':'src'},
        package_data={'':['contrib/C/*','contrib/asm/mips/*','common/hackers/hackers.txt']},
        packages=['bowcaster',
            'bowcaster.common',
            'bowcaster.common.hackers',
            'bowcaster.development',
            'bowcaster.payloads',
            'bowcaster.payloads.mips',
            'bowcaster.encoders',
            'bowcaster.servers',
            'bowcaster.clients'],
        scripts=["src/standalone/connectbackserver",
                 "src/standalone/trojanserver"]
        )

