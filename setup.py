from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import io
import codecs
import os
import sys

# import libsig

here = os.path.abspath(os.path.dirname(__file__))

def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)

long_description = read('README.md')

setup(
    name='libsig',
    # version=libsig.__version__,
    # url='',
    # license='',
    author='PETS2016w Course',
    install_requires=['gmpy',
                    # 'more stuff',
                    ],
    #author_email='henning.kopp@uni-ulm.de',
    description='A library of some advanced signature schemes',
    long_description=long_description,
    packages=['libsig'],
    include_package_data=True,
    platforms='any',
    # test_suite='sandman.test.test_sandman',
    # classifiers = [
    #     'Programming Language :: Python',
    #     'Natural Language :: English',
    #     ],
    # keywords = '',
    extras_require={
        'testing': ['nose','nose-cov'],
    }
)
