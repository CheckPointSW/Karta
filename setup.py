#!/usr/bin/python

from setuptools import setup, find_packages
from codecs     import open

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='Karta',
      version='1.2.0',
      description='IDA plugin for identifying and matching open-source libraries in (huge) binaries',
      author='Eyal Itkin',
      author_email='eyalit@checkpoint.com',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/CheckPointSW/Karta',
      license='MIT',
      packages=find_packages(),
      install_requires=['elementals==1.2.6', 'networkx==2.2', 'sark==1.0', 'pydocstyle==3.0.0', 'flake8==3.7.7', 'click==7.0', 'scikit-learn==0.20.3'],
      classifiers=[
                    "Programming Language :: Python :: 2",
                    "License :: OSI Approved :: MIT License (MIT License)",
                    "Operating System :: OS Independent",
                  ],
      zip_safe=False)
