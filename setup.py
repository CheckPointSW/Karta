from setuptools import setup, find_packages
from codecs     import open
from os         import path

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='Karta',
      version='0.9.0',
      description='IDA plugin for matching open-source libraries in huge binaries',
      author='Eyal Itkin',
      author_email='eyalit@checkpoint.com',
      long_description=long_description,
      long_description_content_type="text/markdown",
      license='MIT',
      packages=find_packages(),
      install_requires=['elementals', 'sark'],
      classifiers=[
                    "Programming Language :: Python",
                    "License :: OSI Approved :: MIT License (MIT License)",
                    "Operating System :: OS Independent",
                  ],
      zip_safe=False)