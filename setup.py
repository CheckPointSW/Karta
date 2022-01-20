#!/usr/bin/python3

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='Karta',
      version='2.1.0',
      description='IDA plugin for identifying and matching open-source libraries in (huge) binaries',
      author='Eyal Itkin',
      author_email='eyalit@checkpoint.com',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/CheckPointSW/Karta',
      license='MIT',
      packages=find_packages(),
      install_requires=['elementals', 'sark', 'pydocstyle', 'flake8', 'click', 'scikit-learn'],
      python_requires='>=3',
      classifiers=[
                    "Programming Language :: Python :: 3",
                    "License :: OSI Approved :: MIT License (MIT License)",
                    "Operating System :: OS Independent",
                  ],
      zip_safe=False)
