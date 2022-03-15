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
      packages=find_packages(where="src"),
      package_dir={"": "src"},
      install_requires=['elementals', 'sark', 'pydocstyle', 'flake8', 'click', 'scikit-learn'],
      python_requires='>=3',
      classifiers=[
                    "Programming Language :: Python :: 3",
                    "License :: OSI Approved :: MIT License (MIT License)",
                    "Operating System :: OS Independent",
                  ],
      entry_points={
            'console_scripts': [
                  'karta_analyze_src = karta.karta_analyze_src:main'
            ]
      },
      zip_safe=False
      )
