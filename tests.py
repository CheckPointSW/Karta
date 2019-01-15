#!/usr/bin/python

import pydocstyle
import os
from glob import glob

SRC_DIR = "src"

def fileList():
    return filter(lambda z: not z.endswith("__init__.py"), [y for x in os.walk(SRC_DIR) for y in glob(os.path.join(x[0], '*.py'))])


file_list = fileList()

passed = True

# Documentation tests
for check in pydocstyle.check(file_list, ignore=["D100", "D104", "D413", "D213", "D203", "D402"]):
    print(check)
    passed = False

# last status
exit(0 if passed else 1)
