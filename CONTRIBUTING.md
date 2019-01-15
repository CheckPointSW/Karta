How to contribute
==============
First of all, thank you for choosing to contribute to our project. This short guide will describe the required coding conventions, as well as the built-in tests that we use in our project. Following these guidelines will help us merge your pull request into our code base in a fast as smooth manner.

Submitting changes
------------------------
Please send us a GitHub Pull Request with a clear list of what you've done. Make sure to include a clear log message for your commits, describing the modifications / additions to the code base, and their implications.

By it's nature **Karta** requires an extensive testing environment. When adding support to a new identifier or fixing a bug in an existing one, please link to a test case (binary, firmware, etc.) that could be used from now for regression tests.

Reporting a bug
-------------------
In order to help us close the bug as quickly as possible, please follow these steps:
1. Make sure there isn't an open issue that already addresses this bug
2. If there isn't, open a new issue and attach as many informative details as you can:
      * Binary sample / library name + version in which the bug occurs
      * Details about the used disassembler: name + version
      * Trace + logs, describing the bug / exception
      * As many details as you can in order to help us reproduce and fix this issue
 3. If you already have a fix, please submit it as a pull request, and include the bug details in it's description

Coding Conventions
------------------------
Start reading our code and we believe you'll get the hang of it.
The important notes are:
* Every function should be documented in a manner that is consistent with the current documentation standard
* Each indentation level should be 4 spaces in width (spaces, not tabs)
* We believe that comments improve the readability, make sure that your code is documented enough to be understood by other developers

Testing
---------
**Karta** uses the following tools to enforce coding conventions and to help eliminate common python bugs:
* [pydocstyle](http://www.pydocstyle.org/en/2.1.1/usage.html)
* [flake8](https://pypi.org/project/flake8/)

Our CI environment will check every pull request using these tools. Therefor, We highly recommend that every commit will be checked in advance to make sure it won't fail during the pull request.

Testing can be done from the project's home directory:
1. Testing for **pydocstyle**:
```Karta> python tests.py```
2. Testing for **flake8**:
```Karta> flake8 src```

One last note
----------------
We believe that the only way that Open Source tools will help the info-sec community in the long term, is to maintain these tools and to make sure they are developed according to the community standards. Each contribution brings as one step further to this goal.

Thanks :)