Adding support for a new open source
====================================
Support consists of two parts:
1.  A fingerprint *.py file with the logic required for locating the library
1.  An initial configuration file for a chosen version

Compiling the configuration is done exactly as described in the prior section. However, you should make sure to document the flags you changed in the project's Makefile, by storing your guidelines in the ```compilations``` folder under a new *.txt file named after your open source library.

Adding a new *.py file for the identification script is rather simple. The needed steps are:
1.  Copy some existing file from the ```libs``` folder (```libpng.py``` for instance) to a new *.py file with the name of your library, and place it too under the ```libs``` folder
1.  Update the ```__init__.py``` file with your library, and place your new import line at the **end** of the list
1.  Update the name of the class
1.  Update the ```NAME``` variable, with an exact string name (case sensitive)
1.  Update the logic of ```searchLib()``` method - currently based on a basic string search
1.  If needed, update the logic of the ```identifyVersions()``` method

Sharing with the community :)
-----------------------------
So, you just added support for a new library, and it worked on your setup. Good Job :)

Please consider submitting it to the community collection of configurations and fingerprints. Feel free to submit it as a pull request for now, and in the future we might update it to a separate repository.