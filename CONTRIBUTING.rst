Contributing
============

First of all, thank you for your interest in contributing to dionaea!


Filing bug reports
------------------

Bug reports are very welcome.
Please file them on the `GitHub issue tracker`_.
Good bug reports come with extensive descriptions of the error and how to reproduce it.


Patches
-------

All patches to dionaea should be submitted in the form of pull requests to the main dionaea repository, `DinoTools/dionaea`_.
These pull requests should satisfy the following properties:

Code
^^^^

- The pull request should focus on one particular improvement to dionaea.
- Create different pull requests for unrelated features or bugfixes.
- Python code should follow `PEP 8`_, especially in the "do what code around you does" sense.

Documentation
^^^^^^^^^^^^^

When introducing new functionality, please remember to write documentation.

First time setup
^^^^^^^^^^^^^^^^

- Download and install the `latest version of git`_
- Configure git with your username and email

.. code::

    $ git config user.name 'Your Name'
    $ git config user.email 'your.email@example.org'

- Make sure you have a `GitHub account`_
- Fork dionaea to your GitHub account by using the Fork button
- Clone the main repository locally

.. code::

    $ git clone https://github.com/DinoTools/dionaea.git
    $ cd dionaea

- Add your fork as a remote to push your work to. Replace <username> with your username.

.. code::

    $ git remote add fork https://github.com/<username>/dionaea

- Install `pre-commit`_ by using a virtualenv.

.. code::

    $ python3 -m venv venv_git
    $ source venv_git/bin/activate
    $ pip install pre-commit

- Install pre-commit hooks.

.. code::

    $ pre-commit install

Review
------

Finally, pull requests must be reviewed before merging.
Everyone can perform reviews; this is a very valuable way to contribute, and is highly encouraged.


.. _GitHub issue tracker: https://github.com/DinoTools/dionaea/issues
.. _DinoTools/dionaea: https://github.com/DinoTools/dionaea
.. _PEP 8: https://www.python.org/dev/peps/pep-0008/
.. _latest version of git: https://git-scm.com/downloads
.. _GitHub account: https://github.com/join
.. _pre-commit: https://pre-commit.com/
