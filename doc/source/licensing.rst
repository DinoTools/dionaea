..
    This file is part of the dionaea honeypot

Licensing rules
===============

The dionaea honeypot is provided under the terms of the GNU General Public License version 2 or any later (GPL-2.0+)

This documentation file provides a description of how each source file should be annotated to make its license clear and unambiguous.
It doesn't replace dionaeas license.

The license described in the LICENSE file applies to the dionaea source as a whole, though individual source files can have a different license which is required to be compatible with the GPL-2.0::

    GPL-3.0+  :  GNU General Public License v2.0 or later
    LGPL-2.0  :  GNU Library General Public License v2 only
    LGPL-2.0+ :  GNU Library General Public License v2 or later
    LGPL-2.1  :  GNU Lesser General Public License v2.1 only
    LGPL-2.1+ :  GNU Lesser General Public License v2.1 or later

Aside from that, individual files can be provided under a dual license, e.g. one of the compatible GPL variants and alternatively under a permissive license like BSD, MIT etc.

A common way of expressing the license of a source file is to add the matching boilerplate text into the top comment of the file. Due to formatting, typos etc. these "boilerplates" are hard to validate for tools which are used in the context of license compliance.

A replacement to the boilerplate text is the use of Software Package Data Exchange (SPDX) license identifiers in each source file.  SPDX license identifiers are machine parsable and precise shorthands for the license under which the content of the file is contributed. SPDX license identifiers are managed by the SPDX Workgroup at the Linux Foundation and have been agreed on by partners throughout the industry, tool vendors, and legal teams.  For further information see https://spdx.org/

The dionaea honeypot requires the precise SPDX identifier in all source files. The REUSE tool from the FSFE is used to check if all required information are set. For additional information and formatting see https://reuse.software/

License identifier syntax
-------------------------

1. Placement:

    The SPDX license identifier in source files shall be added at the first possible position in a file which can contain a comment.

2. Style:

    The SPDX license identifier is added in form of a comment.  The comment style depends on the file type:

    C source and header::

        /**
         * This file is part of the dionaea honeypot
         *
         * SPDX-FileCopyrightText: 2019 Jane Doe <jane@example.org>
         *
         * SPDX-License-Identifier: GPL-2.0-or-later
         */

    Python::

        # This file is part of the dionaea honeypot
        #
        # SPDX-FileCopyrightText: 2019 John Doe <john@example.org>
        #
        # SPDX-License-Identifier: GPL-2.0-or-later

    Scripts::

        # This file is part of the dionaea honeypot
        #
        # SPDX-FileCopyrightText: 2019 Jane Doe <jane@example.org>
        #
        # SPDX-License-Identifier: GPL-2.0-or-later


    .rst::

        ..
            This file is part of the dionaea honeypot

            SPDX-FileCopyrightText: 2019 John Doe <john@example.org>

            SPDX-License-Identifier: <SPDX License Expression>


   If a specific tool cannot handle the standard comment style, then the appropriate comment mechanism which the tool accepts shall be used.

Compliance check
----------------

The REUSE tool is used to validate if all recommendations provided bei the REUSE project of the FSFE are met. For more information about the specification have a look at https://reuse.software/ and https://spdx.dev/

Tooling
^^^^^^^

Install the tool.::

    $ pip install reuse

Run the linter.::

    $ reuse lint

git hooks
^^^^^^^^^

The reuse tool has been included in the pre-commit hooks to check compliance on changed files before committing them.
