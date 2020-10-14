# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

all:
	test -e venv || virtualenv --python=/usr/bin/python3 venv
	( \
		. ./venv/bin/activate; \
		pip install -r requirements.txt; \
		py.test tests/; \
	)
	# rm -rf venv
