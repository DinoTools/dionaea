# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2019 Michael Neu
#
# SPDX-License-Identifier: GPL-2.0-or-later

all:
	test -e venv || virtualenv --python=python3 venv
	( \
		. ./venv/bin/activate; \
		pip install -r requirements.txt; \
		py.test tests/; \
	)
	# rm -rf venv
