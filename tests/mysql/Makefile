all:
	test -e venv || virtualenv --python=/usr/bin/python3 venv
	( \
		. ./venv/bin/activate; \
		pip install -r requirements.txt; \
		py.test tests/; \
	)
	# rm -rf venv