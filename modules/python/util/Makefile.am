AUTOMAKE_OPTIONS = foreign

bin_SCRIPTS = readlogsqltree gnuplotsql
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = readlogsqltree.py gnuplotsql.py


do_subst = sed -e 's,[@]PYTHON[@],$(PYTHON),g'

readlogsqltree: readlogsqltree.py
	$(do_subst) < readlogsqltree.py > readlogsqltree
	chmod +x readlogsqltree

gnuplotsql: gnuplotsql.py
	$(do_subst) < gnuplotsql.py > gnuplotsql
	chmod +x gnuplotsql

install-exec-hook:
	-rm -f $(bin_SCRIPTS)
