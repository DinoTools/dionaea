#!/opt/dionaea/bin/python3

import sqlite3
import os
import datetime
import calendar
from optparse import OptionParser

def resolve_result(resultcursor):
	names = [resultcursor.description[x][0] for x in range(len(resultcursor.description))]
	resolvedresult = [ dict(zip(names, i)) for i in resultcursor]
	return resolvedresult

def get_ranges_from_db(cursor):
	# create list of *all* days
	ranges = []
	dates = []

	r = cursor.execute("""SELECT 
		strftime('%Y-%m-%d',MIN(connection_timestamp),'unixepoch','localtime') AS start,
		strftime('%Y-%m-%d',MAX(connection_timestamp),'unixepoch','localtime') AS stop
	FROM 
		connections""")

	r = resolve_result(r)
	# round start and stop by month
	start = datetime.datetime.strptime(r[0]['start'], "%Y-%m-%d")
	start = datetime.datetime(start.year,start.month,1)

	stop = datetime.datetime.strptime(r[0]['stop'], "%Y-%m-%d")
	stop = datetime.datetime(stop.year,stop.month,1)+datetime.timedelta(days=calendar.monthrange(stop.year,stop.month)[1])-datetime.timedelta(seconds=1)

	# create a list of ranges
	# (overview|year|month,start,stop)
	ranges.append(("all",start,stop))

	cur = start
	while cur < stop:
		dates.append(cur.strftime("%Y-%m-%d"))
		next = cur + datetime.timedelta(1)
		if next.year != cur.year:
			ranges.append((
				"year", 
				datetime.datetime(cur.year,1,1),
				cur)
			)
		if next.month != cur.month:
			ranges.append((
				"month", 
				datetime.datetime(cur.year,cur.month,1),
				cur)
			)
		cur = next

	ranges.append((
		"year", 
		datetime.datetime(cur.year,1,1),
		datetime.datetime(cur.year+1,1,1)-datetime.timedelta(1))
	)
	ranges.append((
		"month", 
		datetime.datetime(cur.year,cur.month,1),
		datetime.datetime(cur.year,cur.month,1)+datetime.timedelta(days=calendar.monthrange(stop.year,stop.month)[1])-datetime.timedelta(seconds=1))
	)
	return (ranges,dates)

def make_directories(ranges, path_destination):
	# create directories
	for r in ranges:
		if r[0] == 'month':
			path = os.path.join(path_destination, r[1].strftime("%Y"), r[1].strftime("%m"))
#			print(path)
			if not os.path.exists(path):
				os.makedirs(path)

	paths = [
		os.path.join(
			path_destination,
			"gnuplot"
		),
		os.path.join(
			path_destination,
			"gnuplot",
			"data"
		)
	]
	for path in paths:
		if not os.path.exists(path):
			os.makedirs(path)
	
def write_index(ranges, _protocols, DSTDIR, image_ext):
	tpl_html="""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
		"http://www.w3.org/TR/html4/strict.dtd">
		<html>
			<head>
				<title>Summary for the dionaea honeypot</title>
			</head>
			<body>
				<h1>{headline}</h1>
				<ul>
					<li>{menu_all_label}: {menu_all}</li>
					<li>{menu_timerange_label}: {menu_timerange}</li>
					<li>{menu_overview_label}: {menu_overview}</li>
					<li>{menu_data_label}: {menu_data}</li>
					<li>{menu_plot_label}: {menu_plot}</li>
				</ul>

				<h2>Overviews</h2>
				{images}
			</body>
		</html>
	"""

	# create index.html files
	for r in ranges:
		web_headline = ""
		if r[0] == 'all':
			web_headline = "All - {} - {}".format(
				r[1].strftime("%Y-%m-%d"),
				r[2].strftime("%Y-%m-%d")
			)

		if r[0] == 'year':
			web_headline = "Year - {}".format(
				r[1].strftime("%Y")
			)

		if r[0] == 'month':
			web_headnline = "Month - {}".format(
				r[1].strftime("%Y-%m")
			)

		web_menu_timerange_label = ""
		web_menu_timeranges = []
		if r[0] == "all":
			web_menu_all_label = "All"
			web_menu_all = """<a href="index.html">All</a></li>"""

			# Years
			web_menu_timerange_label = "Years"
			for y in ranges:
				if y[0] != 'year':
					continue
				web_menu_timeranges.append(
					"""<a href="{}/index.html">{}</a> """.format(
						y[1].strftime("%Y"),
						y[1].strftime("%Y")
					)
				)

		if r[0] == "year":
			web_menu_all_label = "All"
			web_menu_all = """<a href="../index.html">All</a></li>"""

			# write months
			web_menu_timerange_label = "Months"
			for y in ranges:
				if y[0] != 'month' or y[1].year != r[1].year:
					continue
				web_menu_timeranges.append(
					"""<a href="{}/index.html">{}-{}</a>""".format(
						y[1].strftime("%m"),
						y[1].strftime("%Y"),
						y[1].strftime("%m")
					)
				)
		if r[0] == "month":
			web_menu_all_label = "All"
			web_menu_all = """<a href="../../index.html">All</a></li>"""

			web_menu_timerange_label = "Year"
			web_menu_timeranges.append(
				"""<a href="../index.html">{}</a> """.format(
					y[1].strftime("%Y")
				)
			)

		# Overviews
		web_menu_overview_label = "Overview"
		web_menu_overviews = []
		for p in _protocols:
			web_menu_overviews.append(
				"""<a href="#overview_{}">{}</a>""".format(p,p)
			)

		web_menu_data_label = "Data"
		web_menu_datas = []
		for p in ["overview"] + _protocols:
			path_data = ""
			if r[0] == 'all':
				path_data = "gnuplot/data/" + p + ".data"
			if r[0] == "year":
				path_data = "../gnuplot/data/" + p + ".data"
			if r[0] == "month":
				path_data = "../../gnuplot/data/" + p + ".data"

			web_menu_datas.append("""<a href="{}">{}</a> """.format(path_data, p))

		rstart = r[1].strftime("%Y-%m-%d")
		rstop = r[2].strftime("%Y-%m-%d")
		web_menu_plot_label = "Plot"
		web_menu_plots = []
		for p in ["overview"] + _protocols:
			path_data = ""
			if r[0] == 'all':
				path_data = "gnuplot"
			if r[0] == "year":
				path_data = "../gnuplot"
			if r[0] == "month":
				path_data = "../../gnuplot"

			web_menu_plots.append(
				"""
				<a href="{path_data}/{protocol}_{range}_{start}_{stop}.cmd">{protocol}</a>
				""".format(
					path_data=path_data,
					protocol=p,
					range=r[0],
					start=rstart,
					stop=rstop
				)
			)

		web_images = """ 
			<h3>Any</h3>
			<img src="dionaea-overview.{image_ext}" alt="Overview for Any">
		""".format(
			image_ext=image_ext
		)

		for p in _protocols:
			web_images = web_images + """
				<h3 id="overview_{protocol}">Overview {protocol}</h3>
				<img src="dionaea-overview-{protocol}.{image_ext}" alt="Overview for {protocol}">
			""".format(
				protocol=p,
				image_ext=image_ext
			)

		content = tpl_html.format(
			headline=web_headline,
			menu_all_label=web_menu_all_label,
			menu_all=web_menu_all,
			menu_timerange_label=web_menu_timerange_label,
			menu_timerange=" ".join(web_menu_timeranges),
			menu_overview_label=web_menu_overview_label,
			menu_overview=" ".join(web_menu_overviews),
			menu_data_label=web_menu_data_label,
			menu_data=" ".join(web_menu_datas),
			menu_plot_label=web_menu_plot_label,
			menu_plot=" ".join(web_menu_plots),
			images=web_images
		)
			

		w = None

		if r[0] == 'all':
			w = open(os.path.join(DSTDIR,"index.html"),"wt")
		elif r[0] == 'year':
			w = open(os.path.join(DSTDIR,r[1].strftime("%Y"),"index.html"),"wt")
		elif r[0] ==  'month':
			w = open(os.path.join(DSTDIR,r[1].strftime("%Y"),r[1].strftime("%m"),"index.html"),"wt")

		if w == None:
			break

		w.write(content)
		w.close()
	

def get_overview_data(cursor, path_destination, filename_data, protocol):
	data = {}
	sql = {}
	sql["downloads"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			count(*) AS num
		FROM
			connections AS conn
			NATURAL JOIN downloads
		{where}
		GROUP BY
			strftime('{time_format}',conn.connection_timestamp,'unixepoch','localtime')
		ORDER BY
			conn.connection_timestamp;
	"""
	sql["offers"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			count(*) AS num
		FROM
			connections AS conn
			NATURAL JOIN offers
		{where}
		GROUP BY
			strftime('{time_format}',conn.connection_timestamp,'unixepoch','localtime')
		ORDER BY
			conn.connection_timestamp;
	"""
	sql["shellcodes"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			count(*) AS num
		FROM
			connections AS conn
			NATURAL JOIN emu_profiles
		{where}
		GROUP BY
			strftime('{time_format}',conn.connection_timestamp,'unixepoch','localtime')
		ORDER BY
			conn.connection_timestamp;
	""";
	sql["accepts"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			count(*) AS num
		FROM
			connections AS conn
		{where}
		GROUP BY
			strftime('{time_format}',conn.connection_timestamp,'unixepoch','localtime')
		ORDER BY
			conn.connection_timestamp;
	"""
	sql["uniq"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			count(DISTINCT downloads.download_md5_hash) as num
		FROM
			downloads
			NATURAL JOIN connections AS conn
			NATURAL JOIN offers JOIN connections AS root ON(conn.connection_root = root.connection)
		{where}
		GROUP BY
			strftime('{time_format}',conn.connection_timestamp,'unixepoch','localtime')
		ORDER BY
			conn.connection_timestamp;
	"""
	sql["newfiles"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			count(down.download_md5_hash) AS num
		FROM
			downloads AS down
			JOIN connections AS conn ON(down.connection = conn.connection)
			NATURAL JOIN offers
			JOIN connections AS root ON(conn.connection_root = root.connection)
		{where}
		GROUP BY
			down.download_md5_hash
		ORDER BY
			conn.connection_timestamp;
	"""
	sql["hosts"] = """
		SELECT
			strftime('%Y-%m-%d',conn.connection_timestamp,'unixepoch','localtime') AS date,
			COUNT(DISTINCT conn.remote_host) as num
		FROM
			connections as conn
		{where}
		GROUP BY
			strftime('{time_format}',conn.connection_timestamp,'unixepoch','localtime')
		ORDER BY
			conn.connection_timestamp;
	"""
	where = ""
	if protocol != "":
		where ="""
			WHERE
				conn.connection_protocol='{protocol}'
		"""

	where = where.format(
		protocol=protocol
	)

	for t in list(sql.keys()):
		print("Selecting %s ..." % t)
		db_query = sql[t].format(
			time_format="%Y-%m-%d",
			where=where
		)
		#print(db_query)
		db_res = cursor.execute(db_query)
		db_data = resolve_result(db_res)

		for db_row in db_data:
			date = db_row["date"]
			if not date in data:
				data[date] = {}
				for k in list(sql.keys()):
					data[date][k] = 0
			data[date][t] = str(db_row["num"])

	# fill with zeros
	for date in dates:
		if date not in data:
			data[date] = {}
			for k in list(sql.keys()):
				data[date][k] = 0

	# write data file
	w = open(filename_data,"wt")
	for d in dates:
		a = data[d]
		w.write("{}|{}|{}|{}|{}|{}|{}|{}\n".format(d,
			a['hosts'],
			a['accepts'],
			a['shellcodes'],
			a['offers'],
			a['downloads'],
			a['uniq'],
			a['newfiles']))
	w.close()
	
def plot_overview_data(ranges, path_destination, filename_data, protocol, filename_tpl, image_ext):
	suffix = ""
	prefix = "overview"
	if protocol != "":
		suffix = "-{}".format(protocol)
		prefix = protocol

	tpl_gnuplot ="""set terminal png size 600,600 nocrop butt font "/usr/share/fonts/truetype/ttf-liberation/LiberationSans-Regular.ttf" 8
	set output "{filename_output}"
	set xdata time
	set timefmt "%Y-%m-%d"
	set xrange ["{range_start}":"{range_stop}"]
	set format x "%b %d"
	set xlabel "date"
	set ylabel "count"
	set y2label "count"
	set y2tics
	set grid

	set size 1.0,0.5

	set style line 1 lt rgb "#00C613" # aqua
	set style line 2 lt rgb "#6AFFA0" #
	set style line 3 lt rgb "#23FF38"
	set style line 4 lt rgb "#75BF0F"
	set style line 5 lt rgb "#A1FF00"
	set style line 6 lt rgb "red" # "#D6FFBF" # deepskyblue

	unset logscale y
	set datafile separator "|"
	set multiplot

	set origin 0.0,0.5
	plot "{filename_data}" using 1:3 title "accept" with boxes fs solid, \\
		"" using 1:4 title "shellcode" with boxes fs solid, \\
		"" using 1:5 title "offers" with boxes fs solid, \\
		"" using 1:6 title "downloads" with boxes fs solid, \\
		"" using 1:7 title "uniq" with boxes fs solid, \\
		"" using 1:8 title "new" with boxes fs solid

	set origin 0.0,0.0
	plot "{filename_data}" using 1:2 title "hosts" with boxes fs solid

	unset multiplot
	"""

	if filename_tpl != None and os.path.exists(filename_tpl) and os.path.isfile(filename_tpl):
		fp = open(filename_tpl, "rt")
		tpl_gnuplot = fp.read()
		fp.close()

	for r in ranges:
		path = ""
		print(r)
		xstart = r[1]
		xstop = r[2]
		if r[0] == 'all':
			rstart = xstart.strftime("%Y-%m-%d")
			rstop = xstop.strftime("%Y-%m-%d")
			title = 'all {}-{}'.format(rstart,rstop)
		elif r[0] == 'year':
			rstart = xstart.strftime("%Y-%m-%d")
			rstop = xstop.strftime("%Y-%m-%d")
			title = 'year {}-{}'.format(rstart,rstop)
			path = xstart.strftime("%Y")
		elif r[0] == 'month':
			rstart = xstart.strftime("%Y-%m-%d")
			rstop = xstop.strftime("%Y-%m-%d")
			title = 'month {}-{}'.format(rstart,rstop)
			path = os.path.join(xstart.strftime("%Y"),xstart.strftime("%m"))

		output = os.path.join(path_destination, path, "dionaea-overview{}.{}".format(suffix, image_ext))
		filename_gnuplot = os.path.join(
			path_destination,
			"gnuplot",
			"{prefix}_{range}_{start}_{stop}.cmd".format(
				prefix=prefix,
				range=r[0],
				start=rstart,
				stop=rstop
			)
		)

		w = open(filename_gnuplot, "wt")
		w.write(
			tpl_gnuplot.format(
				filename_output=output,
				range_start=xstart,
				range_stop=xstop,
				filename_data=filename_data
			)
		)
		w.close()

		os.system("gnuplot {}".format(filename_gnuplot))

if __name__ == "__main__":
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", type="string", dest="database", default="/opt/dionaea/var/dionaea/logsql.sqlite")
	parser.add_option("-D", "--destination", action="store", type="string", dest="destination", default="/tmp/dionaea-gnuplot")
	parser.add_option("-t", "--tempfile", action="store", type="string", dest="tempfile", default="/tmp/dionaea-gnuplotsql.data")
	parser.add_option('-p', '--protocol', dest='protocols', help='none', 	type="string", action="append")
	parser.add_option('-g', '--gnuplot-tpl', dest='gnuplot_tpl', help='none', type="string", action="store", default=None)
	parser.add_option('', '--image-ext', dest='image_ext', help='none', type="string", action="store", default="png")
	(options, args) = parser.parse_args()
	
	dbh = sqlite3.connect(options.database)
	cursor = dbh.cursor()
	(ranges,dates) = get_ranges_from_db(cursor)
	make_directories(ranges, options.destination)
#	protocols = ["smbd","epmapper","httpd"]
	write_index(
		ranges,
		options.protocols,
		options.destination,
		options.image_ext
	)

	# general overview
	print("[+] getting data for general overview")
	filename_data = os.path.join(
		options.destination,
		"gnuplot",
		"data",
		"overview.data"
	)
	get_overview_data(cursor, options.destination, filename_data, "")
	plot_overview_data(
		ranges,
		options.destination,
		filename_data,
		"",
		options.gnuplot_tpl,
		options.image_ext
	)

	# protocols
	for protocol in options.protocols:
		filename_data = os.path.join(
			options.destination,
			"gnuplot",
			"data",
			protocol + ".data"
		)
		print("[+] getting data for {} overview".format(protocol))
		get_overview_data(
			cursor,
			options.destination,
			filename_data,
			protocol
		)
		plot_overview_data(
			ranges,
			options.destination,
			filename_data,
			protocol,
			options.gnuplot_tpl,
			options.image_ext
		)
	

