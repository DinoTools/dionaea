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

def make_directories(ranges, DSTDIR):
	# create directories
	for r in ranges:
		if r[0] == 'month':
			path = os.path.join(DSTDIR, r[1].strftime("%Y"), r[1].strftime("%m"))
#			print(path)
			if not os.path.exists(path):
				os.makedirs(path)
	
def write_index(ranges, _protocols, DSTDIR):
	# create index.html files
	for r in ranges:
		w = None

		if r[0] == 'all':
			w = open(os.path.join(DSTDIR,"index.html"),"wt")
		elif r[0] == 'year':
			w = open(os.path.join(DSTDIR,r[1].strftime("%Y"),"index.html"),"wt")
		elif r[0] ==  'month':
			w = open(os.path.join(DSTDIR,r[1].strftime("%Y"),r[1].strftime("%m"),"index.html"),"wt")
		if w == None:
			break

		w.write("""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
	"http://www.w3.org/TR/html4/strict.dtd">
	<html>
		<head>
			<title>Summary for the dionaea honeypot</title>
		</head>
		<body>""")

		if r[0] == 'all':
			w.write("""
				<h1>All - {} - {}</h1>""".format(r[1].strftime("%Y-%m-%d"),r[2].strftime("%Y-%m-%d")))

		if r[0] == 'year':
			w.write("""
				<h1>Year - {}</h1>""".format(r[1].strftime("%Y")))

		if r[0] == 'month':
			w.write("""
				<h1>Month - {}</h1>""".format(r[1].strftime("%Y-%m")))


		w.write("""
			<ul>""")

		if r[0] == 'all':
			# Years
			w.write("""
			<li>Years: """)
			for y in ranges:
				if y[0] == 'year':
					w.write("""
			<a href="{}/index.html">{}</a> """.format(y[1].strftime("%Y"),y[1].strftime("%Y")))
			w.write("""
			</li>""")


		if r[0] == "year":
			w.write("""
			<li>All: <a href="../index.html">All</a></li>""")

			# write months
			w.write("""
			<li>Months: """)
			for y in ranges:
				if y[0] == 'month' and y[1].year == r[1].year:
					w.write("""
			<a href="{}/index.html">{}-{}</a> """.format(
				y[1].strftime("%m"),
				y[1].strftime("%Y"),
				y[1].strftime("%m")))
			w.write("""
			</li>""")
		if r[0] == "month":
			w.write("""
			<li>All: <a href="../../index.html">All</a></li>""")

			w.write("""
			<li>Year: <a href="../index.html">{}</a> """.format(
				y[1].strftime("%Y")))
			w.write("""
			</li>""")

			
		
		# Overviews
		w.write("""
		<li>Overview: """)
		for p in _protocols:
			w.write("""
		<a href="#overview_{}">{}</a>""".format(p,p))
		w.write("""
		</li>""")

		w.write("""
			</ul>""")

	
		w.write("""
			<h2>Overviews</h2>
			<h3>Any</h3>
			<img src="dionaea-overview.png" alt="Overview for Any">""")

		for p in _protocols:
			w.write("""
			<h3 id="overview_{}">Overview {}</h3>
			<img src="dionaea-overview-{}.png" alt="Overview for {}">""".format(p,p,p,p))
		w.write("""	</body>
	</html>""")
		w.close()
	

def get_overview_data(cursor, protofilter, dstfile):
	r = cursor.execute("""SELECT 
		strftime('%Y-%m-%d',connection_timestamp,'unixepoch','localtime') AS date,
		( -- remote hosts
			SELECT 
				COUNT(DISTINCT a.remote_host)
			FROM
				connections as a
			{0}
			GROUP BY 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime')
			HAVING 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime') 
						= strftime('%Y-%m-%d',connections.connection_timestamp,'unixepoch','localtime')
		) AS hosts,
		( -- accepted tcp connection
			SELECT 
				COUNT(*)
			FROM
				connections as a
			{0}
			GROUP BY 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime')
			HAVING 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime') 
						= strftime('%Y-%m-%d',connections.connection_timestamp,'unixepoch','localtime')
		) AS accepts,
		( -- detected shellcode
			SELECT 
				COUNT(*)
			FROM
				emu_profiles
				NATURAL JOIN connections AS a
			{0}
			GROUP BY 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime')
			HAVING 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime') 
						= strftime('%Y-%m-%d',connections.connection_timestamp,'unixepoch','localtime')
		) AS shellcodes,	
		( -- offers 
			SELECT 
				COUNT(*) 
			FROM 
				offers
				NATURAL JOIN connections AS a
			{0}
			GROUP BY 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime')
			HAVING 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime') 
						= strftime('%Y-%m-%d',connections.connection_timestamp,'unixepoch','localtime')
		) AS offers,
		( -- downloads
			SELECT 
				COUNT(*) 
			FROM 
				downloads
				NATURAL JOIN connections AS a
				NATURAL JOIN offers			
			{0}
			GROUP BY 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime')
			HAVING 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime') 
						= strftime('%Y-%m-%d',connections.connection_timestamp,'unixepoch','localtime')
		) AS downloads,
		( -- uniq
			SELECT 
				COUNT(DISTINCT downloads.download_md5_hash) 
			FROM 
				downloads
				NATURAL JOIN connections AS a
				NATURAL JOIN offers			
			{0}
			GROUP BY 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime')
			HAVING 
				strftime('%Y-%m-%d',a.connection_timestamp,'unixepoch','localtime') 
						= strftime('%Y-%m-%d',connections.connection_timestamp,'unixepoch','localtime')
		) AS uniq,	
		( -- newfiles
			SELECT 
				COUNT(*) 
			FROM
				(
					SELECT
						b.download_md5_hash
					FROM 
						downloads AS b
						JOIN connections AS a ON(a.connection = b.connection)
						NATURAL JOIN offers
						{0}
					GROUP BY 
						b.download_md5_hash
					HAVING 
						strftime('%Y-%m-%d',MIN(a.connection_timestamp),'unixepoch','localtime') 
						= strftime('%Y-%m-%d',MAX(connections.connection_timestamp),'unixepoch','localtime')
				)
		)AS newfiles
	FROM 
		connections
	GROUP BY
		date
	ORDER BY 
		connection_timestamp DESC;""".format(protofilter))

	r = resolve_result(r)
	# copy data
	data = {}
	for i in r:
		d = i['date']
		if d not in data:
			data[d] = i

	# fill with zeros
	for d in dates:
		if d not in data:
			data[d] = {'hosts':0,'accepts':0, 'shellcodes':0,'offers':0,'downloads':0,'uniq':0,'newfiles':0}

	# write data file
	w = open(dstfile,"wt")
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
	
def plot_overview_data(ranges, DSTDIR, tempfile, suffix):
	for r in ranges:
		path = ""
		print(r)
		xstart = r[1]
		xstop = r[2]
		boxwidth = "" #set boxwidth 1"
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
			boxwidth = ""

		output = os.path.join(DSTDIR,path,"dionaea-overview{}.png".format(suffix))
		print(output)
	
		w = open("/tmp/dionaea-gnuplot.cmd","wt")
		w.write("""set terminal png size 600,600 nocrop butt font "/usr/share/fonts/truetype/ttf-liberation/LiberationSans-Regular.ttf" 8
	set output "{0}"
	set xdata time
	set timefmt "%Y-%m-%d"
	set xrange ["{1}":"{2}"]
	set format x "%b %d"
	set xlabel "date"
	set ylabel "count"
	set y2label "count"
	set y2tics
	{3}
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
	plot '{4}' using 1:3 title "accept" with boxes fs solid, \\
	"" using 1:4 title "shellcode" with boxes fs solid, \\
	"" using 1:5 title "offers" with boxes fs solid, \\
	"" using 1:6 title "downloads" with boxes fs solid, \\
	"" using 1:7 title "uniq" with boxes fs solid, \\
	"" using 1:8 title "new" with boxes fs solid

	set origin 0.0,0.0
	plot '{4}' using 1:2 title "hosts" with boxes fs solid

	unset multiplot
	""".format(output, xstart, xstop, boxwidth, tempfile))
		w.close()
		os.system("gnuplot /tmp/dionaea-gnuplot.cmd")

if __name__ == "__main__":
	parser = OptionParser()
	parser.add_option("-d", "--database", action="store", type="string", dest="database", default="/opt/dionaea/var/dionaea/logsql.sqlite")
	parser.add_option("-D", "--destination", action="store", type="string", dest="destination", default="/tmp/dionaea-gnuplot")
	parser.add_option("-t", "--tempfile", action="store", type="string", dest="tempfile", default="/tmp/dionaea-gnuplotsql.data")
	parser.add_option('-p', '--protocol', dest='protocols', help='none', 	type="string", action="append")
	(options, args) = parser.parse_args()
	
	dbh = sqlite3.connect(options.database)
	cursor = dbh.cursor()
	(ranges,dates) = get_ranges_from_db(cursor)
	make_directories(ranges, options.destination)
#	protocols = ["smbd","epmapper","httpd"]
	write_index(ranges, options.protocols, options.destination)

	# general overview
	print("[+] getting data for general overview")
	get_overview_data(cursor, "", options.tempfile)
	plot_overview_data(ranges, options.destination, options.tempfile, "")

	# protocols
	for p in options.protocols:
		print("[+] getting data for {} overview".format(p))
		get_overview_data(cursor, """JOIN connections AS root ON(a.connection_root = root.connection) WHERE root.connection_protocol = '{}' """.format(p), options.tempfile)
		plot_overview_data(ranges, options.destination, options.tempfile, "-{}".format(p))
	

