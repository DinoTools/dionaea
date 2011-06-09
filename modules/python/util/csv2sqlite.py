#!/usr/bin/env python
#
# create a sqlite database from a csv file
# creates table schema and inserts rows
# can handle multiple csv files
# 
# ./csv2sqlite a.csv bs.csv
# will create tables a and bs and bs will get the primary key of type integer "b"
#  

import sqlite3
import csv
import sys
import argparse
import codecs

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Update a sqlite Database with random but correct cc numbers')
	parser.add_argument('--database', help='the database to create', required=True)
	parser.add_argument('--primary-key', help='create a primary key')
	parser.add_argument('files', nargs='*', help='csv files to use as input')
	args = parser.parse_args()

	dbh = sqlite3.connect(args.database)
	cursor = dbh.cursor()

	for f in args.files:
		print("Processing File %s" % (f,))
		c = csv.reader(codecs.open(f, 'r', encoding="utf-8-sig"), delimiter=',', quotechar='"')
		table = f[:-4]
		colnames = c.next()
		print("Using column names %s" % " ".join(colnames))
		cols = ','.join(colnames)
		if args.primary_key is not None:
			cols2 = "%s INTEGER PRIMARY KEY, " % args.primary_key + cols
		else:
			cols2 = cols
		create_table = "CREATE TABLE %s ( %s )" % (table, cols2)
		insert_into = "INSERT INTO %s (%s) VALUES (%s) " % (table, cols, ','.join(['?' for i in colnames]))

		try:
			dbh.execute(create_table)
		except Exception as e:
			print("Could not CREATE table %s (%s))" % (table,e))
			continue
		for i in c:
			try:		
				cursor.execute(insert_into, i)
			except Exception as e:
				print("Could not insert %s into table %s (%s)" % (i,table,e))
				print(insert_into)
		for i in cols:
			create_idx = "CREATE INDEX %s_idx ON %s (%s)" % (i,table,i)
		dbh.commit()
			
			

