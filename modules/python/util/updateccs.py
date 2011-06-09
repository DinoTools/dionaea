#!/opt/dionaea/bin/python3
#
# 
# Basing on:
# gencc: A simple program to generate credit card numbers that pass the MOD 10 check
# (Luhn formula).
# Usefull for testing e-commerce sites during development.
# 
# Copyright 2003 Graham King
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# http://www.darkcoding.net/credit-card-generator/
#

from random import Random
import sys
import copy
import sqlite3
import argparse

visaPrefixList = [ 	['4', '5', '3', '9'], 
					['4', '5', '5', '6'], 
					['4', '9', '1', '6'],
					['4', '5', '3', '2'], 
					['4', '9', '2', '9'],
					['4', '0', '2', '4', '0', '0', '7', '1'],
					['4', '4', '8', '6'],
					['4', '7', '1', '6'],
					['4'] ]

mastercardPrefixList = [    ['5', '1'],
							['5', '2'],
							['5', '3'],
							['5', '4'],
							['5', '5'] ]

amexPrefixList = [  ['3', '4'],
					['3', '7'] ]

discoverPrefixList = [ ['6', '0', '1', '1'] ]

dinersPrefixList = [    ['3', '0', '0'],
						['3', '0', '1'],
						['3', '0', '2'],
						['3', '0', '3'],
						['3', '6'],
						['3', '8'] ]

enRoutePrefixList = [   ['2', '0', '1', '4'],
						['2', '1', '4', '9'] ]

jcbPrefixList16 = [   ['3', '0', '8', '8'],
					['3', '0', '9', '6'],
					['3', '1', '1', '2'],
					['3', '1', '5', '8'],
					['3', '3', '3', '7'],
					['3', '5', '2', '8'] ]

jcbPrefixList15 = [ ['2', '1', '0', '0'],
					['1', '8', '0', '0'] ]

voyagerPrefixList = [ ['8', '6', '9', '9'] ]                    
					

"""
'prefix' is the start of the CC number as a string, any number of digits.
'length' is the length of the CC number to generate. Typically 13 or 16
"""
def completed_number(prefix, length):
	ccnumber = prefix

	# generate digits
	while len(ccnumber) < (length - 1):
		digit = generator.choice(['0',  '1', '2', '3', '4', '5', '6', '7', '8', '9'])
		ccnumber.append(digit)

	# Calculate sum 
	sum = 0
	pos = 0
	reversedCCnumber = []
	reversedCCnumber.extend(ccnumber)
	reversedCCnumber.reverse()

	while pos < length - 1:
		odd = int( reversedCCnumber[pos] ) * 2
		if odd > 9:
			odd -= 9
		sum += odd
		if pos != (length - 2):
			sum += int( reversedCCnumber[pos+1] )
		pos += 2
	# Calculate check digit
	checkdigit = ((sum / 10 + 1) * 10 - sum) % 10
	ccnumber.append( str(checkdigit) )
	return ''.join(ccnumber)


def credit_card_number(generator, prefixList, length):
	if type(length) is list:
		length = generator.choice(length)
	ccnumber = copy.copy( generator.choice(prefixList) )
	return completed_number(ccnumber, length)

generator = None

def gencc(card):
	global generator
	cards = { "MasterCard": { "prefix" : mastercardPrefixList, "length": 16 },
			  "Visa":{ "prefix" : visaPrefixList, "length": [13,16] },
			  "AmericanExpress":{ "prefix" : amexPrefixList, "length": 15 },
			}
	if generator is None:
		generator = Random()
		generator.seed()        # Seed from current time

	if card in cards:
		return credit_card_number(generator, cards[card]['prefix'], cards[card]['length'])
	raise ValueException("card %s is unknown" % card)

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Update a sqlite Database with random but correct cc numbers')
	parser.add_argument('database', help='the database to use')
	parser.add_argument('--table', help='the table to update', required=True)
	parser.add_argument('--type-col', help='the column containing the cc type', required=True)
	parser.add_argument('--num-col', help='the column containing the cc number', required=True)
	args = parser.parse_args()

	dbh = sqlite3.connect(args.database)
	dbh.create_function("gencc",1,gencc)

	cursor = dbh.cursor()
	query = "UPDATE {:s} SET {:s}=CAST(gencc({:s}) AS INTEGER)".format(args.table,args.num_col,args.type_col)
	print(query)
	cursor.execute(query)
	dbh.commit()
	print("updated the ccs for %i rows" % cursor.rowcount)

