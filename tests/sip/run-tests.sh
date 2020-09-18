#!/bin/bash

# set default values

PWD=$(pwd)
DATETIME=$(date +%Y%m%d-%H%M%S)

if [ "${LHOST}" == "" ]; then
	LHOST=127.0.0.1
fi

if [ "${RHOST}" == "" ]; then
	RHOST=127.0.0.1
fi

if [ "${VERBOSE}" == "" ]; then
	VERBOSE=0
fi

if [ "${TOOL_SMAP}" == "" ]; then
	TOOL_SMAP=smap
fi

# SNMAP needs its fingerprint db
if [ "${TOOL_SMAP_BASE}" == "" ]; then
	TOOL_SMAP_BASE=.
fi

if [ "${TOOL_SIPP}" == "" ]; then
	TOOL_SIPP=sipp
fi

if [ "${TRANSPORT}" == "" ]; then
	TRANSPORT="udp"
fi

function help_print() {
	echo "Help"
	echo "$0 run|clean|help"
	echo ""
	echo "Commands"
	echo -e "\tclean: remove log files and so on"
	echo -e "\thelp:  display this help"
	echo -e "\trun:   run all tests"
	echo ""
	echo "Environment vars"
	echo -e "\tLHOST:     The IP Address of the local computer"
	echo -e "\tRHOST:     The IP Address of the SIP server"
	echo -e "\tTRANSPORT: Transport mode. (tcp|udp)"
	echo -e "\tVERBOSE:   Verbosity from 0(no logging) to 2(more logging)"
	echo -e "\tTools:"
	echo -e "\t\tTOOL_SIPP - sipp tool"
	echo -e "\t\tTOOL_SMAP - smap tool"
	echo -e "\t\tTOOL_SMAP_BASE - path where to run smap"
	echo ""
	echo "Example"
	echo -e "\tLHOST=192.168.1.2 RHOST=192.168.1.1 ./run_tests.sh run"
	echo -e "\t./run_tests.sh clean"
	echo ""
}


function print_debug() {
	if [ $VERBOSE -gt 1 ]; then
		print_msg "$1" "blue"
	fi
}

function print_error() {
	print_msg "$1" "red"
}

function print_info() {
	if [ $VERBOSE -gt 0 ]; then
		print_msg "$1" "blue"
	fi
}

function print_ok() {
	print_msg "$1" "green"
}

function print_warning() {
	print_msg "$1" "orange"
}
	
function print_msg() {
	TXTBLUE="\e[0;34m"
	TXTGREEN="\e[0;32m"
	TXTRED="\e[0;31m"
	TXTYELLOW="\e[0;33m"
	TXTRESET="\e[0m"

	case $2 in
		"blue")
			echo -ne $TXTBLUE
			;;
		"red")
			echo -ne $TXTRED
			;;
		"green")
			echo -ne $TXTGREEN
			;;
		"yellow"|"orange")
			echo -ne $TXTYELLOW
			;;
	esac
	echo $1
	echo -ne $TXTRESET
}

function sipp_clean() {
	echo "Cleaning sipp ..."
	(cd sipp && rm *.log)
}

function sipp_run() {
	echo -e "\n=== SIPP ===\n"
	if [ "${SIPP_PARAMS}" == "" ]; then
		if [ "${VERBOSE}" -gt "0" ]; then
			SIPP_PARAMS=-trace_err
		fi
		if [ "${VERBOSE}" -gt "1" ]; then
			SIPP_PARAMS="-trace_msg -trace_err -trace_screen"
		fi
		if [ "${TRANSPORT}" == "udp" ]; then
			SIPP_PARAMS=$SIPP_PARAMS" -t un"
		fi
		if [ "${TRANSPORT}" == "tcp" ]; then
			SIPP_PARAMS=$SIPP_PARAMS" -t tn"
		fi
	fi

	echo -n "REGISTER(w/o password): "
	CMD="cd sipp && ${TOOL_SIPP} -sf register.xml -m 1 -l 1 ${SIPP_PARAMS} -i ${LHOST} -max_retrans 0 -inf user.csv ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> /dev/null)
	if [ $? == 0 ]; then
		print_ok "OK"
	else
		print_error "Failed"
	fi

	echo -n "REGISTER(with password): "
	CMD="cd sipp && ${TOOL_SIPP} -sf register_pw.xml -m 1 -l 1 ${SIPP_PARAMS} -i ${LHOST} -max_retrans 0 -inf user_pw.csv ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> /dev/null)
	if [ $? == 0 ]; then
		print_ok "OK"
	else
		print_warning "Authentication requires OpenSSL support! Please re-check manually."
		print_error "Failed"
	fi

	echo -n "INVITE ACK BYE: "
	CMD="cd sipp && ${TOOL_SIPP} -sf uac.xml -s 500 -m 1 -l 1 -d 500 ${SIPP_PARAMS} -i ${LHOST} -max_retrans 0 ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> /dev/null)
	if [ $? == 0 ]; then 
		print_ok "OK"
	else
		print_error "Failed"
	fi

	echo -n "NEWMETHOD: "
	CMD="cd sipp && ${TOOL_SIPP} -sf newmethod.xml -m 1 -l 1 ${SIPP_PARAMS} -i ${LHOST} -max_retrans 0 -inf user.csv ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> /dev/null)
	if [ $? == 0 ]; then
		print_ok "OK"
	else
		print_error "Failed"
	fi

	echo -n "OPTIONS: "
	CMD="cd sipp && ${TOOL_SIPP} -sf options.xml -m 1 -l 1 ${SIPP_PARAMS} -i ${LHOST} -max_retrans 0 -inf user.csv ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> /dev/null)
	if [ $? == 0 ]; then
		print_ok "OK"
	else
		print_error "Failed"
	fi

	echo -n "Wrong SDP: "
	CMD="cd sipp && ${TOOL_SIPP} -sf error_sdp.xml -m 1 -l 1 ${SIPP_PARAMS} -i ${LHOST} -max_retrans 0 -inf user.csv ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> /dev/null)
	if [ $? == 0 ]; then
		print_ok "OK"
	else
		print_error "Failed"
	fi
}


function smap_clean() {
	echo "Cleaning smap ..."
	rm smap-*.log
}

function smap_run() {
	echo -e "\n=== SMAP ===\n"
	if [ "${SMAP_PARAMS}" == "" ]; then
		if [ "${TRANSPORT}" == "udp" ]; then
			# -u doesn't work
			SMAP_PARAMS=$SMAP_PARAMS""
		fi
		if [ "${TRANSPORT}" == "tcp" ]; then
			print_warning "TCP support seams to be a little bit buggy"
			SMAP_PARAMS=$SMAP_PARAMS" -t"
		fi
	fi
	echo -n "Scanning ... "
	FILE=$PWD/smap-$DATETIME.log
	CMD="cd ${TOOL_SMAP_BASE} && ${TOOL_SMAP} ${SMAP_PARAMS} -d -o ${RHOST}"
	print_debug "$CMD"
	(eval $CMD &> $FILE)
	awk "/^$RHOST.*, SIP enabled/{exit 1} /^$RHOST.*, SIP disabled/{exit 2}" $FILE
	case $? in
		1)
			print_ok "OK - SIP enabled"
			;;
		2)
			print_error "Failed - SIP disabled or not detected"
			;;
		*)
			print_warning "An error occurs"
			;;
	esac
}

case $1 in
	"run")
		sipp_run
		smap_run
		;;
	"clean")
		sipp_clean
		smap_clean
		;;
	* )
		help_print
		;;
esac
