#!/bin/bash

##
# ovpn-to-apc.sh
# -----------------------------------------------
# (C) 2009 Patrick Schneider http://goo.gl/5bPqy
# (C) 2012 Stefan Rubner    <stefan@whocares.de>
# -----------------------------------------------
# Changes:
# 2012-05-26
#   Stefan Rubner:
#    * Started work on making the script work
#      with embedded certs and keys (tnx Alois)
# 2012-04-17
#   Stefan Rubner:
#    * Fixed tr calls to also strip \r in .ovpn
#      files created on Windows
#    * Added some defaults for settings that may
#      not be present in the .ovpn but are needed
#      by the Astaro Security Gateway
#    * reformatted the code a bit and added some
#      comments
# 2009-01-22
#   Patrick Schneider:
#    * initial revision
# -----------------------------------------------
# Usage:
#    ovpn-to-apc.sh $1 $2 [$3 [$4]]
#
# $1 : OpenVPN Config File
# $2 : Astaro .apc to create
# $3 : username
# $4 : password
#
##

########
# Functions
########

##
# Write .apc header
##
write_header() {
    printf "\x04\x06\x041234\x04\x04\x04\x08\x03\x0c\x00\x00\x00\x0a" > ${ApcFile}
}

##
# Get the CA either from supplied file
# or from XMLish definition within the
# .ovpn file
##
get_ca() {
    if [ -z "${isxml}" ]; then
        ca=`grep "^ca " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
    else
    	ca="${TmpDir}/ca.crt"
		sed -n "/<ca>/,/<\/ca>/p" ${OvpnFile} | grep -v "ca>" > ${ca} 
	fi
}

##
# Get the key either from supplied file
# or from XMLish definition within the
# .ovpn file
##
get_key() {
    if [ -z "${isxml}" ]; then
		key=`grep "^key " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
    else
    	key="${TmpDir}/user.key"
		sed -n "/<key>/,/<\/key>/p" ${OvpnFile} | grep -v "key>" > ${key} 
	fi
}

##
# Get the cert either from supplied file
# or from XMLish definition within the
# .ovpn file
##
get_cert() {
    if [ -z "${isxml}" ]; then
		cert=`grep "^cert " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
    else
    	cert="${TmpDir}/user.cert"
		sed -n "/<cert>/,/<\/cert>/p" ${OvpnFile} | grep -v "cert>" > ${cert} 
	fi
}

##
# Get the tls-auth data 
# from XMLish definition within the
# .ovpn file
##
get_ta() {
	# Create file with the ta.key
	tafile=`mktemp --tmpdir=. --suffix=.key ta_XXXXXXXX`
	sed -n "/<tls-auth>/,/<\/tls-auth>/p" ${OvpnFile} | grep -v "^#" > ${tafile}
	# patch up the server_dn info to include
	# the necessary tls stuff
    takey="${TmpDir}/ta.key"
    echo "/CN=OpenVPN_Server" > ${takey}
    echo "tls-auth /etc/${tafile:2}" >> ${takey}
	echo "key-direction 1" >> ${takey}
}

##
# Get Remote Host's address, port and
# protocol
##
get_host_port_proto() {
	if [ -z "${isxml}" ]; then
		# do it the old way
		RemHost=`grep "^remote " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
		RemPort=`grep "^remote " ${OvpnFile} | cut -d ' ' -f3 |tr -d '\r\n'`
		RemProto=`grep "^proto " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
	else
		# Check whether we have a protocol statement
		RemLine=`grep "^proto " ${OvpnFile}`
		if [ -z "${RemLine}" ]; then
			# Ok, looks like a load balancing setup
			# So we just pick the first of the UDP lines since
			# Access Server seems to like those better
			RemHost=`grep "^remote .*udp" ${OvpnFile} | head -n1 | awk '{ print $2 }'`
			RemPort=`grep "^remote .*udp" ${OvpnFile} | head -n1 | awk '{ print $3 }'`
			RemProto="udp"
		else
			RemHost=`grep "^remote " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
			RemPort=`grep "^port " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
			RemProto=`grep "^proto " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
		fi
	fi
}

##
# Main Script
##
echo "+------------------------------------------------+"
echo "|     OpenVPN .ovpn to Astaro .apc converter     |"
echo "|                                                |"
echo "| (C) 2009 Patrick Schneider, 2012 Stefan Rubner |"
echo "|  https://gitorious.org/admintools/ovpn-to-apc  |"
echo "+------------------------------------------------+"
echo ""

if [ $# -lt 2 ] || [ $# -gt 4 ]; then
    echo Usage:
    echo
    echo [bash] ${0} openvpn-config.ovpn output.apc [username [password]]
    echo
    echo username and password are optional and may be entered by the user
    echo The config file needs to contain the ca, cert and key directives
    echo that point to the corresponding files or it needs to contain the 
	echo certificates and keys directly enclosed in XML-like tags.
    echo
    exit
fi

##
# Remember our input values
##
OvpnFile=${1}
ApcFile=${2}

echo "Using input file        : ${OvpnFile}"
echo ""

if [ $# -gt 2 ] && [ $# -lt 4 ]; then
    # Only username given on command line
    user=${3}
    echo -n "Please enter your password: "
    read pass
    echo ""
elif [ $# -gt 3 ]; then
    # username and password given
    user=${3}
    pass=${4}
else 
    # try to get user from the .ovpn file
    user=`echo $1 | cut -d '@' -f1`
    if [ ${user} = ${1} ]; then
        echo -n "Please enter your username: "
        read user
    fi
    echo -n "Please enter your password: "
    read pass
    echo ""
fi

##
# Passwort field is required by Astaro but
# wrong content doesn't hurt operations
##
if [ -z "${pass}" ]; then
    pass="dummy"
fi

##
# Check for type of .ovpn file
##
isxml=`grep "<ca>" ${1}`
if [ "${isxml}" == "<ca>" ]; then
	isxml=1
	TmpDir=`mktemp -d`
else
	isxml=
fi

# if [ -z "${isxml}" ]; then
    ##
    # Read the filenames from the config-file
    ##
    # ca=`grep "^ca " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
    # key=`grep "^key " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
    # cert=`grep "^cert " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
# fi

echo -n "Getting CA information  : "
get_ca
echo "${ca}"
echo -n "Getting Key information : "
get_key
echo "${key}"
echo -n "Getting Cert information: "
get_cert
echo "${cert}"
echo -n "Getting remote host data: "
get_host_port_proto
echo "${RemHost} : ${RemPort} : ${RemProto}"

echo ""
echo "Writing .apc file       : ${ApcFile}"
echo ""

write_header

##
# Extract protocol (UDP/TCP) from config file
##
var=${RemProto}
# Determine length of the protocol and convert it to hex
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
# Write length to output file
printf "\x${varlen}" >> ${ApcFile}
# Write protocol to output file
echo $var | tr -d '\r\n' >> ${ApcFile}
# Write fix information to output file
printf "\x08\x00\x00\x00" >> ${ApcFile}
echo protocol >>${ApcFile}

##
# HMAC packet authentication
# default: SHA1
## 
var=`grep "^auth " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
if [ -z "${var}" ]; then
  var="SHA1"
fi
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${ApcFile}
echo $var | tr -d '\r\n' >> ${ApcFile}
printf "\x18\x00\x00\x00" >> ${ApcFile}
echo authentication_algorithm | tr -d '\r\n' >> ${ApcFile}

##
# Determine length of user certifcate file
# and put certificate into .apc file
##
varlen=`cat "${cert}" | wc -c`
# Length decimal
hex=`echo "obase=16; ${varlen}" | bc -q` # Length hexadecimal
num=`echo "obase=16; ${varlen}" | bc -q | tr -d '\r\n' | wc -c` # Length of the hex-number
odd=`expr ${num} % 2` # hex-number: even or odd?
# TODO: Add a check for bigger hex-number (more than 4 digits)
if [ ${odd} -eq 0 ]; then 
    # even: swap AABB > BBAA
    varlen1=`echo "obase=16; ${varlen}" | bc -q | cut -b 3,4`
    varlen2=`echo "obase=16; ${varlen}" | bc -q | cut -b 1,2`
else 
    # odd: swap AAB > AB 0A
    varlen1=`echo "obase=16; ${varlen}" | bc -q | cut -b 2,3`
    varlen2=`echo "obase=16; ${varlen}" | bc -q | cut -b 1`
fi
printf "\x1\x${varlen1}\x${varlen2}\x0\x0" >> ${ApcFile}
cat ${cert} >> ${ApcFile}
printf "\xb\x0\x0\x0" >> ${ApcFile}
echo "certificate" | tr -d '\r\n' >> ${ApcFile}

##
# Determine size of CA certificate file
# and put CA certificate into .apc file
##
varlen=`cat ${ca} | wc -c`
hex=`echo "obase=16; ${varlen}" | bc -q`
num=`echo "obase=16; ${varlen}" | bc -q | tr -d '\r\n' | wc -c`
odd=`expr ${num} % 2`
if [ ${odd} -eq 0 ]; then
    varlen1=`echo "obase=16; ${varlen}" | bc -q | cut -b 3,4`
    varlen2=`echo "obase=16; ${varlen}" | bc -q | cut -b 1,2`
else
    varlen1=`echo "obase=16; ${varlen}" | bc -q | cut -b 2,3`
    varlen2=`echo "obase=16; ${varlen}" | bc -q | cut -b 1`
fi
printf "\x1\x${varlen1}\x${varlen2}\x0\x0" >> ${ApcFile}
cat ${ca} >> ${ApcFile}
printf "\x7\x0\x0\x0" >> ${ApcFile}
echo "ca_cert" | tr -d '\r\n' >> ${ApcFile}

##
# Determine size of user key file and
# put the key file into the .apc file
##
varlen=`cat ${key} | wc -c`
hex=`echo "obase=16; ${varlen}" | bc -q`
num=`echo "obase=16; ${varlen}" | bc -q | tr -d '\r\n' | wc -c`
odd=`expr ${num} % 2`
if [ ${odd} -eq 0 ]; then
    varlen1=`echo "obase=16; ${varlen}" | bc -q | cut -b 3,4`
    varlen2=`echo "obase=16; ${varlen}" | bc -q | cut -b 1,2`
else
    varlen1=`echo "obase=16; ${varlen}" | bc -q | cut -b 2,3`
    varlen2=`echo "obase=16; ${varlen}" | bc -q | cut -b 1`
fi
printf "\x1\x${varlen1}\x${varlen2}\x0\x0" >> ${ApcFile}
cat ${key} >> ${ApcFile}
printf "\x3\x0\x0\x0" >> ${ApcFile}
echo "key" >> ${ApcFile}

##
# Username entry
##
varlen=`echo ${user} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >>${ApcFile}
echo ${user} | tr -d '\r\n' >> ${ApcFile}
printf "\x08\x00\x00\x00" >> ${ApcFile}
echo username | tr -d '\r\n' >> ${ApcFile}

##
# Compression entry
# -----------------------------------------------
# This is a bit of a kludge. Actually OpenVPN
# Access Server puts a 'compl-lzo no' into the
# .ovpn file - but later on complains if the
# Astaro tries to connect with comp-lzo disabled
# So we check if a line starting with "comp-lzo"
# is present and if so, we enable compression
# for the ASG.
##
var=`grep "^comp-lzo" ${OvpnFile}| tr -d '\r\n'`
if [ -z "${var}" ]; then
	printf "\x0a\x01\x30\x0b\x0\x0\x0" >> ${ApcFile}
else
	printf "\x0a\x01\x31\x0b\x0\x0\x0" >> ${ApcFile}
fi
echo compression >> ${ApcFile}

##
# Encryption algorithm
# default: BF-CBC
### 
var=`grep "^cipher " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
if [ -z "${var}" ]; then
    var="BF-CBC"
fi
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${ApcFile}
echo $var | tr -d '\r\n' >>${ApcFile}
printf "\x14\x00\x00\x00" >> ${ApcFile}
echo encryption_algorithm >> ${ApcFile}

##
# Password entry
##
varlen=`echo ${pass} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${ApcFile}
echo ${pass} | tr -d '\r\n' >> ${ApcFile}
printf "\x08\x00\x00\x00" >> ${ApcFile}
echo password >> ${ApcFile}

##
# TLS remote identification
# ASG seems to need that entry so try our best to
# find one in case there's none in the .ovpn
# default: the CN of the remote server (w/o the '/CN=' part)
##
####
# !!! Experimental !!!
# We try to trick the ASG into writing more
# stuff into the config file than it normally
# would
###
if [ ! -z "${isxml}" ]; then
	# The .ovpn was most likely created by an
	# OpenVPN Access Server. Thus we somehow
	# need to get the 'tls-auth stuff' into 
	# our client config
	get_ta
	varlen=`cat ${takey} | wc -c`
	varlen=`echo "obase=16; ${varlen}" | bc -q`
	printf "\x${varlen}" >> ${ApcFile}
	cat ${takey} >> ${ApcFile}
else
	# Standard procedure ...
	var=`grep "^tls-remote " ${OvpnFile} | cut -d '"' -f2 |tr -d '\r\n'`
	if [ -z "${var}" ]; then
    	# need to fetch CN from .crt
    	var=`grep DirName ${cert} | awk -F'CN=' '{ print $2 }' | awk -F'/' '{ print $1 }'`
    	if [ -z "${var}" ]; then
    		# still no luck so make one up
			var="/CN=OpenVPN_CA"
		fi
	else
    	# check whether CN was set without quotes 
    	temp=`echo ${var} | grep "^tls-remote "`
    	if [ "${temp}" = "${var}" ]; then
        	var=`grep "^tls-remote " ${OvpnFile} | cut -d ' ' -f2 |tr -d '\r\n'`
    	fi
	fi
	varlen=`echo ${var} | tr -d '\r\n' | wc -c`
	varlen=`echo "obase=16; ${varlen}" | bc -q`
	printf "\x${varlen}" >> ${ApcFile}
	echo $var | tr -d '\r\n' >> ${ApcFile}
fi
printf "\x09\x00\x00\x00" >> ${ApcFile}
echo server_dn >> ${ApcFile}

##
# Remote Server Port
##
var=${RemPort}
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${ApcFile}
echo $var | tr -d '\r\n' >>${ApcFile}
printf "\x0b\x00\x00\x00" >> ${ApcFile}
echo server_port >> ${ApcFile}

##
# Remote Server IP/URI
##
var=${RemHost}
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${ApcFile}
echo $var | tr -d '\r\n' >> ${ApcFile}
printf "\x0e\x00\x00\x00" >> ${ApcFile}
echo server_address| tr -d '\r\n' >> ${ApcFile} 

##
# Clean up the tmp files we
# created (if any)
##
if [ ! -z "${TmpDir}" ]; then
	echo "Cleaning up tmp dir     : ${TmpDir}"
	echo ""
	rm -rf ${TmpDir}
fi

##
# Check for ta.key we created and if
# we did, send a notice to the user
##
if [ ! -z "${tafile}" ]; then
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	echo " Notice: A key file for tls-auth was created for you"
	echo ""
	echo " To use it, you need to copy it over to your Astaro"
	echo " BEFORE installing the generated .apc config file."
	echo ""
	echo " To do that, use a command similar to this:"
	echo ""
	echo "     scp -p ${tafile} root@<ip.of.astaro>:/var/chroot-openvpn/etc/"
	echo ""
	echo " Make sure to NOT change the name of the key file!!!"
	echo ""
fi