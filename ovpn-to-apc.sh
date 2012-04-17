#!/bin/bash

##
# ovpn-to-apc.sh
# -----------------------------------------------
# (C) 2009 Patrick Schneider http://goo.gl/5bPqy
# (C) 2012 Stefan Rubner    <stefan@whocares.de>
# -----------------------------------------------
# Changes:
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
# All files are looked for in the current direc-
# tory only.
##

if [ $# -lt 2 ] || [ $# -gt 4 ]; then
    echo
    echo Usage:
    echo ${0} openvpn-config.ovpn output.apc [username [password]]
    echo
    echo username and password are optional and may be entered by the user
    echo The config file needs to contain the ca, cert and key directives
    echo that point to the corresponding files.
    exit
fi
if [ $# -gt 2 ] && [ $# -lt 4 ]; then
    # Only username given on command line
    user=${3}
    echo "Please enter your password: "
    read pass
elif [ $# -gt 3 ]; then
    # username and password given
    user=${3}
    pass=${4}
else 
    # try to get user from the .ovpn file
    user=`echo $1 | cut -d '@' -f1`
    if [ ${user} = ${1} ]; then
        echo "Enter username: "
        read user
    fi
    echo "Please enter your password: "
    read pass
fi

##
# Passwort field is required by Astaro but
# wrong content doesn't hurt operations
##
if [ -z ${pass} ]; then
    pass="dummy"
fi

##
# Read the filenames from the config-file
##
ca=`grep "^ca " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
key=`grep "^key " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
cert=`grep "^cert " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`

##
# Write .apc header
##
printf "\x04\x06\x041234\x04\x04\x04\x08\x03\x0c\x00\x00\x00\x0a" > $2

##
# Extract protocol (UDP/TCP) from config file
##
var=`grep "^proto " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
# Determine length of the protocol and convert it to hex
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
# Write length to output file
printf "\x${varlen}" >> ${2}
# Write protocol to output file
echo $var | tr -d '\r\n' >> ${2}
# Write fix information to output file
printf "\x08\x00\x00\x00" >> ${2}
echo protocol >>${2}

##
# HMAC packet authentication
# default: SHA1
## 
var=`grep "^auth " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
if [ -z ${var} ]; then
  var="SHA1"
fi
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${2}
echo $var | tr -d '\r\n' >> ${2}
printf "\x18\x00\x00\x00" >> ${2}
echo authentication_algorithm | tr -d '\r\n' >> ${2}

##
# Determine length of user certifcate file
# and put certificate into .apc file
##
varlen=`cat "${cert}" | wc -c`
# Length decimal
hex=`echo "obase=16; ${varlen}" | bc -q` # Length hexadecimal
num=`echo "obase=16; ${varlen}" | bc -q | tr -d '\r\n' | wc -c` # Length of the hex-number
echo "${varlen}:${hex}:${num}"
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
printf "\x1\x${varlen1}\x${varlen2}\x0\x0" >> ${2}
cat ${cert} >> ${2}
printf "\xb\x0\x0\x0" >> ${2}
echo "certificate" | tr -d '\r\n' >> ${2}

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
printf "\x1\x${varlen1}\x${varlen2}\x0\x0" >> ${2}
cat ${ca} >> ${2}
printf "\x7\x0\x0\x0" >> ${2}
echo "ca_cert" | tr -d '\r\n' >> ${2}

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
printf "\x1\x${varlen1}\x${varlen2}\x0\x0" >> ${2}
cat ${key} >> ${2}
printf "\x3\x0\x0\x0" >> ${2}
echo "key" >> ${2}

##
# Username entry
##
varlen=`echo ${user} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >>${2}
echo ${user} | tr -d '\r\n' >> ${2}
printf "\x08\x00\x00\x00" >> ${2}
echo username | tr -d '\r\n' >> ${2}

##
# Compression entry
# #FIXME# we're setting 'comp-lzo' always here
##
var=`grep "^comp-lzo" ${1}|tr -d '\r\n'`
# if [ ${var} = "comp-lzo" ]
# then
# printf "\x0a\x01\x31\x0b\x0\x0\x0" >> ${2}
# else
printf "\x0a\x01\x31\x0b\x0\x0\x0" >> ${2}
# fi
echo compression >> ${2}

##
# Encryption algorithm
# default: BF-CBC
### 
var=`grep "^cipher " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
if [ -z ${var} ]; then
    var="BF-CBC"
fi
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${2}
echo $var | tr -d '\r\n' >>${2}
printf "\x14\x00\x00\x00" >> ${2}
echo encryption_algorithm >> ${2}

##
# Password entry
##
varlen=`echo ${pass} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${2}
echo ${pass} | tr -d '\r\n' >> ${2}
printf "\x08\x00\x00\x00" >> ${2}
echo password >> ${2}

##
# TLS remote identification
# ASG seems to need that entry so try our best to
# find one in case there's none in the .ovpn
# default: the CN of the remote server (w/o the '/CN=' part)
##
var=`grep "^tls-remote " ${1} | cut -d '"' -f2 |tr -d '\r\n'`
if [ -z ${var} ]; then
    # need to fetch CN from .crt
    var=` grep DirName ${cert} | awk -F'CN=' '{ print $2 }' | awk -F'/' '{ print $1 }'`
else
    # check whether CN was set without quotes 
    temp=`echo ${var} | grep "^tls-remote "`
    if [ "${temp}" = "${var}" ]; then
        var=`grep "^tls-remote " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
    fi
fi
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${2}
echo $var | tr -d '\r\n' >> ${2}
printf "\x09\x00\x00\x00" >> ${2}
echo server_dn >> ${2}

##
# Remote Server Port
##
var=`grep "^remote " ${1} | cut -d ' ' -f3 |tr -d '\r\n'`
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${2}
echo $var | tr -d '\r\n' >>${2}
printf "\x0b\x00\x00\x00" >> ${2}
echo server_port >> ${2}

##
# Remote Server IP/URI
##
var=`grep "^remote " ${1} | cut -d ' ' -f2 |tr -d '\r\n'`
varlen=`echo ${var} | tr -d '\r\n' | wc -c`
varlen=`echo "obase=16; ${varlen}" | bc -q`
printf "\x${varlen}" >> ${2}
echo $var | tr -d '\r\n' >> ${2}
printf "\x0e\x00\x00\x00" >> ${2}
echo server_address| tr -d '\r\n' >> ${2} 

