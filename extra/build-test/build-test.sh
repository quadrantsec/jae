#!/bin/bash

# Simple shell script that compiles Sagan with multiple flags.  This helps 
# hunt down compile time bugs.  This is taken from the original Sagan
# https://github.com/beave/sagan
# 
#   2020/10/20 - Adapted for Sagan-NG

STANDARD=""
ALLFLAGS="--enable-system-strstr"
NOFLAG="--disable-system-strstr"

LOG="output.log" 

MAKE_FLAGS="-j5"

autoreconf -vfi

echo "**** STANDARD BUILD | NO FLAGS ****"
echo "**** STANDARD BUILD | NO FLAGS ****" >> $LOG

#make clean
#cd tools && make clean && cd ..

CFLAGS=-Wall ./configure

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
	exit
        fi

make $MAKE_FLAGS 2>> $LOG
#cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
	then
	echo "Error on standard build!";
	exit
	fi

echo "**** ALL FLAGS ****"
echo "**** ALL FLAGS ****" >> $LOG

make clean
#cd tools && make clean && cd .. 

CFLAGS=-Wall ./configure $ALLFLAGS

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
#cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

echo "****  NO FLAGS ****"
echo "****  NO FLAGS ****" >> $LOG

make clean
#cd tools && make clean && cd ..

CFLAGS=-Wall ./configure $NOFLAG

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
#cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

for I in $STANDARD
do

make clean
#cd tools && make clean && cd ..

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
#cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $ALLFLAGS
do

make clean
#cd tools && make clean && cd .. 

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
#cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $NOFLAGS
do

make clean
#cd tools && make clean && cd ..

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
#cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

