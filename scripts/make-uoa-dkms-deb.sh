#!/bin/bash

UOA_DIR=..

if [ -z $UOA_DIR ]; then
	echo "UOA_DIR not set, will exit"
	exit 1
fi


PACKAGE_NAME="uoa-dkms"
PACKAGE_VERSION="2.1.3"


DEST_DIR=dkms
# cp files for installation
mkdir -p $UOA_DIR/$DEST_DIR/usr/src

UOA_DKMS_DIR=$UOA_DIR/$DEST_DIR/usr/src/$PACKAGE_NAME-$PACKAGE_VERSION
mkdir -p $UOA_DKMS_DIR

cp -R $UOA_DIR/kmod/uoa.h $UOA_DKMS_DIR
#cp -R $UOA_DIR/uoa_extra.h $UOA_DKMS_DIR
cp -R $UOA_DIR/kmod/uoa_opp.h $UOA_DKMS_DIR
cp -R $UOA_DIR/kmod/uoa.c $UOA_DKMS_DIR
cp -R $UOA_DIR/kmod/Makefile $UOA_DKMS_DIR
cp -R $UOA_DIR/scripts/uoa-dkms.conf $UOA_DKMS_DIR/dkms.conf

# make deb package
# apt install ruby rubygems ruby-dev
# gem install fpm
fpm -s dir \
    -t deb \
	-p "$PACKAGE_NAME"_VERSION_ARCH.deb \
	-n $PACKAGE_NAME \
	-v 2.1.3 \
	--after-install $UOA_DIR/scripts/uoa-dkms-after-install.sh \
	--before-remove $UOA_DIR/scripts/uoa-dkms-before-remove.sh \
	-C $UOA_DIR/$DEST_DIR usr/


# remove temp files
rm -rf $UOA_DIR/$DEST_DIR
