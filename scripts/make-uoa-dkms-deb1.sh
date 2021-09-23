#!/bin/bash

UOA_DIR=..

if [ -z $UOA_DIR ]; then
	echo "UOA_DIR not set, will exit"
	exit 1
fi


PACKAGE_NAME="uoa-dkms"
PACKAGE_VERSION="2.2.1"


DEB_DIR=$UOA_DIR/deb
DKMS_DIR=$DEB_DIR/usr/src/$PACKAGE_NAME-$PACKAGE_VERSION

mkdir -p $DEB_DIR/DEBIAN
mkdir -p $DKMS_DIR


cp  $UOA_DIR/kmod/uoa.h            $DKMS_DIR/
cp  $UOA_DIR/kmod/uoa_opp.h        $DKMS_DIR/
cp  $UOA_DIR/kmod/uoa.c            $DKMS_DIR/
cp  $UOA_DIR/kmod/Makefile         $DKMS_DIR/
cp  $UOA_DIR/scripts/uoa-dkms.conf $DKMS_DIR/dkms.conf

cp  $UOA_DIR/scripts/uoa-dkms-after-install.sh $DEB_DIR/DEBIAN/postinst
cp  $UOA_DIR/scripts/uoa-dkms-before-remove.sh $DEB_DIR/DEBIAN/prerm
cp  $UOA_DIR/scripts/debian_control            $DEB_DIR/DEBIAN/control

(cd $DEB_DIR && md5sum `find usr -type f` > DEBIAN/md5sums)


dpkg-deb -b $DEB_DIR .









# remove temp files
rm -rf $DEB_DIR
