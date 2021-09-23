#!/bin/bash

# remove dkms
PACKAGE_NAME="uoa-dkms"
PACKAGE_VERSION="2.2.1"

case "$1" in
    remove|upgrade|deconfigure)

        echo "1"
        modprobe -r uoa

        echo "2"
        rm -f /etc/modprobe.d/uoa.conf

        echo "3"
        rm -f /usr/lib/modules-load.d/uoa.conf

        echo "4"
        if [  "$(dkms status -m $PACKAGE_NAME -v $PACKAGE_VERSION)" ]; then
            dkms remove -m $PACKAGE_NAME -v $PACKAGE_VERSION --all
        fi
        
        echo "5"

    ;;
esac
