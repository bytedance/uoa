


build: 
	./make-uoa-dkms-deb1.sh

install: build
	dpkg -i uoa-dkms_2.2.1_amd64.deb
#	modprobe uoa

uninstall:
#	-modprobe -r uoa
	-dpkg -r uoa-dkms 
	-rm uoa-dkms_2.2.1_amd64.deb
