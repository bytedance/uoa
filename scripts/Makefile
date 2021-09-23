


build: 
	./make-uoa-dkms-deb.sh

install: build
	dpkg -i uoa-dkms_2.1.3_amd64.deb
#	modprobe uoa

uninstall:
#	-modprobe -r uoa
	-dpkg -r uoa-dkms 
	-rm uoa-dkms_2.1.3_amd64.deb