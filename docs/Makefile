#!/usr/bin/make

DEST=	../build
XSLS?=	xslscript.pl

PACKAGES=	unit 							\
		unit-php 						\
		unit-python unit-python2.7 unit-python3.4		\
		unit-python3.5 unit-python3.6 unit-python3.7		\
		unit-python3.8						\
		unit-go unit-go1.7 unit-go1.8 unit-go1.9 unit-go1.10	\
		unit-go1.12 unit-go1.13					\
		unit-perl						\
		unit-ruby						\
		unit-jsc-common unit-jsc8 unit-jsc10 unit-jsc11

CURDATE:=$(shell date +"%Y-%m-%d")
CURTIME:=$(shell date +"%H:%M:%S %z")


all:		changes changelogs

changes:	$(DEST)/CHANGES

changelogs:	$(addsuffix .rpm-changelog, $(addprefix $(DEST)/, $(PACKAGES))) \
		$(addsuffix .deb-changelog, $(addprefix $(DEST)/, $(PACKAGES)))

$(DEST)/CHANGES:		changes.dtd				\
				changes.xml				\
				change_log_conf.xml			\
				changes.xslt

	mkdir -p $(DEST)

	xmllint --noout --valid changes.xml
	xsltproc --stringparam format generic				\
		--stringparam curdate '$(CURDATE)'			\
		--stringparam curtime '$(CURTIME)'			\
		-o $@ changes.xslt changes.xml

$(DEST)/%.rpm-changelog:	changes.dtd 				\
				changes.xml 				\
				change_log_conf.xml 			\
				changes.xslt
	mkdir -p $(DEST)
	xmllint --noout --valid changes.xml
	xsltproc --stringparam pkgname $* --stringparam format rpm	\
		--stringparam curdate '$(CURDATE)'			\
		--stringparam curtime '$(CURTIME)'			\
		-o $@ changes.xslt changes.xml

$(DEST)/%.deb-changelog:	changes.dtd 				\
				changes.xml 				\
				change_log_conf.xml 			\
				changes.xslt
	mkdir -p $(DEST)
	xmllint --noout --valid changes.xml
	xsltproc --stringparam pkgname $* --stringparam format deb	\
		--stringparam curdate '$(CURDATE)'			\
		--stringparam curtime '$(CURTIME)'			\
		-o $@ changes.xslt changes.xml

changes.xslt:	changes.xsls
	$(XSLS) -o $@ $<

clean:
	rm -rf $(DEST)
