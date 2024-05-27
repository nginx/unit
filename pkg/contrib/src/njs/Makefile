# njs

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/version
NJS_URL := https://hg.nginx.org/njs/archive/$(NJS_VERSION).tar.gz

PKGS += njs

$(TARBALLS)/njs-$(NJS_VERSION).tar.gz:
	$(call download_pkg,$(NJS_URL),njs)

.sum-njs: njs-$(NJS_VERSION).tar.gz

njs: njs-$(NJS_VERSION).tar.gz .sum-njs
	$(UNPACK)
	$(MOVE)

.njs: njs
	cd $< && ./configure \
		--no-libxml2 \
		--no-zlib \
		&& $(MAKE) libnjs
	touch $@
