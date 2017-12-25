$(call PKG_INIT_BIN, 1.1)
$(PKG)_SOURCE:=ptunnel-ng-$($(PKG)_VERSION).tar.gz
$(PKG)_SOURCE_SHA256:=3182ecc4f9a7ef3ae8895b460aa596ae050b9718b98fd5eaf224772fba017c22
$(PKG)_SITE:=https://github.com/lnslbrty/ptunnel-ng/releases/download/v$($(PKG)_VERSION)
$(PKG)_DIR:=$($(PKG)_SOURCE_DIR)/ptunnel-ng-$($(PKG)_VERSION)

$(PKG)_BINARY:=$($(PKG)_DIR)/src/ptunnel-ng
$(PKG)_TARGET_BINARY:=$($(PKG)_DEST_DIR)/usr/sbin/ptunnel-ng

$(PKG)_BUILD_PREREQ += aclocal automake autoconf
$(PKG)_DEPENDS_ON += libpcap

$(PKG)_EXTRA_CFLAGS += -std=gnu99
$(PKG)_CONFIGURE_OPTIONS += --disable-selinux

$(PKG_SOURCE_DOWNLOAD)
$(PKG_UNPACKED)
$(PKG_CONFIGURED_CONFIGURE)

$($(PKG)_BINARY): $($(PKG)_DIR)/.configured
	echo "______$(PINGTUNNEL_NG_EXTRA_CFLAGS)_____"
	$(SUBMAKE) -C $(PINGTUNNEL_NG_DIR) V=1 \
		CFLAGS="$(TARGET_CFLAGS) $(PINGTUNNEL_NG_EXTRA_CFLAGS)"

$($(PKG)_TARGET_BINARY): $($(PKG)_BINARY)
	$(INSTALL_BINARY_STRIP)

$(pkg):

$(pkg)-precompiled: $($(PKG)_TARGET_BINARY)

$(pkg)-uninstall:
	$(RM) $(PINGTUNNEL_NG_TARGET_BINARY)

$(PKG_FINISH)
