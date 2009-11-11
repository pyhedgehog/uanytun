# 
# Copyright (C) 2008 Christian Pointner,
#                    <equinox@anytun.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# This Makefile builds uAnytun Package for OpenWRT
#
# $Id: $

include $(TOPDIR)/rules.mk

PKG_NAME:=uanytun
PKG_VERSION:=0.3.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.anytun.org/download/
PKG_MD5SUM:=7923882da9b97559d5f2074f5d5f8dee

PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/uanytun/template
  SECTION:=net
  CATEGORY:=Network
  TITLE:=micro anycast tunneling daemon
  URL:=http://www.anytun.org/
  MAINTAINER:=Christian Pointner <equinox@anytun.org>
  SUBMENU:=VPN
endef

define Package/uanytun/desc-template
uAnytun is a tiny implementation of SATP the secure anycast tunneling protocol.
  SATP defines a protocol used for communication between any combination of 
  unicast and anycast tunnel endpoints.  It has less protocol overhead than 
  IPSec in Tunnel mode and allows tunneling of every ETHER TYPE protocol (e.g.
  ethernet, ip, arp ...). SATP directly includes cryptography and message 
  authentication based on the methodes used by SRTP.  It is intended to deliver 
  a generic, scaleable and secure solution for tunneling and relaying of packets 
  of any protocol.
  Unlike Anytun which is a full featured implementation uAnytun has no support 
  for multiple connections or synchronisation. It is a small single threaded 
  implementation intended to act as a client on small platforms.
endef

define Package/uanytun
  $(call Package/uanytun/template)
  DEPENDS:=+kmod-tun +libgcrypt
endef

define Package/uanytun/conffiles
/etc/config/uanytun
endef

define Package/uanytun/description
  $(call Package/uanytun/desc-template)
endef


define Package/uanytun-sslcrypt
  $(call Package/uanytun/template)
  DEPENDS:=+kmod-tun +libopenssl
endef

define Package/uanytun-sslcrypt/conffiles
/etc/config/uanytun-sslcrypt
endef

define Package/uanytun-sslcrypt/description
  $(call Package/uanytun/desc-template)
endef


define Package/uanytun-nocrypt
  $(call Package/uanytun/template)
  DEPENDS:=+kmod-tun
endef

define Package/uanytun-nocrypt/conffiles
/etc/config/uanytun-nocrypt
endef

define Package/uanytun-nocrypt/description
  $(call Package/uanytun/desc-template)
endef



define Build/Configure
  (cd $(PKG_BUILD_DIR)/src; \
    touch include.mk; \
    ln -s linux/tun.c . \
  )
endef

define Build/Compile
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR) 

	$(MAKE) -C $(PKG_BUILD_DIR)/src \
    $(TARGET_CONFIGURE_OPTS) \
    NO_CRYPT_OBJ=1 \
    TARGET=Linux \
    CFLAGS="$(TARGET_CFLAGS) -DNO_CRYPT" \
    LDFLAGS="$(TARGET_LDFLAGS) -ldl" 
	cp $(PKG_BUILD_DIR)/src/uanytun $(PKG_BUILD_DIR)/src/uanytun-nocrypt
	$(MAKE) -C $(PKG_BUILD_DIR)/src NO_CRYPT_OBJ=1 clean

	$(MAKE) -C $(PKG_BUILD_DIR)/src \
    $(TARGET_CONFIGURE_OPTS) \
    TARGET=Linux \
    CFLAGS="$(TARGET_CFLAGS) -DUSE_SSL_CRYPTO -I$(STAGING_DIR)/usr/include" \
    LDFLAGS="$(TARGET_LDFLAGS) -ldl -lcrypto" 
	cp $(PKG_BUILD_DIR)/src/uanytun $(PKG_BUILD_DIR)/src/uanytun-sslcrypt
	$(MAKE) -C $(PKG_BUILD_DIR)/src clean

	$(MAKE) -C $(PKG_BUILD_DIR)/src \
    $(TARGET_CONFIGURE_OPTS) \
    TARGET=Linux \
    CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
    LDFLAGS="$(TARGET_LDFLAGS) -ldl -lgcrypt -lgpg-error" 

	$(STRIP) $(PKG_BUILD_DIR)/src/uanytun-nocrypt
	$(STRIP) $(PKG_BUILD_DIR)/src/uanytun-sslcrypt
	$(STRIP) $(PKG_BUILD_DIR)/src/uanytun
endef



define Package/uanytun/install-generic
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/$(3) $(1)/etc/config/$(2)
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/$(2) $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/uanytun.init $(1)/etc/init.d/$(2)
	@sed -e 's/BIN=uanytun/BIN=$(2)/' -i $(1)/etc/init.d/$(2)
endef

define Package/uanytun/install
  $(call Package/uanytun/install-generic,$(1),uanytun,uanytun.config)
endef

define Package/uanytun-sslcrypt/install
  $(call Package/uanytun/install-generic,$(1),uanytun-sslcrypt,uanytun.config)
endef

define Package/uanytun-nocrypt/install
  $(call Package/uanytun/install-generic,$(1),uanytun-nocrypt,uanytun-nocrypt.config)
endef



$(eval $(call BuildPackage,uanytun))
$(eval $(call BuildPackage,uanytun-sslcrypt))
$(eval $(call BuildPackage,uanytun-nocrypt))
