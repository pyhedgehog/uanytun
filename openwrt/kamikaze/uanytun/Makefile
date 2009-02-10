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
PKG_VERSION:=0.3-rc1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.anytun.org/~equinox/
PKG_MD5SUM:=97854b33081f7685ff174db4c7083d8e

PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/uanytun
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+kmod-tun +libopenssl
  TITLE:=micro anycast tunneling daemon
  URL:=http://www.anytun.org/
  MAINTAINER:=Christian Pointner <equinox@anytun.org>
  SUBMENU:=VPN
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
    TARGET=Linux \
    CFLAGS="$(TARGET_CFLAGS) -DUSE_SSL_CRYPTO -I$(STAGING_DIR)/usr/include" \
    LDFLAGS="$(TARGET_LDFLAGS) -ldl -lcrypto" 
  $(STRIP) $(PKG_BUILD_DIR)/src/uanytun
endef

define Package/uanytun/install
  $(INSTALL_DIR) $(1)/etc/config
  $(INSTALL_DATA) ./files/uanytun.config $(1)/etc/config/uanytun
  $(INSTALL_DIR) $(1)/usr/sbin
  $(INSTALL_BIN) $(PKG_BUILD_DIR)/src/uanytun $(1)/usr/sbin/
  $(INSTALL_DIR) $(1)/etc/init.d
  $(INSTALL_BIN) ./files/uanytun.init $(1)/etc/init.d/uanytun

endef

$(eval $(call BuildPackage,uanytun))
