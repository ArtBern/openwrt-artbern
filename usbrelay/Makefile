#
# Copyright (C) 2011-2015 ArtBern
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=usbrelay
PKG_VERSION:=0.1-2017-10-30
#PKG_REV:=9507922619e9b879a95a1ec0bfdf413c905fdcc3
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_URL:=https://github.com/artbern/usbrelay
#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_VERSION:=$(PKG_REV)

#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-0.1

include $(INCLUDE_DIR)/package.mk

define Package/usbrelay
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libhid
	TITLE:=USB Relay Controller
	URL:=https://github.com/artbern/usbrelay
	MAINTAINER:=Artem Bernadsky
endef

define Package/usbrelay/description
 USB Relay Controller
endef

BINARIES:= \
	usb_relay

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(foreach bin,$(BINARIES),./src/$(bin).c) \
	    $(PKG_BUILD_DIR)
endef


define Build/Configure
	$(SED) 's,/usr/include/usb.h,$(STAGING_DIR)/opt/include/usb.h,g' $(PKG_BUILD_DIR)/config.h
	$(SED) 's,/usr/local/lib/_include_/hid.h,$(STAGING_DIR)/opt/include/hid.h,g' $(PKG_BUILD_DIR)/config.h
endef

define Build/Compile
	for bin in $(BINARIES); \
	do \
	    $(TARGET_CC) $(TARGET_CFLAGS) -I$(STAGING_DIR)/opt/include \
	    $(TARGET_LDFLAGS) -L$(STAGING_DIR)/opt/lib -lusb -s \
	    -o $(PKG_BUILD_DIR)/$$$${bin} $(PKG_BUILD_DIR)/$$$${bin}.c; \
	done
endef

define Package/usbrelay/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(foreach bin,$(BINARIES),$(PKG_BUILD_DIR)/$(bin)) \
	    $(1)/opt/bin
endef

$(eval $(call BuildPackage,usbrelay))