#
# Copyright (C) 2011-2015 ArtBern
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=usbrelay
PKG_VERSION:=0.1-2017-10-30
PKG_REV:=9507922619e9b879a95a1ec0bfdf413c905fdcc3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/artbern/usbrelay
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-0.1

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


define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -c -I$(STAGING_DIR)/opt/include -D_GNU_SOURCE -D_BSD_SOURCE -o $(PKG_BUILD_DIR)/usbrelay.o $(PKG_BUILD_DIR)/usbrelay.c
	$(TARGET_CC) $(TARGET_LDFLAGS) -L$(STAGING_DIR)/opt/lib -o $(PKG_BUILD_DIR)/usbrelay \
		$(PKG_BUILD_DIR)/usbrelay.o \
		-llibhid
endef		

#define Build/Configure
##	$(SED) 's,/usr/include/usb.h,$(STAGING_DIR)/opt/include/usb.h,g' $(PKG_BUILD_DIR)/config.h
#	$(SED) 's,/usr/local/lib/_include_/hid.h,$(STAGING_DIR)/opt/include/hid.h,g' $(PKG_BUILD_DIR)/config.h
#endef

TARGET_CFLAGS += \
	-fPIC \
	-DLANG_ENG \

#define Package/usbrelay/conffiles
#/opt/etc/wmr/wmr.conf
#endef

define Package/usbrelay/install
	$(INSTALL_DIR) $(1)/opt/lib/usbrelay
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_DIR) $(1)/opt/etc/usbrelay
endef

$(eval $(call BuildPackage,usbrelay))