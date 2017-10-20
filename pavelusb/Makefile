#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#


include $(TOPDIR)/rules.mk

PKG_NAME:=pavelusb
PKG_VERSION:=2.1.00
PKG_RELEASE:=1


PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_REV:=87cf2d92c7b64b02f870b86a55ee9c970c29abdd
PKG_SOURCE_URL:=https://github.com/pavel-a/usb-relay-hid
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/pavelusb
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libusb-compat
	TITLE:=clone of usb
	URL:=https://github.com/pavel-a/usb-relay-hid
	MAINTAINER:=Artem Bernadsky
endef

define Package/pavelusb/description
 This project provides open-source API for low-cost USB HID relays (search on eBay for "5V USB Relay Programmable Computer Control For Smart Home").
endef


#CONFIGURE_ARGS += \
#	--disable-swig \
#	--disable-werror \
#	--without-doxygen \

#PKG_CONFIGURE_OPTS += \
#		--enable-usb \
#		--with-libusb-config="$(STAGING_DIR)/opt/bin/libusb-config"


MAKE_PATH:=commandline/makemake

define Package/pavelusb/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/*.so* $(1)/opt/lib
	$(INSTALL_BIN) $(1)/opt/bin
endef

$(eval $(call BuildPackage,pavelusb))
