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

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./commandline/* $(PKG_BUILD_DIR)/
	rm -f $(PKG_BUILD_DIR)/CMakeCache.txt
	rm -fR $(PKG_BUILD_DIR)/CMakeFiles
	rm -f $(PKG_BUILD_DIR)/Makefile
	rm -f $(PKG_BUILD_DIR)/cmake_install.cmake
	rm -f $(PKG_BUILD_DIR)/progress.make
endef

define Build/Configure
	IN_OPENWRT=1 \
	AR="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)ar" \
	AS="$(TOOLCHAIN_DIR)/bin/$(TARGET_CC) -c $(TARGET_CFLAGS)" \
	LD="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)ld" \
	NM="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)nm" \
	CC="$(TOOLCHAIN_DIR)/bin/$(TARGET_CC)" \
	GCC="$(TOOLCHAIN_DIR)/bin/$(TARGET_CC)" \
	CXX="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)g++" \
	RANLIB="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)ranlib" \
	STRIP="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)strip" \
	OBJCOPY="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)objcopy" \
	OBJDUMP="$(TOOLCHAIN_DIR)/bin/$(TARGET_CROSS)objdump" \
	TARGET_CPPFLAGS="$(TARGET_CPPFLAGS)" \
	TARGET_CFLAGS="$(TARGET_CFLAGS)" \
	TARGET_LDFLAGS="$(TARGET_LDFLAGS)" \
	cmake $(PKG_BUILD_DIR)/CMakeLists.txt
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)
	$(STRIP) $(PKG_BUILD_DIR)/pavelusb
endef

define Package/pavelusb/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hidusb-relay-cmd $(1)/usr/bin/
endef

#CONFIGURE_ARGS += \
#	--disable-swig \
#	--disable-werror \
#	--without-doxygen \

#PKG_CONFIGURE_OPTS += \
#		--enable-usb \
#		--with-libusb-config="$(STAGING_DIR)/opt/bin/libusb-config"


#MAKE_PATH:=commandline/makemake

#define Build/InstallDev
#	$(INSTALL_DIR) $(1)/opt/include
#	#$(CP) $(PKG_INSTALL_DIR)/opt/include/*.h $(1)/opt/include/
#	$(INSTALL_DIR) $(1)/opt/lib
#	#$(CP) $(PKG_INSTALL_DIR)/opt/lib/usb_relay_device.{a,la,so*} $(1)/opt/lib/
#	$(INSTALL_DIR) $(1)/opt/lib/pkgconfig
#	#$(CP) $(PKG_INSTALL_DIR)/opt/lib/pkgconfig/libhid.pc $(1)/opt/lib/pkgconfig/
#endef

#define Package/pavelusb/install
#	$(INSTALL_DIR) $(1)/opt/lib
#	#$(CP) $(PKG_INSTALL_DIR)/opt/lib/usb_relay_device.so* $(1)/opt/lib
#	$(INSTALL_DIR) $(1)/opt/bin
#	$(INSTALL_BIN) $(1)/opt/bin
#endef

$(eval $(call BuildPackage,pavelusb))
