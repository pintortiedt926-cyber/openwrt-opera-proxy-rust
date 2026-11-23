include $(TOPDIR)/rules.mk

PKG_NAME:=opera-proxy
PKG_VERSION:=1.32.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=Snawoot <vladislav-ex-gh@vm-0.com>

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
    SECTION:=net
    CATEGORY:=Network
    TITLE:=Opera Proxy client
    URL:=https://github.com/Snawoot/opera-proxy
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/opera-proxy
endef

define Build/Configure
endef

define Build/Compile
	if [ -n "$(OPERA_PROXY_BIN)" ] && [ -f "$(OPERA_PROXY_BIN)" ]; then \
		$(INSTALL_DIR) ./files/usr/bin; \
		$(CP) "$(OPERA_PROXY_BIN)" ./files/usr/bin/opera-proxy; \
		chmod +x ./files/usr/bin/opera-proxy; \
	fi
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/opera-proxy $(1)/etc/init.d/

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/opera-proxy $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/opera-proxy $(1)/etc/config/
endef

$(eval $(call BuildPackage,opera-proxy))
