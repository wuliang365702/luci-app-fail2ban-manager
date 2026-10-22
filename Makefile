# SPDX-License-Identifier: MIT
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-fail2ban-manager
PKG_VERSION:=1.0.3
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=wuliang365702

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-fail2ban-manager
  PKGARCH:=all
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Fail2ban status and individual unban
  URL:=https://github.com/wuliang365702/luci-app-fail2ban-manager
  DEPENDS:=+luci-base +rpcd +fail2ban +python3-light +python3-codecs
endef

define Package/luci-app-fail2ban-manager/description
  Discover active Fail2ban jails, inspect bans and recent events, and unban
  individual addresses using LuCI authentication. Existing protection settings
  are never installed, replaced, enabled or restarted by this manager.
endef

define Build/Compile
endef

define Package/luci-app-fail2ban-manager/install
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./root/usr/libexec/rpcd/luci.fail2ban $(1)/usr/libexec/rpcd/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/*.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/*.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/fail2ban
	$(INSTALL_DATA) ./root/www/luci-static/resources/view/fail2ban/manager.js $(1)/www/luci-static/resources/view/fail2ban/
endef

define Package/luci-app-fail2ban-manager/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
fi
exit 0
endef

define Package/luci-app-fail2ban-manager/postrm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
fi
exit 0
endef

$(eval $(call BuildPackage,luci-app-fail2ban-manager))
