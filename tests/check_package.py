"""Guard the installation boundary and check public-source hygiene."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
expected = {
    'usr/libexec/rpcd/luci.fail2ban',
    'usr/share/rpcd/acl.d/luci-app-fail2ban-manager.json',
    'usr/share/luci/menu.d/luci-app-fail2ban-manager.json',
    'www/luci-static/resources/view/fail2ban/manager.js',
}
actual = {p.relative_to(root / 'root').as_posix() for p in (root / 'root').rglob('*') if p.is_file()}
assert actual == expected, actual
for filename in (root / 'root').rglob('*.json'):
    json.loads(filename.read_text())
acl = json.loads((root / 'root/usr/share/rpcd/acl.d/luci-app-fail2ban-manager.json').read_text())['luci-app-fail2ban-manager']
assert acl['read']['ubus'] == {'luci.fail2ban': ['snapshot']}
assert acl['write']['ubus'] == {'luci.fail2ban': ['unban']}
makefile = (root / 'Makefile').read_text()
assert 'define Package/luci-app-fail2ban-manager\n  PKGARCH:=all\n' in makefile
for forbidden in ('/etc/init.d/fail2ban', '/etc/init.d/firewall', 'uci set', 'uci commit'):
    assert forbidden not in makefile, forbidden
for name in expected:
    content = (root / 'root' / name).read_text()
    assert '\r' not in content
    assert not re.search(r'19900326|192\.168\.10\.1|certificate_deploy|BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY', content)
print('Package payload, ACL, non-invasive lifecycle and private-data checks passed.')
