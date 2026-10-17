import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('signing', Path(__file__).resolve().parents[1] / 'ci/signing.py')
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class SigningTests(unittest.TestCase):
    def test_patch_adds_signing_at_creation(self):
        original = '\t$(FAKEROOT) $(STAGING_DIR_HOST)/bin/apk mkpkg \\\n\t--files data\n'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'package-pack.mk'
            path.write_text(original)
            signing.patch_sdk(path)
            result = path.read_text()
            self.assertIn('mkpkg $(if $(CONFIG_SIGNED_PACKAGES),--sign $(BUILD_KEY_APK_SEC),)', result)
            self.assertNotIn('allow-untrusted', result)

    def test_changed_sdk_rule_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'package-pack.mk'
            path.write_text('new SDK format')
            with self.assertRaises(RuntimeError):
                signing.patch_sdk(path)
            self.assertEqual(path.read_text(), 'new SDK format')

    def test_noarch_metadata_is_required(self):
        self.assertEqual(signing.package_info('{"info":{"name":"luci-app-fail2ban-manager","version":"1.0.2-r1","arch":"noarch"}}')['arch'], 'noarch')
        for text in ('{}', '{"info":{"name":"luci-app-fail2ban-manager","arch":"x86_64"}}'):
            with self.assertRaises(RuntimeError):
                signing.package_info(text)


if __name__ == '__main__':
    unittest.main()
