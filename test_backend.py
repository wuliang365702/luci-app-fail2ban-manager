import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

# The workstation does not need a running Fail2ban installation.
stub = types.ModuleType("fail2ban.client.csocket")
stub.CSocket = object
sys.modules.setdefault("fail2ban", types.ModuleType("fail2ban"))
sys.modules.setdefault("fail2ban.client", types.ModuleType("fail2ban.client"))
sys.modules["fail2ban.client.csocket"] = stub
source = Path(__file__).parent / "root/usr/libexec/rpcd/luci.fail2ban"
loader = importlib.machinery.SourceFileLoader("f2b_rpc", str(source))
spec = importlib.util.spec_from_loader(loader.name, loader)
backend = importlib.util.module_from_spec(spec)
loader.exec_module(backend)


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.banned = {"dropbear": ["192.0.2.10", "2001:db8::10"], "luci-auth": []}
        self.mock_call = patch.object(backend, "call", side_effect=self.command)
        self.call_mock = self.mock_call.start()
        self.addCleanup(self.mock_call.stop)

    def command(self, args):
        self.calls.append(args)
        if args[0] == "status":
            if len(args) == 1:
                return [("Jail list", list(self.banned))]
            return [("Filter", [("Currently failed", 0), ("Total failed", 0)]),
                    ("Actions", [("Total banned", 2), ("Banned IP list", self.banned[args[1]][:])])]
        if args[0] == "get":
            if args[2:] == ['banip', '--with-time']:
                return ['192.0.2.10 2026-10-22 21:30:00 + 7200 = 2026-10-22 23:30:00',
                        '2001:db8::10 2026-10-22 21:30:00 + -1 = 9999-12-31 23:59:59']
            return {"maxretry": 5, "findtime": 600, "bantime": 600,
                    "bantime.increment": args[1] == 'dropbear', "bantime.maxtime": 604800}[args[2]]
        if args[:1] == ["set"] and args[2] == "unbanip":
            self.banned[args[1]].remove(args[3])
            return 1
        raise AssertionError(args)

    def test_only_active_jails_can_be_changed(self):
        for jail in ("sshd", "--all", "; reboot", None, ["dropbear"]):
            self.assertFalse(backend.unban({"jail": jail, "ip": "192.0.2.10"})["ok"])
        self.assertFalse(any(command[0] == "set" for command in self.calls))

    def test_invalid_addresses_never_reach_fail2ban(self):
        for ip in ("--all", "192.0.2.10;reboot", "192.0.2.10\n", "::1%eth0", "192.0.2.0/24", None, {}, "9" * 200):
            self.assertEqual(backend.unban({"jail": "dropbear", "ip": ip})["error"], "invalid_ip")
        self.assertEqual(self.calls, [])

    def test_non_banned_ip_is_not_changed(self):
        result = backend.unban({"jail": "dropbear", "ip": "192.0.2.99"})
        self.assertEqual(result["error"], "not_banned")
        self.assertFalse(any(command[0] == "set" for command in self.calls))

    @patch.object(backend.subprocess, "run")
    def test_individual_unban_and_audit(self, logger):
        self.assertTrue(backend.unban({"jail": "dropbear", "ip": "192.0.2.10"})["ok"])
        self.assertEqual(self.banned["dropbear"], ["2001:db8::10"])
        logger.assert_called_once()
        self.assertIsInstance(logger.call_args.args[0], list)
        self.assertNotIn("shell", logger.call_args.kwargs)

    @patch.object(backend.subprocess, "run")
    def test_ipv6_is_canonicalized(self, logger):
        self.assertTrue(backend.unban({"jail": "dropbear", "ip": "2001:0db8:0:0::10"})["ok"])
        self.assertIn(["set", "dropbear", "unbanip", "2001:db8::10"], self.calls)

    def test_unknown_method_is_rejected(self):
        self.assertFalse(backend.dispatch("exec", {"command": "reboot"})["ok"])
        self.assertEqual(self.calls, [])

    def test_snapshot_contains_policies_and_addresses(self):
        with patch.object(backend, "recent_events", return_value=([], [])):
            data = backend.snapshot()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["jails"]), 2)
        self.assertEqual(data["jails"][0]["maxretry"], 5)

    def test_ticket_expiry_uses_actual_incremented_duration(self):
        result = backend.jail_status('dropbear')
        self.assertEqual(result['expirations']['192.0.2.10']['time'], '2026-10-22 23:30:00')
        self.assertTrue(result['expirations']['2001:db8::10']['permanent'])

    def test_expiry_unsupported_keeps_status_available(self):
        original = self.command
        def command(args):
            if args[2:] == ['banip', '--with-time']:
                raise backend.ServiceError('unsupported')
            return original(args)
        self.call_mock.side_effect = command
        self.assertEqual(backend.jail_status('dropbear')['expirations'], {})

    def test_expiry_invalid_and_unbanned_entries_are_ignored(self):
        original = self.command
        def command(args):
            if args[2:] == ['banip', '--with-time']:
                return ['192.0.2.99 2026-10-22 21:30:00 + 600 = 2026-10-22 21:40:00',
                        '192.0.2.10 2026-10-22 21:30:00 + 600 = <script>', None,
                        'not-an-ip 2026-10-22 21:30:00 + 600 = 2026-10-22 21:40:00']
            return original(args)
        self.call_mock.side_effect = command
        self.assertEqual(backend.jail_status('dropbear')['expirations'], {})

    def test_runtime_policy_is_reported(self):
        ssh = backend.jail_status('dropbear')
        self.assertTrue(ssh['bantime_increment'])
        self.assertEqual(ssh['bantime_maximum'], 604800)
        self.assertFalse(backend.jail_status('luci-auth')['bantime_increment'])

    def test_logs_are_bounded_and_only_known_events_are_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "system.log"
            lines = ["Fri Oct 16 10:00:00 2026 daemon.notice fail2ban.actions[1]: NOTICE [dropbear] Ban 192.0.2.10",
                     "Fri Oct 16 10:00:01 2026 daemon.notice fail2ban.actions[1]: NOTICE [unknown] Ban 192.0.2.11",
                     "Fri Oct 16 10:00:02 2026 daemon.notice fail2ban.actions[1]: NOTICE [dropbear] Ban <script>",
                     "Fri Oct 16 10:00:03 2026 authpriv.notice luci-fail2ban: Manual unban jail=dropbear ip=192.0.2.10"]
            log.write_text("\n".join(lines), encoding="utf-8")
            with patch.object(backend, "log_sources", return_value=([str(log)], False)), patch.object(backend, "EVENT_LIMIT", 1):
                events, warnings = backend.recent_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "Manual unban")
            json.dumps(events)

    @patch.object(backend.subprocess, "run")
    def test_custom_jail_can_be_unbanned(self, logger):
        self.banned['nginx-auth'] = ['192.0.2.12']
        self.assertTrue(backend.unban({'jail': 'nginx-auth', 'ip': '192.0.2.12'})['ok'])

    def test_global_status_string_list(self):
        with patch.object(backend, 'call', return_value=[('Jail list', 'sshd, nginx-auth')]):
            self.assertEqual(backend.active_jails(), ['sshd', 'nginx-auth'])

    def test_malicious_daemon_jail_name_rejected(self):
        with patch.object(backend, 'call', return_value=[('Jail list', ['--all'])]):
            with self.assertRaises(backend.ServiceError):
                backend.active_jails()

    def test_timestamp_formats(self):
        self.assertEqual(backend.format_timestamp('Sun Sep  6 22:09:12 2026 daemon.notice'), '2026-09-06 22:09:12')
        self.assertEqual(backend.format_timestamp('2026-09-06 22:09:12,234 fail2ban.actions'), '2026-09-06 22:09:12')
        self.assertEqual(backend.format_timestamp('2026-09-06T22:09:12+08:00 host'), '2026-09-06 22:09:12')

    def test_file_logs_custom_jail_and_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fail2ban.log'
            line = '2026-09-06 22:09:12,123 fail2ban.actions [123]: NOTICE [nginx-auth] Ban 2001:db8::10\n'
            path.write_text(line * 2, encoding='utf-8')
            with patch.object(backend, 'log_sources', return_value=([str(path), str(path)], False)):
                events, warnings = backend.recent_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['jail'], 'nginx-auth')
            self.assertEqual(events[0]['time'], '2026-09-06 22:09:12')

    def test_invalid_config_does_not_fall_back_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text('[]', encoding='utf-8')
            with patch.object(backend, 'CONFIG', str(path)):
                with self.assertRaises(ValueError):
                    backend.settings()

    def test_history_disabled_is_explicit(self):
        with patch.object(backend, 'log_sources', return_value=([], False)):
            self.assertEqual(backend.recent_events(), ([], ['history_unavailable']))


if __name__ == "__main__":
    unittest.main()
