import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
import contextlib
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
        self.assertEqual(result['expirations']['192.0.2.10']['duration'], 7200)
        self.assertIsInstance(result['expirations']['192.0.2.10']['expires_at'], int)
        self.assertTrue(result['expirations']['2001:db8::10']['permanent'])

    def test_snapshot_has_router_clock(self):
        with patch.object(backend, 'recent_events', return_value=([], [])):
            result = backend.snapshot()
        self.assertIsInstance(result['router_time'], int)
        self.assertRegex(result['router_time_text'], r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
        self.assertRegex(result['router_timezone'], r'^UTC[+-]\d{2}:\d{2}$')

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

    def policy_request(self):
        return {'jail':'dropbear', 'findtime':600, 'maxretry':5, 'bantime':3600,
                'increment':True, 'maximum':604800,
                'expected':{'findtime':600,'maxretry':5,'bantime':600,'increment':True,'maximum':604800}}

    def test_policy_persists_only_whitelisted_override_and_reloads_one_jail(self):
        params = self.policy_request()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manager.local'
            path.write_text('[other-jail]\nmaxretry = 9\n')
            with patch.object(backend,'OVERRIDE',str(path)), patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'client_command') as client, patch.object(backend,'audit',return_value=True), patch.object(backend,'policy_values',side_effect=[params['expected'],{k:v for k,v in params.items() if k not in ('jail','expected')} ]):
                self.assertTrue(backend.save_policy(params)['ok'])
            text = path.read_text()
            self.assertIn('[other-jail]',text)
            self.assertIn('maxretry = 9',text)
            self.assertIn('bantime = 3600',text)
            self.assertNotIn('action =',text)
            self.assertEqual(client.call_args_list, [unittest.mock.call(['-t']), unittest.mock.call(['reload','dropbear'])])

    def test_policy_test_failure_restores_exact_original(self):
        params = self.policy_request()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manager.local'
            old = b'# retained\n[other-jail]\nmaxretry=9\n'
            path.write_bytes(old)
            with patch.object(backend,'OVERRIDE',str(path)), patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'client_command',side_effect=backend.subprocess.CalledProcessError(1,'test')) as client, patch.object(backend,'policy_values',return_value=params['expected']):
                self.assertEqual(backend.save_policy(params)['error'],'policy_apply_failed')
            self.assertEqual(path.read_bytes(),old)
            client.assert_called_once_with(['-t'])

    def test_policy_reload_failure_rolls_back_and_checks_previous_values(self):
        params = self.policy_request()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manager.local'
            with patch.object(backend,'OVERRIDE',str(path)), patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'client_command',side_effect=[None,backend.subprocess.CalledProcessError(1,'reload'),None]), patch.object(backend,'policy_values',return_value=params['expected']):
                self.assertEqual(backend.save_policy(params)['error'],'policy_apply_failed')
            self.assertFalse(path.exists())

    def test_invalid_policy_and_stale_values_do_not_write(self):
        for key, value in [('findtime',True),('maxretry',0),('bantime',-1),('increment','yes'),('maximum',1)]:
            params = self.policy_request()
            params[key] = value
            with patch.object(backend,'atomic_override') as writer:
                self.assertEqual(backend.save_policy(params)['error'],'invalid_policy')
                writer.assert_not_called()
        params = self.policy_request()
        params['expected'] = {}
        with patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'atomic_override') as writer:
            self.assertEqual(backend.save_policy(params)['error'],'policy_changed')
            writer.assert_not_called()

    def test_extend_accepts_more_than_seven_days_without_global_setters(self):
        end = backend.jail_status('dropbear')['expirations']['192.0.2.10']['expires_at']
        original = self.command
        extended = False
        def command(args):
            nonlocal extended
            if args[:1] == ['get'] and args[2:] == ['actions']:
                return ['luci-manager']
            if args[2:] == ['action','luci-manager','manager_api_version']:
                return 1
            if args[:5] == ['set','dropbear','action','luci-manager','extend']:
                extended = True
                self.calls.append(args)
                return {'ok':True}
            if extended and args[2:] == ['banip','--with-time']:
                return ['192.0.2.10 start + 2599200 = ' + backend.time.strftime('%Y-%m-%d %H:%M:%S',backend.time.localtime(end+2592000))]
            return original(args)
        self.call_mock.side_effect = command
        with patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'audit',return_value=True), patch.object(backend,'ensure_control'):
            result = backend.extend_ban({'jail':'dropbear','ip':'192.0.2.10','seconds':2592000,'expected_end':end})
        self.assertTrue(result['ok'])
        self.assertEqual(result['expires_at'],end+2592000)
        self.assertFalse(any(args[0]=='set' and args[2] in ('bantime','unbanip','banip') for args in self.calls))

    def test_extension_rejects_invalid_stale_permanent_or_absent_bans(self):
        for ip, seconds, end, error in [('bad;command',60,1,'invalid_extension'),('192.0.2.10',True,1,'invalid_extension'),('192.0.2.10',-1,1,'invalid_extension'),('192.0.2.99',60,1,'not_banned'),('192.0.2.10',60,1,'ban_changed'),('2001:db8::10',60,1,'ban_changed')]:
            with patch.object(backend,'mutation_lock',contextlib.nullcontext):
                self.assertEqual(backend.extend_ban({'jail':'dropbear','ip':ip,'seconds':seconds,'expected_end':end})['error'],error)
        self.assertFalse(any(args[0]=='set' for args in self.calls))

    def test_policy_restore_write_failure_is_reported(self):
        params = self.policy_request()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(backend,'OVERRIDE',str(Path(directory)/'manager.local')), patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'policy_values',return_value=params['expected']), patch.object(backend,'atomic_override',side_effect=[None,OSError('disk failure')]), patch.object(backend,'client_command',side_effect=backend.subprocess.CalledProcessError(1,'test')):
                self.assertEqual(backend.save_policy(params)['error'],'rollback_failed')

    def test_symlink_override_refused_without_writes(self):
        params = self.policy_request()
        with patch.object(backend,'mutation_lock',contextlib.nullcontext), patch.object(backend,'policy_values',return_value=params['expected']), patch.object(backend.Path,'is_symlink',return_value=True), patch.object(backend,'atomic_override') as writer:
            with self.assertRaises(ValueError): backend.save_policy(params)
            writer.assert_not_called()

    def test_custom_socket_cannot_mutate_another_default_instance(self):
        with patch.object(backend,'settings',return_value={'socket':'/tmp/custom.sock'}), patch.object(backend,'atomic_override') as writer:
            self.assertEqual(backend.save_policy(self.policy_request())['error'],'unsupported_configuration')
            self.assertEqual(backend.extend_ban({})['error'],'unsupported_configuration')
            writer.assert_not_called()

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
