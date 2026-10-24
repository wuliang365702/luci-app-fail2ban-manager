import importlib.util
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest.mock import Mock, patch
sys.dont_write_bytecode = True

class Base:
    def __init__(self,jail,name):
        pass

stub = types.ModuleType('fail2ban.server.action')
stub.ActionBase = Base
sys.modules.setdefault('fail2ban',types.ModuleType('fail2ban'))
sys.modules.setdefault('fail2ban.server',types.ModuleType('fail2ban.server'))
sys.modules['fail2ban.server.action'] = stub
path = Path(__file__).resolve().parents[1]/'root/usr/lib/fail2ban-manager/control.py'
spec = importlib.util.spec_from_file_location('control_test',path)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)

class Ticket:
    def __init__(self,duration=3600): self.duration=duration; self.data={}
    def getBanTime(self,default): return self.duration
    def getEndOfBanTime(self,default): return 1000+self.duration
    def setBanTime(self,value): self.duration=value
    def getData(self): return self.data
    def setData(self,value): self.data=value
    def getTime(self): return 1000

class ControlTests(unittest.TestCase):
    def setUp(self):
        self.target=Ticket()
        self.other=Ticket()
        self.manager=types.SimpleNamespace(_BanManager__lock=threading.Lock(),_BanManager__banList={'192.0.2.10':self.target,'2001:db8::10':self.other},getBanTime=lambda:3600)
        self.db=Mock()
        self.jail=types.SimpleNamespace(name='test',actions=types.SimpleNamespace(banManager=self.manager),database=self.db)
        self.action=control.Action(self.jail,'manager')
        timer=patch.object(control.time,'time',return_value=2000)
        timer.start();self.addCleanup(timer.stop)

    def test_extension_beyond_auto_cap_changes_only_target(self):
        self.assertEqual(self.action.extend('192.0.2.10',2592000,4600)['expires_at'],2596600)
        self.assertEqual(self.other.duration,3600)
        self.assertEqual(self.manager.getBanTime(),3600)
        self.db.addBan.assert_called_once_with(self.jail,self.target)

    def test_database_error_restores_ticket(self):
        self.db.addBan.side_effect=RuntimeError('disk error')
        with self.assertRaises(RuntimeError): self.action.extend('192.0.2.10',3600,4600)
        self.assertEqual(self.target.duration,3600)
        self.assertEqual(self.target.data,{})

    def test_stale_and_absent_and_permanent_rejected(self):
        for ip,end in [('192.0.2.11',4600),('192.0.2.10',1234)]:
            with self.assertRaises(ValueError): self.action.extend(ip,3600,end)
        self.target.duration=-1
        with self.assertRaises(ValueError): self.action.extend('192.0.2.10',3600,4600)
        self.db.addBan.assert_not_called()

    def test_invalid_arguments_and_overflow_rejected(self):
        for seconds in (True,-1,0,'3600',control.MAX_SECONDS):
            with self.assertRaises(ValueError): self.action.extend('192.0.2.10',seconds,4600)
        self.assertEqual(self.target.duration,3600)

    def test_expired_not_resurrected(self):
        with patch.object(control.time,'time',return_value=4601):
            with self.assertRaises(ValueError): self.action.extend('192.0.2.10',3600,4600)
        self.assertEqual(self.target.duration,3600)

    def test_ipv6(self):
        self.assertTrue(self.action.extend('2001:0db8::10',3600,4600)['ok'])
        self.assertEqual(self.target.duration,3600)

    def test_replayed_request_not_applied_twice(self):
        self.action.extend('192.0.2.10',3600,4600)
        with self.assertRaises(ValueError): self.action.extend('192.0.2.10',3600,4600)
        self.assertEqual(self.target.duration,7200)

    def test_start_restores_only_valid_manual_deadlines_without_auto_cap(self):
        self.target.data={'manager_manual_until':2596600}
        self.db.getCurrentBans.return_value=[self.target,self.other]
        self.jail.putFailTicket=Mock()
        self.action.start()
        self.db.getCurrentBans.assert_called_once_with(self.jail,forbantime=-1,correctBanTime=False)
        self.jail.putFailTicket.assert_called_once_with(self.target)
        self.assertEqual(self.target.duration,2595600)
        self.assertTrue(self.target.restored)

if __name__=='__main__': unittest.main()
