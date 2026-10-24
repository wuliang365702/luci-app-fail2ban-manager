"""On-demand Fail2ban Python action: extend one existing ticket without unbanning."""
import ipaddress
import logging
import time

from fail2ban.server.action import ActionBase

MAX_SECONDS = 315360000


class Action(ActionBase):
    manager_api_version = 1

    def __init__(self, jail, name):
        super().__init__(jail, name)
        self.jail = jail
        pending = getattr(jail.actions, '_reload_actions', None)
        if isinstance(pending, dict):
            pending[name] = {}

    def clearAllParams(self):
        pass

    def reload(self, **kwargs):
        self.start()

    def start(self):
        if self.jail.database is None:
            return
        # Restore manual deadlines without the automatic jail's maxtime clamp.
        for ticket in self.jail.database.getCurrentBans(self.jail, forbantime=-1, correctBanTime=False):
            end = ticket.getData().get('manager_manual_until')
            if type(end) not in (int, float) or end <= time.time():
                continue
            duration = end - ticket.getTime()
            if not 0 < duration <= MAX_SECONDS:
                continue
            ticket.setBanTime(duration)
            ticket.restored = True
            self.jail.putFailTicket(ticket)

    def stop(self):
        pass

    def ban(self, aInfo):
        pass

    def unban(self, aInfo):
        pass

    def extend(self, ip, seconds, expected_end):
        if not isinstance(ip, str) or '%' in ip:
            raise ValueError('Invalid IP')
        ip = str(ipaddress.ip_address(ip))
        if type(seconds) is not int or not 1 <= seconds <= MAX_SECONDS:
            raise ValueError('Invalid extension')
        if type(expected_end) is not int or expected_end <= 0:
            raise ValueError('Invalid expected expiry')
        manager = self.jail.actions.banManager
        # Fail2ban 1.1 has no public per-ticket duration setter. Guard its known
        # ticket lock/layout; never fall back to changing the jail or re-banning.
        lock = getattr(manager, '_BanManager__lock', None)
        tickets = getattr(manager, '_BanManager__banList', None)
        if lock is None or not isinstance(tickets, dict):
            raise RuntimeError('Unsupported Fail2ban ticket API')
        with lock:
            ticket = tickets.get(ip)
            if ticket is None:
                raise ValueError('Address is no longer banned')
            default = manager.getBanTime()
            duration = ticket.getBanTime(default)
            end = ticket.getEndOfBanTime(default)
            if duration < 0:
                raise ValueError('Permanent ban cannot be extended')
            if end <= time.time() or abs(end - expected_end) > 1:
                raise ValueError('Ban changed; refresh required')
            if duration + seconds > MAX_SECONDS:
                raise ValueError('Result exceeds ten-year safety bound')
            ticket.setBanTime(duration + seconds)
            previous_data = ticket.getData().copy()
            data = previous_data.copy()
            data['manager_manual_until'] = ticket.getEndOfBanTime(default)
            ticket.setData(data)
            try:
                if self.jail.database is not None:
                    self.jail.database.addBan(self.jail, ticket)
            except Exception:
                ticket.setBanTime(duration)
                ticket.setData(previous_data)
                raise
            # The old wake-up remains safe: it only causes an earlier recheck.
            result = {'ok': True, 'expires_at': int(ticket.getEndOfBanTime(default))}
        logging.getLogger('fail2ban.actions').log(25,
            '[%s] Manual extend %s seconds=%s', self.jail.name, ip, seconds)
        return result
