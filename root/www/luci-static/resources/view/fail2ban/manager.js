'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var snapshot = rpc.declare({ object: 'luci.fail2ban', method: 'snapshot' });
var unban = rpc.declare({ object: 'luci.fail2ban', method: 'unban', params: ['jail', 'ip'] });
var labels = Object.assign(Object.create(null), { dropbear: 'SSH', 'luci-auth': 'Web' });
var actions = { Ban: '\u5c01\u7981', Unban: '\u89e3\u5c01', 'Restore Ban': '\u6062\u590d\u5c01\u7981', 'Manual unban': '\u624b\u52a8\u89e3\u5c01' };

function formatTime(value) {
    if (typeof value === 'string') {
        var match = value.match(/^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})$/);
        var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        if (match && months.indexOf(match[1]) !== -1)
            return match[4] + '-' + String(months.indexOf(match[1]) + 1).padStart(2, '0') + '-' + match[2].padStart(2, '0') + ' ' + match[3];
        return value;
    }
    function pad(number) { return String(number).padStart(2, '0'); }
    return value.getFullYear() + '-' + pad(value.getMonth() + 1) + '-' + pad(value.getDate()) + ' ' +
        pad(value.getHours()) + ':' + pad(value.getMinutes()) + ':' + pad(value.getSeconds());
}

function table(headers) {
    return E('table', { 'class': 'table cbi-section-table', 'style': 'table-layout:fixed;width:100%' }, [
        E('tr', { 'class': 'tr table-titles' }, headers.map(function(text) { return E('th', { 'class': 'th' }, text); }))
    ]);
}

function cell(value) {
    return E('td', { 'class': 'td', 'style': 'overflow-wrap:anywhere;white-space:normal' }, value);
}

function emptyRow(target, columns, text) {
    target.appendChild(E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td', 'colspan': columns }, text)]));
}

function duration(seconds) {
    if (seconds < 0) return '\u6c38\u4e45';
    if (seconds > 0 && seconds % 86400 === 0) return (seconds / 86400) + '\u5929';
    if (seconds > 0 && seconds % 3600 === 0) return (seconds / 3600) + '\u5c0f\u65f6';
    if (seconds % 60 === 0) return (seconds / 60) + '\u5206\u949f';
    return seconds + '\u79d2';
}

function policyText(jail) {
    if (jail.bantime_increment) {
        return '\u57fa\u7840' + duration(jail.bantime) + '\uff0c\u91cd\u590d\u8fdd\u89c4\u9012\u589e' +
            (jail.bantime_maximum > 0 ? '\uff0c\u6700\u957f' + duration(jail.bantime_maximum) : '');
    }
    return (jail.bantime_increment === false ? '\u56fa\u5b9a' : '') + duration(jail.bantime);
}

function expiryText(value) {
    if (!value) return '\u672a\u77e5';
    return value.permanent ? '\u6c38\u4e45\u5c01\u7981' : (value.time || '\u672a\u77e5');
}

function remainingText(value, now) {
    if (!value) return '\u672a\u77e5';
    if (value.permanent) return '\u6c38\u4e45';
    if (!Number.isFinite(value.expires_at) || !Number.isFinite(now)) return '\u672a\u77e5';
    var seconds = Math.max(0, Math.ceil(value.expires_at - now));
    if (!seconds) return '\u7b49\u5f85\u89e3\u5c01';
    if (seconds < 60) return seconds + '\u79d2';
    var minutes = Math.ceil(seconds / 60);
    var days = Math.floor(minutes / 1440), hours = Math.floor(minutes % 1440 / 60);
    return ((days ? days + '\u5929 ' : '') + (hours ? hours + '\u5c0f\u65f6 ' : '') + (minutes % 60 ? minutes % 60 + '\u5206\u949f' : '')).trim();
}

function banDuration(value) {
    return value && Number.isFinite(value.duration) ? duration(value.duration) : '\u672a\u77e5';
}

return view.extend({
    handleSave: null,
    handleSaveApply: null,
    handleReset: null,

    load: function() { return snapshot().catch(function() { return {ok:false, error:'RPC error'}; }); },

    confirmUnban: function(jail, ip) {
        var self = this;
        self.busy = true;
        var cancel = E('button', { 'class': 'btn', 'click': function() { ui.hideModal(); self.busy = false; } }, '\u53d6\u6d88');
        var confirm = E('button', { 'class': 'btn cbi-button-positive', 'click': function() {
            confirm.disabled = cancel.disabled = true;
            return unban(jail, ip).then(function(result) {
                if (!result.ok) {
                    var errors = { not_banned: '\u8be5 IP \u5df2\u4e0d\u5728\u5c01\u7981\u540d\u5355\u4e2d', service_unavailable: 'Fail2ban \u6682\u65f6\u4e0d\u53ef\u7528' };
                    throw new Error(errors[result.error] || '\u89e3\u5c01\u5931\u8d25');
                }
                if (result.audit_warning)
                    ui.addNotification(null, E('p', {}, '\u5df2\u89e3\u5c01\uff0c\u4f46\u624b\u52a8\u64cd\u4f5c\u5ba1\u8ba1\u65e5\u5fd7\u5199\u5165\u5931\u8d25'), 'warning');
                ui.hideModal();
                return self.refresh();
            }).catch(function(error) {
                ui.addNotification(null, E('p', {}, error.message || '\u89e3\u5c01\u5931\u8d25'), 'error');
            }).finally(function() {
                confirm.disabled = cancel.disabled = false;
                self.busy = false;
            });
        } }, '\u786e\u8ba4\u89e3\u5c01');
        ui.showModal('\u89e3\u9664\u5c01\u7981', [
            E('p', { 'style': 'overflow-wrap:anywhere' }, (labels[jail] || jail) + ' \u00b7 ' + ip),
            E('div', { 'class': 'right' }, [cancel, ' ', confirm])
        ]);
    },

    refresh: function() {
        var self = this;
        if (self.refreshing) return Promise.resolve();
        self.refreshing = true;
        self.drawStatus();
        return snapshot().then(function(data) {
            if (!data || !data.ok) throw new Error((data && (data.error || (data.unavailable || []).join(', '))) || 'Fail2ban unavailable');
            self.data = data;
            self.refreshError = '';
            self.draw();
        }).catch(function(error) {
            self.refreshError = String(error.message || 'RPC error').slice(0, 160);
        }).finally(function() {
            self.refreshing = false;
            self.drawStatus();
        });
    },

    drawStatus: function() {
        var self = this, data = self.data || {};
        self.status.textContent = self.refreshError ? '\u66f4\u65b0\u5931\u8d25\uff08\u4fdd\u7559\u4e0a\u6b21\u6570\u636e\uff09\uff1a' + self.refreshError :
            (self.refreshing ? '\u66f4\u65b0\u4e2d' : (data.ok ? '\u8fd0\u884c\u4e2d' : '\u670d\u52a1\u4e0d\u53ef\u7528'));
        self.status.classList.toggle('error', !!self.refreshError || !data.ok);
        self.updated.textContent = '\u6700\u540e\u66f4\u65b0\uff1a' + (data.router_time_text || '\u672a\u77e5') +
            (data.router_timezone ? ' (' + data.router_timezone + ')' : '');
    },

    draw: function() {
        var self = this, data = self.data || {}, group = self.group.value;
        var names = Object.create(null);
        (data.jails || []).forEach(function(jail) { names[jail.jail] = jail.label; });
        (data.events || []).forEach(function(event) { if (!names[event.jail]) names[event.jail] = event.jail; });
        while (self.group.options.length > 1) self.group.remove(1);
        Object.keys(names).sort().forEach(function(name) {
            self.group.appendChild(E('option', { 'value': name }, names[name]));
            labels[name] = names[name];
        });
        self.group.value = Object.prototype.hasOwnProperty.call(names, group) ? group : '';
        group = self.group.value;
        var jails = (data.jails || []).filter(function(jail) { return !group || jail.jail === group; });
        var rows = [];
        self.drawStatus();
        while (self.bans.rows.length > 1) self.bans.deleteRow(1);
        while (self.events.rows.length > 1) self.events.deleteRow(1);
        while (self.policies.rows.length > 1) self.policies.deleteRow(1);
        jails.forEach(function(jail) {
            self.policies.appendChild(E('tr', { 'class': 'tr' }, [
                cell(jail.label), cell(String(jail.failed)),
                cell(duration(jail.findtime) + ' / ' + jail.maxretry + '\u6b21'),
                cell(policyText(jail))
            ]));
            (jail.ips || []).forEach(function(ip) {
                var command = self.writable ? E('button', {
                    'class': 'btn cbi-button-remove', 'type': 'button',
                    'click': function() { self.confirmUnban(jail.jail, ip); },
                    'aria-label': '\u89e3\u5c01 ' + ip
                }, '\u89e3\u5c01') : '\u53ea\u8bfb';
                var expiry = (jail.expirations || {})[ip];
                rows.push(E('tr', { 'class': 'tr' }, [cell(ip), cell(jail.label), cell(banDuration(expiry)), cell(remainingText(expiry, data.router_time)), cell(expiryText(expiry)), cell(command)]));
            });
        });
        if (!jails.length) emptyRow(self.policies, 4, '\u6682\u65e0\u8fd0\u884c\u7684\u670d\u52a1');
        self.historyWarning.textContent = (data.history_warnings || []).length ? '\u65e5\u5fd7\u53ef\u80fd\u4e0d\u5b8c\u6574\uff1a' + data.history_warnings.join(', ') : '';
        rows.forEach(function(row) { self.bans.appendChild(row); });
        if (!rows.length) emptyRow(self.bans, 6, data.ok ? '\u5f53\u524d\u65e0\u5c01\u7981 IP' : '\u65e0\u6cd5\u83b7\u53d6\u5c01\u7981\u540d\u5355');
        var events = (data.events || []).filter(function(event) { return !group || event.jail === group; });
        events.forEach(function(event) {
            self.events.appendChild(E('tr', { 'class': 'tr' }, [cell(formatTime(event.time)), cell(labels[event.jail] || event.jail), cell(actions[event.action] || event.action), cell(event.ip)]));
        });
        if (!events.length) emptyRow(self.events, 4, '\u6682\u65e0\u8bb0\u5f55');
    },

    render: function(data) {
        var self = this;
        self.data = data;
        self.writable = L.hasViewPermission();
        self.status = E('span', { 'role': 'status', 'aria-live': 'polite', 'style': 'max-width:100%;overflow-wrap:anywhere' });
        self.updated = E('span', { 'style': 'max-width:100%;overflow-wrap:anywhere' });
        self.historyWarning = E('p', { 'role': 'status' });
        self.group = E('select', { 'aria-label': '\u670d\u52a1\u7b5b\u9009', 'style': 'max-width:100%;min-width:0', 'change': function() { self.draw(); } }, [
            E('option', { 'value': '' }, '\u5168\u90e8\u670d\u52a1')
        ]);
        self.policies = table(['\u670d\u52a1', '\u89c2\u5bdf\u7a97\u53e3\u5185\u5931\u8d25\u6b21\u6570', '\u5931\u8d25\u9608\u503c', '\u5c01\u7981\u7b56\u7565']);
        self.bans = table(['IP', '\u670d\u52a1', '\u672c\u6b21\u5c01\u7981\u65f6\u957f', '\u5269\u4f59\u65f6\u95f4', '\u9884\u8ba1\u89e3\u5c01\u65f6\u95f4', '\u64cd\u4f5c']);
        self.bans.style.minWidth = '760px';
        self.events = table(['\u65f6\u95f4', '\u670d\u52a1', '\u4e8b\u4ef6', 'IP']);
        var refresh = E('button', { 'class': 'btn cbi-button-action', 'type': 'button', 'click': function() {
            refresh.disabled = true;
            return self.refresh().finally(function() { refresh.disabled = false; });
        } }, '\u5237\u65b0');
        var content = E('div', { 'class': 'cbi-map f2b-manager' }, [
            E('style', {}, '@media (max-width:767px){.f2b-manager .table{display:table!important}.f2b-manager .table .tr{display:table-row!important}.f2b-manager .table .th,.f2b-manager .table .td{display:table-cell!important;width:auto!important;font-size:13px;padding:8px 4px!important}}'),
            E('h2', {}, 'Fail2ban'),
            E('div', { 'style': 'display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px' }, [self.group, refresh, self.status, self.updated]),
            self.policies,
            E('h3', {}, '\u5f53\u524d\u5c01\u7981'), E('div', { 'style': 'overflow-x:auto;max-width:100%' }, self.bans),
            E('h3', {}, '\u8fd1\u671f\u5c01\u7981\u8bb0\u5f55'),
            E('p', { 'class': 'cbi-section-description' }, '\u6700\u8fd1 200 \u6761'),
            self.historyWarning,
            self.events
        ]);
        self.draw();
        poll.add(function() { return self.busy ? Promise.resolve() : self.refresh(); }, 15);
        return content;
    }
});
