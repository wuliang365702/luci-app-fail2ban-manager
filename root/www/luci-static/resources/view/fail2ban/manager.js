'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var snapshot = rpc.declare({ object: 'luci.fail2ban', method: 'snapshot' });
var unban = rpc.declare({ object: 'luci.fail2ban', method: 'unban', params: ['jail', 'ip'] });
var labels = { dropbear: 'SSH', 'luci-auth': 'Web' };
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
    if (seconds % 60 === 0) return (seconds / 60) + '\u5206\u949f';
    return seconds + '\u79d2';
}

return view.extend({
    handleSave: null,
    handleSaveApply: null,
    handleReset: null,

    load: function() { return snapshot(); },

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
            E('p', {}, (labels[jail] || jail) + ' \u00b7 ' + ip),
            E('div', { 'class': 'right' }, [cancel, ' ', confirm])
        ]);
    },

    refresh: function() {
        var self = this;
        return snapshot().then(function(data) {
            self.data = data;
            self.draw();
        }).catch(function(error) {
            self.status.textContent = '\u5237\u65b0\u5931\u8d25\uff1a' + (error.message || 'RPC error');
        });
    },

    draw: function() {
        var self = this, data = self.data || {}, group = self.group.value;
        var names = {};
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
        self.status.textContent = data.ok ? '\u8fd0\u884c\u4e2d \u00b7 ' + formatTime(new Date()) : '\u670d\u52a1\u4e0d\u53ef\u7528\uff1a' + (data.unavailable || []).join(', ');
        while (self.bans.rows.length > 1) self.bans.deleteRow(1);
        while (self.events.rows.length > 1) self.events.deleteRow(1);
        while (self.policies.rows.length > 1) self.policies.deleteRow(1);
        jails.forEach(function(jail) {
            self.policies.appendChild(E('tr', { 'class': 'tr' }, [
                cell(jail.label), cell(String(jail.failed)),
                cell(duration(jail.findtime) + ' / ' + jail.maxretry + '\u6b21'),
                cell(duration(jail.bantime))
            ]));
            (jail.ips || []).forEach(function(ip) {
                var command = self.writable ? E('button', {
                    'class': 'btn cbi-button-remove', 'type': 'button',
                    'click': function() { self.confirmUnban(jail.jail, ip); },
                    'aria-label': '\u89e3\u5c01 ' + ip
                }, '\u89e3\u5c01') : '\u53ea\u8bfb';
                rows.push(E('tr', { 'class': 'tr' }, [cell(ip), cell(jail.label), cell(command)]));
            });
        });
        if (!jails.length) emptyRow(self.policies, 4, '\u6682\u65e0\u8fd0\u884c\u7684\u670d\u52a1');
        self.historyWarning.textContent = (data.history_warnings || []).length ? '\u65e5\u5fd7\u53ef\u80fd\u4e0d\u5b8c\u6574\uff1a' + data.history_warnings.join(', ') : '';
        rows.forEach(function(row) { self.bans.appendChild(row); });
        if (!rows.length) emptyRow(self.bans, 3, data.ok ? '\u5f53\u524d\u65e0\u5c01\u7981 IP' : '\u65e0\u6cd5\u83b7\u53d6\u5c01\u7981\u540d\u5355');
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
        self.status = E('span', { 'role': 'status', 'aria-live': 'polite' });
        self.historyWarning = E('p', { 'role': 'status' });
        self.group = E('select', { 'aria-label': '\u670d\u52a1\u7b5b\u9009', 'change': function() { self.draw(); } }, [
            E('option', { 'value': '' }, '\u5168\u90e8\u670d\u52a1')
        ]);
        self.policies = table(['\u670d\u52a1', '\u5f53\u524d\u5931\u8d25\u8ba1\u6570', '\u5931\u8d25\u9608\u503c', '\u5c01\u7981\u65f6\u957f']);
        self.bans = table(['IP', '\u670d\u52a1', '\u64cd\u4f5c']);
        self.events = table(['\u65f6\u95f4', '\u670d\u52a1', '\u4e8b\u4ef6', 'IP']);
        var refresh = E('button', { 'class': 'btn cbi-button-action', 'type': 'button', 'click': function() {
            refresh.disabled = true;
            return self.refresh().finally(function() { refresh.disabled = false; });
        } }, '\u5237\u65b0');
        var content = E('div', { 'class': 'cbi-map f2b-manager' }, [
            E('style', {}, '@media (max-width:767px){.f2b-manager .table{display:table!important}.f2b-manager .table .tr{display:table-row!important}.f2b-manager .table .th,.f2b-manager .table .td{display:table-cell!important;width:auto!important;font-size:13px;padding:8px 4px!important}}'),
            E('h2', {}, 'Fail2ban'),
            E('div', { 'style': 'display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px' }, [self.group, refresh, self.status]),
            self.policies,
            E('h3', {}, '\u5f53\u524d\u5c01\u7981'), self.bans,
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
