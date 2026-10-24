'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var snapshot = rpc.declare({ object: 'luci.fail2ban', method: 'snapshot' });
var unban = rpc.declare({ object: 'luci.fail2ban', method: 'unban', params: ['jail', 'ip'] });
var savePolicy = rpc.declare({ object: 'luci.fail2ban', method: 'save_policy', params: ['jail', 'findtime', 'maxretry', 'bantime', 'increment', 'maximum', 'expected'] });
var extendBan = rpc.declare({ object: 'luci.fail2ban', method: 'extend_ban', params: ['jail', 'ip', 'seconds', 'expected_end'] });
var labels = Object.assign(Object.create(null), { dropbear: 'SSH', 'luci-auth': 'Web' });
var actions = { Ban: '\u5c01\u7981', Unban: '\u89e3\u5c01', 'Restore Ban': '\u6062\u590d\u5c01\u7981', 'Manual unban': '\u624b\u52a8\u89e3\u5c01' };
actions['Manual extend'] = '\u624b\u52a8\u5ef6\u957f';

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

function routerDate(epoch, zone) {
    var match = /^UTC([+-])(\d{2}):(\d{2})$/.exec(zone || '');
    if (!match || !Number.isFinite(epoch)) return '\u672a\u77e5';
    var offset = (Number(match[2]) * 60 + Number(match[3])) * 60 * (match[1] === '+' ? 1 : -1);
    var date = new Date((epoch + offset) * 1000);
    function pad(n) { return String(n).padStart(2, '0'); }
    return date.getUTCFullYear() + '-' + pad(date.getUTCMonth() + 1) + '-' + pad(date.getUTCDate()) + ' ' +
        pad(date.getUTCHours()) + ':' + pad(date.getUTCMinutes()) + ':' + pad(date.getUTCSeconds());
}

function numberInput(value, min, max) {
    return E('input', { 'type':'number', 'value':String(value), 'min':String(min), 'max':String(max), 'step':'1', 'required':'', 'style':'width:100px;max-width:100%' });
}

function timeInput(seconds) {
    var unit = seconds > 0 && seconds % 86400 === 0 ? 86400 : (seconds > 0 && seconds % 3600 === 0 ? 3600 : 60);
    var number = numberInput(seconds / unit, 1, 5256000);
    var select = E('select', { 'style':'width:95px;max-width:100%' }, [
        E('option', {value:'60'}, '\u5206\u949f'), E('option', {value:'3600'}, '\u5c0f\u65f6'), E('option', {value:'86400'}, '\u5929')
    ]);
    select.value = String(unit);
    return { node:E('div', {style:'display:flex;gap:10px;align-items:center;flex-wrap:wrap'}, [number,select]),
        controls:[number, select], value:function() {
            var value = Number(number.value), total = value * Number(select.value);
            if (!number.reportValidity() || !Number.isInteger(value) || !Number.isSafeInteger(total) || total < 60 || total > 315360000)
                throw new Error('\u65f6\u957f\u9700\u4e3a1\u5206\u949f\u81f33650\u5929\u7684\u6574\u6570');
            return total;
        } };
}

function formRow(label, control) {
    return E('label', {style:'display:grid;grid-template-columns:120px minmax(0,1fr);gap:12px;align-items:center;margin:12px 0'}, [E('span',{},label), control]);
}

function resultError(result) {
    var messages = {policy_changed:'\u7b56\u7565\u5df2\u53d8\u5316\uff0c\u8bf7\u5237\u65b0\u540e\u91cd\u8bd5',
        ban_changed:'\u5c01\u7981\u5df2\u53d8\u5316\uff0c\u8bf7\u5237\u65b0\u540e\u91cd\u8bd5',
        not_banned:'\u8be5 IP \u5df2\u4e0d\u5728\u5c01\u7981\u540d\u5355\u4e2d',
        rollback_failed:'\u7b56\u7565\u6062\u590d\u5931\u8d25\uff0c\u8bf7\u7acb\u5373\u68c0\u67e5 Fail2ban \u914d\u7f6e',
        policy_apply_failed:'\u7b56\u7565\u5e94\u7528\u5931\u8d25\uff0c\u5df2\u6062\u590d\u539f\u914d\u7f6e',
        unsupported_extension:'\u5f53\u524d Fail2ban \u7248\u672c\u4e0d\u652f\u6301\u5b89\u5168\u5ef6\u957f',
        unsupported_configuration:'\u81ea\u5b9a\u4e49 socket \u6682\u4e0d\u652f\u6301\u7b56\u7565\u548c\u5ef6\u957f\u64cd\u4f5c'};
    return new Error(messages[result.error] || '\u64cd\u4f5c\u5931\u8d25\uff0c\u8bf7\u5237\u65b0\u540e\u91cd\u8bd5');
}

return view.extend({
    handleSave: null,
    handleSaveApply: null,
    handleReset: null,

    load: function() { return snapshot().catch(function() { return {ok:false, error:'RPC error'}; }); },

    editModal: function(title, rows, text, controls, submit) {
        var self = this;
        if (!self.writable || self.busy) return;
        self.busy = true;
        var cancel = E('button', {class:'btn',type:'button',click:function() { ui.hideModal(); self.busy = false; }}, '\u53d6\u6d88');
        var confirm = E('button', {class:'btn cbi-button-positive',type:'button',click:async function() {
            confirm.disabled = cancel.disabled = true;
            try {
                var pending = submit();
                controls.forEach(function(control) { control.disabled = true; });
                var result = await pending;
                if (!result.ok) throw resultError(result);
                if (result.audit_warning) ui.addNotification(null,E('p',{},'\u64cd\u4f5c\u5df2\u5b8c\u6210\uff0c\u4f46\u5ba1\u8ba1\u65e5\u5fd7\u5199\u5165\u5931\u8d25'),'warning');
                ui.hideModal();
                self.busy = false;
                await self.refresh();
            } catch (error) {
                ui.addNotification(null,E('p',{},error.message || 'RPC error'),'error');
            } finally {
                confirm.disabled = cancel.disabled = false;
                controls.forEach(function(control) { control.disabled = false; });
            }
        }}, text);
        var body = E('div',{keydown:function(event) {
            if (event.key === 'Escape') {
                event.preventDefault();
                if (!confirm.disabled) { ui.hideModal(); self.busy = false; }
            }
        }}, rows.concat([E('div',{class:'right',style:'display:flex;justify-content:flex-end;gap:10px;margin-top:20px'},[cancel,confirm])]));
        ui.showModal(title, [body]);
    },

    editPolicy: function(jail) {
        var observation = timeInput(jail.findtime), base = timeInput(jail.bantime);
        var maximum = timeInput(jail.bantime_maximum > 0 ? jail.bantime_maximum : Math.max(jail.bantime,604800));
        var retry = numberInput(jail.maxretry,1,1000);
        var increment = E('input',{type:'checkbox'});
        increment.checked = !!jail.bantime_increment;
        var maxRow = formRow('\u6700\u957f\u5c01\u7981',maximum.node);
        function toggle() { maxRow.style.display = increment.checked ? 'grid' : 'none'; }
        increment.addEventListener('change',toggle);
        toggle();
        var expected = {findtime:jail.findtime,maxretry:jail.maxretry,bantime:jail.bantime,increment:!!jail.bantime_increment,maximum:jail.bantime_maximum || 0};
        this.editModal(jail.label + ' \u9632\u62a4\u7b56\u7565',[
            formRow('\u89c2\u5bdf\u65f6\u95f4',observation.node), formRow('\u5931\u8d25\u6b21\u6570',retry),
            formRow('\u57fa\u7840\u5c01\u7981',base.node), formRow('\u9012\u589e\u5c01\u7981',E('span',{},[increment,' \u542f\u7528'])), maxRow
        ],'\u4fdd\u5b58\u5e76\u5e94\u7528',observation.controls.concat(base.controls,maximum.controls,[retry,increment]),function() {
            var findtime = observation.value(), bantime = base.value(), cap = increment.checked ? maximum.value() : expected.maximum || maximum.value();
            if (!retry.reportValidity() || !Number.isInteger(Number(retry.value))) throw new Error('\u5931\u8d25\u6b21\u6570\u9700\u4e3a1\u81f31000\u7684\u6574\u6570');
            if (increment.checked && cap < bantime) throw new Error('\u6700\u957f\u5c01\u7981\u4e0d\u80fd\u5c0f\u4e8e\u57fa\u7840\u5c01\u7981');
            return savePolicy(jail.jail,findtime,Number(retry.value),bantime,increment.checked,cap,expected);
        });
    },

    extendBan: function(jail, ip, expiry) {
        var self = this, extra = timeInput(86400), preview = E('span');
        extra.controls[0].value = '24';
        extra.controls[1].value = '3600';
        function update() {
            try { preview.textContent = routerDate(expiry.expires_at + extra.value(),self.data.router_timezone); }
            catch (_) { preview.textContent = '\u672a\u77e5'; }
        }
        extra.controls.forEach(function(control) { control.addEventListener('input',update); control.addEventListener('change',update); });
        update();
        this.editModal('\u5ef6\u957f\u5c01\u7981',[
            formRow('\u670d\u52a1',E('span',{},jail.label)), formRow('IP',E('span',{style:'overflow-wrap:anywhere'},ip)),
            formRow('\u5f53\u524d\u89e3\u5c01\u65f6\u95f4',E('span',{},expiry.time)),
            formRow('\u8ffd\u52a0\u65f6\u95f4',extra.node), formRow('\u5ef6\u957f\u540e\u89e3\u5c01\u65f6\u95f4',preview)
        ],'\u786e\u8ba4\u5ef6\u957f',extra.controls,function() { return extendBan(jail.jail,ip,extra.value(),expiry.expires_at); });
    },

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
                cell(policyText(jail)), cell(self.writable ? E('button', {class:'btn cbi-button-edit',type:'button',click:function() { self.editPolicy(jail); },'aria-label':jail.label + ' \u8bbe\u7f6e'}, '\u8bbe\u7f6e') : '\u53ea\u8bfb')
            ]));
            (jail.ips || []).forEach(function(ip) {
                var command = self.writable ? E('button', {
                    'class': 'btn cbi-button-remove', 'type': 'button',
                    'click': function() { self.confirmUnban(jail.jail, ip); },
                    'aria-label': '\u89e3\u5c01 ' + ip
                }, '\u89e3\u5c01') : '\u53ea\u8bfb';
                var expiry = (jail.expirations || {})[ip];
                var extend = self.writable && expiry && !expiry.permanent ? E('button', {class:'btn cbi-button-action',type:'button',click:function() { self.extendBan(jail,ip,expiry); },'aria-label':'\u5ef6\u957f\u5c01\u7981 ' + ip}, '\u5ef6\u957f\u5c01\u7981') : null;
                rows.push(E('tr', { 'class': 'tr' }, [cell(ip), cell(jail.label), cell(banDuration(expiry)), cell(remainingText(expiry, data.router_time)), cell(expiryText(expiry)), cell(E('div',{style:'display:flex;gap:8px;flex-wrap:wrap'},[extend,command]))]));
            });
        });
        if (!jails.length) emptyRow(self.policies, 5, '\u6682\u65e0\u8fd0\u884c\u7684\u670d\u52a1');
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
        self.policies = table(['\u670d\u52a1', '\u5931\u8d25\u6b21\u6570', '\u5931\u8d25\u9608\u503c', '\u5c01\u7981\u7b56\u7565', '\u64cd\u4f5c']);
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
            E('p', { 'class': 'cbi-section-description' }, '\u6700\u591a\u663e\u793a\u6700\u8fd1 200 \u6761'),
            self.historyWarning,
            self.events
        ]);
        self.draw();
        poll.add(function() { return self.busy ? Promise.resolve() : self.refresh(); }, 15);
        return content;
    }
});
