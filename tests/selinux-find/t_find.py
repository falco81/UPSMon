"""What SELinux refuses, sorted by what puts it right (4.9.0) - root's helper on its own, with
stand-in getenforce / semodule / semanage / setsebool / restorecon / ausearch / audit2why /
matchpathcon on PATH and fixtures of raw ausearch output (hex-encoded names and proctitles, the
records of each event). Run as root: python3 tests/selinux-find/t_find.py
With secilc on the machine, the local module written is compiled against a small base policy."""
import importlib.util, json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..', '..')
W = tempfile.mkdtemp(prefix='upsmon-sefind-')
ok = bad = 0


def check(name, cond, got=None):
    global ok, bad
    if cond:
        ok += 1
        print('OK   ' + name)
    else:
        bad += 1
        print('FAIL %s  -> %r' % (name, got))


BIN, ST = os.path.join(W, 'bin'), os.path.join(W, 'se')
for d in (BIN, ST, os.path.join(W, 'state', 'web')):
    os.makedirs(d)


def fake(name, body):
    with open(os.path.join(BIN, name), 'w') as f:
        f.write('#!/bin/bash\nS=%s\n%s\n' % (ST, body))
    os.chmod(os.path.join(BIN, name), 0o755)


def put(name, text):
    with open(os.path.join(ST, name), 'w') as f:
        f.write(text)


def read(name):
    try:
        return open(os.path.join(ST, name)).read()
    except OSError:
        return ''


fake('getenforce', 'cat $S/mode')
fake('semodule', '''case "$1" in
 -l|-lfull) cat $S/modules 2>/dev/null;;
 -i) n=$(basename "$2" .cil); grep -qx "$n" $S/modules 2>/dev/null || echo "$n" >> $S/modules; cp "$2" $S/loaded-$n.cil; echo "$n" >> $S/semodule-i;;
 -r) grep -vx "$2" $S/modules > $S/m.tmp; mv $S/m.tmp $S/modules; echo "$2" >> $S/semodule-r;;
esac''')
fake('getsebool', 'if grep -qx "$1" $S/bools-on 2>/dev/null; then echo "$1 --> on"; else echo "$1 --> off"; fi')
fake('setsebool', 'echo "$2" >> $S/bools-on; echo "$@" >> $S/setsebool')
fake('semanage', '''if [ "$1 $2" = "port -l" ]; then cat $S/ports 2>/dev/null
elif [ "$1 $2" = "port -a" ]; then echo "$4 $6 $7" >> $S/ports-added; printf '%s   %s   %s\\n' "$4" "$6" "$7" >> $S/ports
fi''')
fake('restorecon', 'echo "$@" >> $S/restorecon')
fake('ausearch', 'cat $S/avc 2>/dev/null')
# audit2why: each line back, then why - by a word put into the fixture for it
fake('audit2why', '''while IFS= read -r l; do echo "$l"; echo
 case "$l" in
  *dest=9849*) printf '\\tWas caused by:\\n\\tThe boolean httpd_can_network_connect was set incorrectly.\\n\\n\\tAllow access by executing:\\n\\t# setsebool -P httpd_can_network_connect 1\\n';;
  *comm=\\"settled\\"*) printf '\\tWas caused by:\\n\\t\\tUnknown - would be allowed by active policy\\n';;
  *dest=5432*) printf '\\tWas caused by:\\n\\tOne of the following booleans was set incorrectly.\\n\\t# setsebool -P httpd_execmem 1\\n';;
  *) printf '\\tWas caused by:\\n\\t\\tMissing type enforcement (TE) allow rule.\\n';;
 esac; echo; done''')
os.environ['PATH'] = BIN + ':' + os.environ['PATH']
MATCH = os.path.join(W, 'match.json')
with open(MATCH, 'w') as f:
    json.dump({'/var/www/upsmon': 'httpd_sys_content_t', '/run/upsmon': 'httpd_var_run_t'}, f)
LABELS = os.path.join(W, 'labels.json')
with open(LABELS, 'w') as f:
    json.dump({'/run/upsmon': 'httpd_var_run_t', '/var/www/upsmon': 'httpd_sys_content_t'}, f)
CONF = os.path.join(W, 'selinux-config')
with open(CONF, 'w') as f:
    f.write('SELINUX=permissive\nSELINUXTYPE=targeted\n')
CIL = os.path.join(W, 'upsmon_server.cil')
shutil.copyfile(os.path.join(ROOT, 'deploy', 'upsmon_server.cil'), CIL)
shutil.copyfile(CIL, CIL + '.in-policy')
os.environ.update(UPSMON_STATE=os.path.join(W, 'state'), UPSMON_ROOT_STATE=os.path.join(W, 'rootstate'),
                  UPSMON_SELINUX_CONFIG=CONF, UPSMON_SELINUX_RELABEL=os.path.join(W, 'autorelabel'),
                  UPSMON_SELINUX_CMDLINE=os.path.join(W, 'cmdline'), UPSMON_SELINUX_CIL=CIL,
                  UPSMON_SELINUX_AUDITD='active', UPSMON_SELINUX_LABELS=LABELS, UPSMON_SELINUX_MATCH=MATCH,
                  # 4.9.1: whose a refusal is comes from the uid the kernel wrote, and the ports from
                  # upsmon's nginx file - as root reads them
                  UPSMON_SELINUX_UIDS=json.dumps({'upsmon': 990, 'upsmon-www': 991}),
                  UPSMON_NGINX_CONF=os.path.join(W, 'nginx-upsmon.conf'))
with open(os.path.join(W, 'nginx-upsmon.conf'), 'w') as f:
    f.write('server {\n    listen      80 default_server;\n    listen      [::]:443 ssl;\n    listen 8443 ssl;\n}\n')
open(os.path.join(W, 'cmdline'), 'w').write('quiet\n')
spec = importlib.util.spec_from_file_location('uw', os.path.join(ROOT, 'deploy', 'upsmon_web.py'))
uw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uw)
uw.SE_LABELS = (('/run/upsmon', 'httpd_var_run_t', 'the folder of the daemon\'s token and port'),)
# Made for the test, and only what was not there is taken away again after it.
made = [d for d in ('/run/upsmon', '/var/www', '/var/www/upsmon', '/var/www/upsmon/assets') if not os.path.exists(d)]
for d in made:
    os.makedirs(d, exist_ok=True)


@__import__('atexit').register
def _away():
    for d in reversed(made):
        try:
            os.rmdir(d)
        except OSError:
            pass
    shutil.rmtree(W, ignore_errors=True)
WANT = {'booleans': [{'name': 'httpd_can_network_connect', 'why': 'the pages ask the daemon'}], 'ports': [],
        'app_ports': [5432, 8443]}      # the request's ports are not believed (4.9.1): nginx's file is
put('mode', 'Permissive\n')
put('modules', 'upsmon_server\n')
put('bools-on', 'httpd_can_network_connect\n')
put('ports', 'http_port_t   tcp   80, 443, 8008\nssh_port_t   tcp   22\npostgresql_port_t   tcp   5432\n'
             'unreserved_port_t   tcp   1024-32767, 61000-65535\n')
T = int(time.time()) - 3600


def hx(s):
    return s.encode().hex().upper()


def ev(n, avc, syscall='', paths=(), title='', cwd=''):
    ts = '%d.%03d:%d' % (T + n, n, 100 + n)
    out = []
    if title:
        out.append('type=PROCTITLE msg=audit(%s): proctitle=%s' % (ts, hx(title)))
    for p in paths:
        out.append('type=PATH msg=audit(%s): item=0 name=%s inode=1 dev=fd:00 mode=0100644' % (ts, p))
    if cwd:
        out.append('type=CWD msg=audit(%s): cwd="%s"' % (ts, cwd))
    if syscall:
        out.append('type=SYSCALL msg=audit(%s): arch=c000003e syscall=59 success=yes %s' % (ts, syscall))
    out.append('type=AVC msg=audit(%s): avc:  denied  %s permissive=1' % (ts, avc))
    return '----\n' + '\n'.join(out) + '\n'


UPS = 'uid=990 exe="/usr/bin/python3.11" comm="upsmon-bg"'      # the daemon: the account upsmon
DAEMON = '/usr/local/lib/upsmon/python /usr/local/lib/upsmon/upsmon.py'
avc = ''.join([
    # 1 the daemon starts chronyc under NoNewPrivileges: a rule of upsmon's
    ev(1, '{ nnp_transition } for  pid=10 comm="upsmon-bg" scontext=system_u:system_r:unconfined_service_t:s0 '
          'tcontext=system_u:system_r:chronyc_t:s0 tclass=process2', UPS, title=DAEMON),
    ev(2, '{ nnp_transition } for  pid=11 comm="upsmon-bg" scontext=system_u:system_r:unconfined_service_t:s0 '
          'tcontext=system_u:system_r:chronyc_t:s0 tclass=process2', UPS, title=DAEMON),
    # 2 chronyc writes back to the daemon's pipe: a rule (a tool of upsmon's)
    ev(3, '{ write } for  pid=12 comm="chronyc" path="pipe:[123]" scontext=system_u:system_r:chronyc_t:s0 '
          'tcontext=system_u:system_r:unconfined_service_t:s0 tclass=fifo_file', 'uid=990 exe="/usr/bin/chronyc" comm="chronyc"'),
    # 3 nginx reads a page labelled default_t: a label (the path from the PATH record, hex - a space in it)
    ev(4, '{ read } for  pid=13 comm="nginx" name=636F72652E6A73 scontext=system_u:system_r:httpd_t:s0 '
          'tcontext=system_u:object_r:default_t:s0 tclass=file', 'uid=992 exe="/usr/sbin/nginx" comm="nginx"',
       paths=[hx('/var/www/upsmon/assets/core.js')]),
    # 4 php-fpm asks the daemon: the boolean (audit2why says it)
    ev(5, '{ name_connect } for  pid=14 comm="php-fpm" dest=9849 scontext=system_u:system_r:httpd_t:s0 '
          'tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket', 'uid=991 exe="/usr/sbin/php-fpm" comm="php-fpm"'),
    # 5 nginx binds 8443, a port of no type of its own: a port (never a port's raw value decoded)
    ev(6, '{ name_bind } for  pid=15 comm="nginx" src=8443 scontext=system_u:system_r:httpd_t:s0 '
          'tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket', 'uid=992 exe="/usr/sbin/nginx" comm="nginx"'),
    # 6 the daemon reads /etc/shadow: never from a button
    ev(7, '{ read } for  pid=16 comm="upsmon-bg" name="shadow" scontext=system_u:system_r:unconfined_service_t:s0 '
          'tcontext=system_u:object_r:shadow_t:s0 tclass=file', UPS, paths=['"/etc/shadow"'], title=DAEMON),
    # 7 the daemon executes a shell script: never from a button
    ev(8, '{ execute } for  pid=17 comm="upsmon-bg" name="x.sh" scontext=system_u:system_r:unconfined_service_t:s0 '
          'tcontext=system_u:object_r:shell_exec_t:s0 tclass=file', UPS, paths=['"/var/lib/upsmon/x.sh"'], title=DAEMON),
    # 8 php-fpm connects to postgres: only a boolean that allows far more - never
    ev(9, '{ name_connect } for  pid=18 comm="php-fpm" dest=5432 scontext=system_u:system_r:httpd_t:s0 '
          'tcontext=system_u:object_r:postgresql_port_t:s0 tclass=tcp_socket', 'uid=991 exe="/usr/sbin/php-fpm" comm="php-fpm"'),
    # 9 somebody's vim and /etc/shadow: not upsmon's
    ev(10, '{ read } for  pid=19 comm="vim" name="shadow" scontext=unconfined_u:unconfined_r:unconfined_t:s0 '
           'tcontext=system_u:object_r:shadow_t:s0 tclass=file', 'uid=1000 exe="/usr/bin/vim" comm="vim"', paths=['"/etc/shadow"']),
    # 10 nginx on a path of somebody else's: not upsmon's
    ev(11, '{ read } for  pid=20 comm="nginx" name="index.html" scontext=system_u:system_r:httpd_t:s0 '
           'tcontext=system_u:object_r:user_home_t:s0 tclass=file', 'uid=992 exe="/usr/sbin/nginx" comm="nginx"',
       paths=['"/home/bob/www/index.html"']),
    # 11 allowed by the policy loaded now: not shown
    ev(12, '{ read } for  pid=21 comm="settled" name="admin-token" scontext=system_u:system_r:httpd_t:s0 '
           'tcontext=system_u:object_r:var_run_t:s0 tclass=file', 'exe="/usr/sbin/php-fpm" comm="settled"'),
])
put('avc', avc)

c = uw.se_do(dict(WANT, do='check'))
f = c['findings']
items = {x['id']: x for x in f['items']}
kinds = {}
for x in f['items']:
    kinds.setdefault(x['kind'], []).append(x)
check('findings read: the tool there', f['tool'], f)
nnp = [x for x in kinds.get('rule', []) if x['tgt'] == 'chronyc_t']
check('the daemon -> chronyc_t nnp_transition: a rule of upsmon\'s, grouped (2 times)',
      len(nnp) == 1 and nnp[0]['count'] == 2 and nnp[0]['fix'] == '(allow unconfined_service_t chronyc_t (process2 (nnp_transition)))', nnp)
check('… the program from its record (upsmon-bg)', nnp and nnp[0]['prog'] == 'upsmon-bg', nnp)
fifo = [x for x in kinds.get('rule', []) if x['src'] == 'chronyc_t']
check('chronyc_t -> the daemon fifo_file write: a rule (a tool of upsmon\'s)', len(fifo) == 1 and 'fifo_file (write)' in fifo[0]['fix'], fifo)
lab = kinds.get('label', [])
check('nginx -> default_t on a page: a label, the path from the hex PATH record, restorecon of its folder',
      len(lab) == 1 and lab[0]['path'] == '/var/www/upsmon/assets/core.js' and
      lab[0]['fix'] == 'restorecon -R -v /var/www/upsmon/assets' and 'httpd_sys_content_t' in lab[0]['why'], lab)
bo = kinds.get('boolean', [])
check('php-fpm -> the daemon\'s port: the boolean audit2why names', len(bo) == 1 and bo[0]['boolean'] == 'httpd_can_network_connect'
      and bo[0]['fix'] == 'setsebool -P httpd_can_network_connect 1', bo)
po = kinds.get('port', [])
check('nginx binds 8443: a port, http_port_t', len(po) == 1 and po[0]['fix'] == 'semanage port -a -t http_port_t -p tcp 8443', po)
nb = {x['tgt']: x for x in kinds.get('nobutton', [])}
check('the daemon reads shadow_t: not for a button, why', 'shadow_t' in nb and 'security-sensitive' in nb['shadow_t']['why'], list(nb))
check('the daemon executes: not for a button, why', 'shell_exec_t' in nb and 'execute' in nb['shell_exec_t']['why'], list(nb))
check('only a boolean that allows far more (httpd_execmem): not for a button', 'postgresql_port_t' in nb and
      'httpd_execmem' in nb['postgresql_port_t']['why'], nb.get('postgresql_port_t'))
other = kinds.get('other', [])
check('vim: not upsmon\'s', [x['prog'] for x in other] == ['vim'], [(x['prog'], x['path']) for x in other])
check('nginx on /home/bob: not put right, but counted (the web server is one upsmon works with)',
      'user_home_t' in nb and 'not known as upsmon' in nb['user_home_t']['why'], list(nb))
check('allowed by the policy loaded now: not shown', not any(x['prog'] == 'settled' for x in f['items']))
check('the counts: fixable 5, not for a button 4, other 1', f['fixable'] == 5 and f['nobutton'] == 4 and f['other'] == 1, f['counts'])
check('… the old count (enforcing locked) leaves out only the others\'', c['denials']['total'] == 10 and not c['ready'], c['denials']['total'])
again = uw.se_do(dict(WANT, do='check'))['findings']
check('the same refusal has the same id at every look', sorted(x['id'] for x in again['items']) == sorted(items), None)

# ---- the request: only ids --------------------------------------------------------------
for bad_ids in ([], ['../../etc'], ['(allow a b (c (d)))'], ['abc'], ['0' * 12] * 65, 'everything'):
    try:
        uw.se_do(dict(WANT, do='fix', ids=bad_ids))
        check('refused: ids %r' % (bad_ids,), False, 'taken')
    except uw.Refused:
        check('refused: ids %s' % json.dumps(bad_ids)[:40], True)
r = uw.se_do(dict(WANT, do='fix', ids=[nb['shadow_t']['id'], 'f' * 12], by='admin'))
check('a not-for-a-button id and an unknown one: said, nothing done', any('not one that is put right' in s for s in r['said'])
      and any('not refused any more' in s for s in r['said']) and not read('semodule-i') and not read('restorecon'), r['said'])

# ---- put in what is selected -------------------------------------------------------------
pick = [nnp[0]['id'], fifo[0]['id'], lab[0]['id'], bo[0]['id'], po[0]['id']]
r = uw.se_do(dict(WANT, do='fix', ids=pick, by='admin'))
said = ' | '.join(r['said'])
check('put in: the boolean, the label, the port, two rules, the local module loaded', 'boolean httpd_can_network_connect on' in said and
      '/var/www/upsmon/assets labelled again' in said and 'port 8443/tcp labelled http_port_t' in said and
      said.count('rule ') == 2 and 'upsmon_local' in said and '2 rule(s)' in said, said)
check('… setsebool -P, restorecon -R -v, semanage port -a: exactly these', read('setsebool').strip() == '-P httpd_can_network_connect 1' and
      read('restorecon').strip() == '-R -v /var/www/upsmon/assets' and read('ports-added').strip() == 'http_port_t tcp 8443',
      (read('setsebool'), read('restorecon'), read('ports-added')))
cil = read('loaded-upsmon_local.cil')
check('… upsmon_local.cil: each rule in an optional block of its own, nothing else',
      cil.count('(optional upsmon_local_') == 2 and '(allow unconfined_service_t chronyc_t (process2 (nnp_transition))))' in cil and
      '(allow chronyc_t unconfined_service_t (fifo_file (write))))' in cil and 'shadow' not in cil, cil)
lr = r['local_rules']
check('… the local rules listed, by whom', len(lr) == 2 and all(x['by'] == 'admin' for x in lr), lr)
check('… root\'s files 0600', oct(os.stat(os.path.join(W, 'rootstate', 'selinux-local.json')).st_mode & 0o777) == '0o600')
f2 = r['findings']
check('… looked at again at once: put right just now, not counted', f2['fixed'] == 5 and f2['fixable'] == 0 and
      all(x['kind'] == 'fixed' for x in f2['items'] if x['id'] in pick), f2['counts'])
check('… the old count left with what is not for a button (4)', r['denials']['total'] == 4, r['denials']['total'])
if shutil.which('secilc'):
    base = os.path.join(W, 'base.cil')
    with open(base, 'w') as fh:
        fh.write('''(class file (getattr setattr read write open))(class dir (getattr setattr search open read write))
(class process2 (nnp_transition nosuid_transition))(class fifo_file (write read))(classorder (file dir process2 fifo_file))
(sid kernel)(sidorder (kernel))(user system_u)(role system_r)(role object_r)(type kernel_t)(type init_t)(type httpd_var_run_t)
(type unconfined_service_t)(type chronyc_t)(type ssh_t)(type ifconfig_t)(category c0)(categoryorder (c0))(sensitivity s0)
(sensitivityorder (s0))(sensitivitycategory s0 (c0))(allow kernel_t self (file (read)))(roletype system_r kernel_t)
(roletype object_r httpd_var_run_t)(userrole system_u system_r)(userrole system_u object_r)(userlevel system_u (s0))
(userrange system_u ((s0)(s0 (c0))))(sidcontext kernel (system_u system_r kernel_t ((s0)(s0))))(handleunknown allow)(mls true)
''')
    loc = os.path.join(ST, 'loaded-upsmon_local.cil')
    got = subprocess.run(['secilc', '-o', os.path.join(W, 'pol'), '-f', os.path.join(W, 'fc'), base, CIL, loc],
                         capture_output=True, text=True)
    check('… upsmon_server.cil and upsmon_local.cil compile (secilc)', got.returncode == 0, got.stderr)
else:
    print('     (secilc is not here - the modules are not compiled)')

# a refusal of the same after it was put right comes back
put('avc', avc + ev(3000, '{ nnp_transition } for  pid=30 comm="upsmon-bg" scontext=system_u:system_r:unconfined_service_t:s0 '
                          'tcontext=system_u:system_r:chronyc_t:s0 tclass=process2', UPS, title=DAEMON).replace(
    'msg=audit(%d.' % (T + 3000), 'msg=audit(%d.' % (int(time.time()) + 5)))
f3 = uw.se_do(dict(WANT, do='check'))['findings']
back = [x for x in f3['items'] if x['id'] == nnp[0]['id']]
check('refused again after it was put right: it comes back', back and back[0]['kind'] == 'rule', back)
put('avc', avc)

# ---- the local rules: taken away -------------------------------------------------------
try:
    uw.se_do(dict(WANT, do='rule_drop', rule='0123456789ab'))
    check('take away a rule that is not there: refused', False)
except uw.Refused:
    check('take away a rule that is not there: refused', True)
r = uw.se_do(dict(WANT, do='rule_drop', rule=fifo[0]['id']))
check('one taken away: the module written again with one rule', len(r['local_rules']) == 1 and
      read('loaded-upsmon_local.cil').count('(optional upsmon_local_') == 1, r['said'])
check('… its refusal counts again', any(x['id'] == fifo[0]['id'] and x['kind'] == 'rule' for x in r['findings']['items']), None)
r = uw.se_do(dict(WANT, do='rule_drop', rule=nnp[0]['id']))
check('the last taken away: semodule -r upsmon_local', read('semodule-r').strip() == 'upsmon_local' and r['local_rules'] == [], r['said'])

# ---- 4.9.1: what any user of the machine may write into the audit log is never believed ------
put('fixed', '')
for n in ('selinux-fixed.json', 'selinux-local.json'):
    try:
        os.unlink(os.path.join(W, 'rootstate', n))
    except OSError:
        pass
attacks = ''.join([
    # a user's program called upsmon-x reading another service's data
    ev(500, '{ read } for  pid=50 comm="upsmon-x" name="user.MYD" scontext=staff_u:staff_r:staff_t:s0 '
            'tcontext=system_u:object_r:mysqld_db_t:s0 tclass=file', 'uid=1000 exe="/home/eve/upsmon-x" comm="upsmon-x"',
       paths=['"/var/lib/mysql/mysql/user.MYD"'], title='upsmon-x upsmon'),
    # another site's PHP through a path that names upsmon's folder
    ev(501, '{ open read } for  pid=51 comm="php-fpm" name="user.MYD" scontext=system_u:system_r:httpd_t:s0 '
            'tcontext=system_u:object_r:mysqld_db_t:s0 tclass=file', 'uid=48 exe="/usr/sbin/php-fpm" comm="php-fpm"',
       paths=['"/var/www/upsmon/../../../var/lib/mysql/mysql/user.MYD"']),
    # the web server writing upsmon's unit file: an app path, but a rule there would open every unit
    ev(502, '{ write } for  pid=52 comm="nginx" name="upsmon.service" scontext=system_u:system_r:httpd_t:s0 '
            'tcontext=system_u:object_r:systemd_unit_file_t:s0 tclass=file', 'uid=992 exe="/usr/sbin/nginx" comm="nginx"',
       paths=['"/etc/systemd/system/upsmon.service"']),
    # a port of no type of its own, for a program not listening there: never a rule on unreserved_port_t
    ev(503, '{ name_connect } for  pid=53 comm="logrotate" dest=9999 scontext=system_u:system_r:logrotate_t:s0 '
            'tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket', 'uid=0 exe="/usr/sbin/logrotate" comm="logrotate"'),
    # a USER_AVC whose command line carries fields of its own before the real ones
    '----\ntype=USER_AVC msg=audit(%d.504:604): pid=1 uid=0 auid=4294967295 msg=\'avc:  denied  { status } for auid=0 uid=0 '
    'gid=0 cmdline="upsmon scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:mysqld_db_t:s0 tclass=file" '
    'scontext=system_u:system_r:init_t:s0 tcontext=system_u:system_r:init_t:s0 tclass=system permissive=1 '
    'exe="/usr/lib/systemd/systemd"\'\n' % (T + 504),
])
# one event, two lines: one refused, one the policy allows now; and node= before every record
two = ev(505, '{ read } for  pid=55 comm="php-fpm" name="x.css" scontext=system_u:system_r:httpd_t:s0 '
              'tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file',
         'uid=991 exe="/usr/sbin/php-fpm" comm="php-fpm"', paths=['"/var/www/upsmon/assets/x.css"'])
two = two.replace('permissive=1\n', 'permissive=1\ntype=AVC msg=audit(%d.505:605): avc:  denied  { open } for  pid=55 '
                  'comm="settled" name="x.css" scontext=system_u:system_r:httpd_t:s0 '
                  'tcontext=system_u:object_r:httpd_sys_content_t:s0 tclass=file permissive=1\n' % (T + 505))
two = '\n'.join(('node=upsmon1 ' + x) if x.startswith('type=') else x for x in two.split('\n'))
put('avc', attacks + two)
fa = uw.se_do(dict(WANT, do='check'))
it = fa['findings']['items']
check('a user\'s program called upsmon-x: not upsmon\'s, never a rule', all(x['kind'] == 'other' for x in it if x['src'] == 'staff_t')
      and any(x['src'] == 'staff_t' for x in it), [(x['src'], x['kind']) for x in it])
check('another PHP through /var/www/upsmon/../..: not a rule (the path is normalised, the uid is not upsmon-www)',
      [x['kind'] for x in it if x['tgt'] == 'mysqld_db_t' and x['src'] == 'httpd_t'] == ['nobutton'], [(x['tgt'], x['kind']) for x in it])
check('the web server writing upsmon\'s unit file: never a rule', [x['kind'] for x in it if x['tgt'] == 'systemd_unit_file_t'] == ['nobutton'],
      [(x['tgt'], x['kind'], x['why']) for x in it if x['tgt'] == 'systemd_unit_file_t'])
check('a port type: never a rule on it', [x['kind'] for x in it if x['tgt'] == 'unreserved_port_t'] == ['nobutton'],
      [(x['tgt'], x['kind']) for x in it if x['tgt'] == 'unreserved_port_t'])
ua = [x for x in it if x['class'] == 'system']
check('USER_AVC: its own fields from the end (init_t), not the command line\'s; not a rule',
      len(ua) == 1 and ua[0]['src'] == 'init_t' and ua[0]['kind'] == 'nobutton' and not any(x['tgt'] == 'mysqld_db_t' and x['class'] == 'file' and x['src'] == 'httpd_t' and x['kind'] == 'rule' for x in it), ua)
css = [x for x in it if x['path'] == '/var/www/upsmon/assets/x.css']
check('one event, two lines: the refused one stays (a rule for the pages), the allowed one goes; node= read',
      len(css) == 1 and css[0]['perms'] == ['read'] and css[0]['kind'] == 'rule' and css[0]['prog'] == 'php-fpm', css)
check('nothing among them a rule but the pages reading their own file', [x['id'] for x in it if x['kind'] == 'rule'] == [css[0]['id']] if css else False,
      [(x['src'], x['tgt'], x['kind']) for x in it])
put('avc', avc)

# ---- the report: the whole machine too ---------------------------------------------------
import tarfile
uw.se_do(dict(WANT, do='report'))
names = tarfile.open(os.path.join(W, 'state', 'web', 'selinux-report.tar.gz')).getnames()
check('the report: os/ processes, booleans, ports, modules, local changes, export, listening',
      all(any(n.endswith('os/' + x) for n in names) for x in ('processes.txt', 'booleans.txt', 'ports.txt', 'modules.txt',
                                                               'local-changes.txt', 'semanage-export.txt', 'listening.txt')), names)
check('… check.json holds the findings', '"findings"' in tarfile.open(os.path.join(W, 'state', 'web', 'selinux-report.tar.gz'))
      .extractfile([n for n in names if n.endswith('check.json')][0]).read().decode())

# disabled: no fix
put('mode', 'Disabled\n')
try:
    uw.se_do(dict(WANT, do='fix', ids=[nnp[0]['id']]))
    check('disabled: fix refused', False)
except uw.Refused:
    check('disabled: fix refused', True)
print('%d ok, %d failed' % (ok, bad))
sys.exit(1 if bad else 0)
