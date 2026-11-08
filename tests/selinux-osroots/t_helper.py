"""SELinux and the system's trusted roots (4.6.0) - root's helper on its own, with fake
getenforce / semodule / getsebool / setsebool / semanage / ausearch / audit2why / setenforce
on PATH and a fake folder of local additions with a fake update tool. Run as root:
python3 tests/selinux-osroots/t_helper.py"""
import importlib.util, json, os, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..', '..')
W = tempfile.mkdtemp(prefix='upsmon-seos-')
ok = bad = 0


def check(name, cond, got=None):
    global ok, bad
    if cond:
        ok += 1
        print('OK   ' + name)
    else:
        bad += 1
        print('FAIL %s  -> %r' % (name, got))


# ---- the fake system ----------------------------------------------------------------------
BIN = os.path.join(W, 'bin')
os.makedirs(BIN)
os.makedirs(os.path.join(W, 'state', 'web'))
ST = os.path.join(W, 'se')            # the fake machine's SELinux state, one file each
os.makedirs(ST)


def fake(name, body):
    p = os.path.join(BIN, name)
    with open(p, 'w') as f:
        f.write('#!/bin/bash\nS=%s\n%s\n' % (ST, body))
    os.chmod(p, 0o755)


def put(name, text):
    with open(os.path.join(ST, name), 'w') as f:
        f.write(text)


fake('getenforce', 'cat $S/mode')
fake('semodule', '''case "$1" in -l) cat $S/modules 2>/dev/null;; -i) echo upsmon_server >> $S/modules; echo "$2" >> $S/semodule-i;; -r) : > $S/modules;; esac''')
fake('getsebool', 'if grep -qx "$1" $S/bools-on 2>/dev/null; then echo "$1 --> on"; else echo "$1 --> off"; fi')
fake('setsebool', 'echo "$2" >> $S/bools-on')
fake('semanage', 'cat $S/ports 2>/dev/null')
fake('ausearch', 'cat $S/avc 2>/dev/null')
fake('audit2why', 'cat >/dev/null')
fake('setenforce', 'if [ "$1" = 1 ]; then echo Enforcing > $S/mode; else echo Permissive > $S/mode; fi')
fake('restorecon', 'exit 0')
os.environ['PATH'] = BIN + ':' + os.environ['PATH']
CONF = os.path.join(W, 'selinux-config')
with open(CONF, 'w') as f:
    f.write('# the config\nSELINUX=disabled\nSELINUXTYPE=targeted\n')
CIL = os.path.join(W, 'upsmon_server.cil')
with open(CIL, 'w') as f:
    f.write(open(os.path.join(ROOT, 'deploy', 'upsmon_server.cil')).read())
LABELS = os.path.join(W, 'labels.json')
with open(LABELS, 'w') as f:
    json.dump({'/run/upsmon': 'var_run_t'}, f)
os.environ.update(UPSMON_STATE=os.path.join(W, 'state'), UPSMON_ROOT_STATE=os.path.join(W, 'rootstate'),
                  UPSMON_SELINUX_CONFIG=CONF, UPSMON_SELINUX_RELABEL=os.path.join(W, 'autorelabel'),
                  UPSMON_SELINUX_CMDLINE=os.path.join(W, 'cmdline'), UPSMON_SELINUX_CIL=CIL,
                  UPSMON_SELINUX_AUDITD='active', UPSMON_SELINUX_LABELS=LABELS)
with open(os.path.join(W, 'cmdline'), 'w') as f:
    f.write('BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet\n')
spec = importlib.util.spec_from_file_location('uw', os.path.join(ROOT, 'deploy', 'upsmon_web.py'))
uw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uw)
uw.SE_LABELS = (('/run/upsmon', 'httpd_var_run_t', 'the folder of the daemon\'s token and port'),)
os.makedirs('/run/upsmon', exist_ok=True)
WANT = {'booleans': [{'name': 'httpd_can_network_connect', 'why': 'the pages ask the daemon'}], 'ports': []}

# ---- SELinux --------------------------------------------------------------------------------
put('mode', 'Disabled\n')
c = uw.se_do(dict(WANT, do='check'))
check('disabled: said so, nothing asked of it', c['mode'] == 'Disabled' and not c['problems'] and not c['ready'], c)
for bad_one in ({'booleans': [{'name': 'httpd_execmem'}]}, {'ports': [{'port': 22, 'proto': 'tcp', 'type': 'shadow_t'}]},
                {'ports': [{'port': 99999, 'proto': 'tcp', 'type': 'http_port_t'}]}):
    try:
        uw.se_do(dict(bad_one, do='check'))
        check('refused: %s' % bad_one, False, 'taken')
    except uw.Refused:
        check('refused: %s' % json.dumps(bad_one)[:70], True)
c = uw.se_do(dict(WANT, ports=[{'port': 5000, 'proto': 'tcp', 'type': 'future_port_t', 'why': 'x'}], do='check'))
check('a port type it does not know: left out with a word, the rest goes on', c['left_out'] and 'future_port_t' in c['left_out'][0], c['left_out'])
try:
    uw.se_do(dict(WANT, do='enforce'))
    check('disabled: enforce refused', False, 'went')
except uw.Refused as e:
    check('disabled: enforce refused (%s)' % str(e)[:50], True)
c = uw.se_do(dict(WANT, do='prepare'))
check('prepare from disabled: SELINUX=permissive, the rest of the file kept',
      'SELINUX=permissive' in open(CONF).read() and 'SELINUXTYPE=targeted' in open(CONF).read() and '# the config' in open(CONF).read())
check('… every file labelled at the next start', os.path.exists(os.environ['UPSMON_SELINUX_RELABEL']))
check('… the mode not changed now (no restart)', open(os.path.join(ST, 'mode')).read().strip() == 'Disabled')
check('… said: restart the machine', any('restart the machine' in x for x in c['said']), c['said'])
check('… shown: after the restart permissive, relabel pending', c['config'] == 'permissive' and c['relabel_pending'], c)
# the restart: permissive, labels relabelled, the module not in yet
put('mode', 'Permissive\n')
put('modules', '')
os.unlink(os.environ['UPSMON_SELINUX_RELABEL'])
now = int(time.time())
put('avc', 'type=AVC msg=audit(%d.100:51): avc:  denied  { read } for  pid=9 comm="php-fpm" name="admin-token" '
    'scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_run_t:s0 tclass=file permissive=1\n'
    'type=AVC msg=audit(%d.200:52): avc:  denied  { read } for  pid=9 comm="vim" '
    'scontext=unconfined_u:unconfined_r:unconfined_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=1\n'
    % (now - 100, now - 100))
c = uw.se_do(dict(WANT, do='check'))
probs = ' | '.join(c['problems'])
check('permissive: the module missing', 'module' in probs, probs)
check('… the label of /run/upsmon wrong', '/run/upsmon is labelled var_run_t' in probs, probs)
check('… the boolean off', 'httpd_can_network_connect is off' in probs, probs)
check('… refused 1 (httpd_t), not the program upsmon has nothing to do with', c['denials']['total'] == 1, c['denials'])
check('… not ready', not c['ready'])
try:
    uw.se_do(dict(WANT, do='enforce'))
    check('enforce while something is missing: refused', False, 'went')
except uw.Refused as e:
    check('enforce while something is missing: refused', 'not yet' in str(e), str(e))
check('… and still permissive', open(os.path.join(ST, 'mode')).read().strip() == 'Permissive')
# put in what upsmon needs
time.sleep(1.1)
with open(LABELS, 'w') as f:
    json.dump({'/run/upsmon': 'httpd_var_run_t'}, f)
c = uw.se_do(dict(WANT, do='prepare'))
check('put in after the refused enforce (which put the module and the boolean in already): in place',
      'upsmon_server' in open(os.path.join(ST, 'modules')).read() and
      'httpd_can_network_connect' in open(os.path.join(ST, 'bools-on')).read(), c['said'])
check('… the module put in only once copied as in the policy', os.path.exists(CIL + '.in-policy'))
check('… what was refused before no longer counts (since put in)', c['denials']['total'] == 0 and c['denials']['since'] > 0, c['denials'])
check('… ready for enforcing', c['ready'], c['problems'])
check('… "applied at" in root\'s folder, 0600', oct(os.stat(os.path.join(W, 'rootstate', 'selinux-applied')).st_mode & 0o777) == '0o600')
c2 = uw.se_do(dict(WANT, do='prepare'))
check('put in again, nothing to change: not counted again', c2['said'] == [], c2['said'])
put('avc', open(os.path.join(ST, 'avc')).read() + 'type=AVC msg=audit(%d.300:53): avc:  denied  { write } for  pid=9 '
    'comm="nginx" name="x" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=dir permissive=1\n'
    % (int(time.time()) + 5))
c = uw.se_do(dict(WANT, do='check'))
check('a new refusal after: counted, not ready', c['denials']['total'] == 1 and not c['ready'], c['denials'])
put('avc', '')
os.environ['UPSMON_SELINUX_AUDITD'] = 'inactive'
c = uw.se_do(dict(WANT, do='check'))
check('auditd not running: a problem (no evidence, no enforcing)', any('auditd' in p for p in c['problems']), c['problems'])
os.environ['UPSMON_SELINUX_AUDITD'] = 'active'
c = uw.se_do(dict(WANT, do='enforce'))
check('enforce: enforcing now and after a restart', open(os.path.join(ST, 'mode')).read().strip() == 'Enforcing' and
      'SELINUX=enforcing' in open(CONF).read(), c['said'])
try:
    uw.se_do(dict(WANT, do='prepare'))
    check('prepare while enforcing: refused', False)
except uw.Refused:
    check('prepare while enforcing: refused', True)
c = uw.se_do(dict(WANT, do='permissive'))
check('back to permissive: now and after a restart', open(os.path.join(ST, 'mode')).read().strip() == 'Permissive' and
      'SELINUX=permissive' in open(CONF).read())
r = uw.se_do(dict(WANT, do='report'))
import tarfile
names = tarfile.open(os.path.join(W, 'state', 'web', 'selinux-report.tar.gz')).getnames()
check('the report: a tar.gz with check.json, avc, labels, README', r['bytes'] > 0 and
      all(any(n.endswith(x) for n in names) for x in ('check.json', 'avc.txt', 'labels.txt', 'README.txt')), names)
tf = tarfile.open(os.path.join(W, 'state', 'web', 'selinux-report.tar.gz'))
proc = tf.extractfile([m for m in tf.getmembers() if m.name.endswith('processes.txt')][0]).read().decode()
check('… processes.txt holds the domains (4.6.1: ps -eZo was refused, the file was empty)',
      proc.startswith('LABEL') and len(proc.splitlines()) > 1, proc[:120])
# selinux.ask through the folder, as the daemon asks it
with open(os.path.join(W, 'state', 'web', 'selinux.ask'), 'w') as f:
    json.dump(dict(WANT, do='check', id='abc123'), f)
uw.selinux_part()
ans = json.load(open(os.path.join(W, 'state', 'web', 'selinux.json')))
check('selinux.ask: answered with its id, the ask taken away', ans['id'] == 'abc123' and ans['ok'] and
      not os.path.exists(os.path.join(W, 'state', 'web', 'selinux.ask')), ans.get('said'))
os.unlink(os.path.join(BIN, 'getenforce'))
c = uw.se_do(dict(WANT, do='check'))
check('no getenforce (Debian): absent, nothing to do', c['mode'] == 'absent' and not c['problems'], c)

# ---- the system's trusted roots ----------------------------------------------------------------
CA = os.path.join(W, 'ca')
os.makedirs(CA)


def ossl(*a):
    subprocess.run(['openssl'] + list(a), check=True, capture_output=True)


ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', CA + '/root.key', '-out', CA + '/root.pem',
     '-days', '3650', '-subj', '/CN=Test Root CA', '-addext', 'basicConstraints=critical,CA:TRUE',
     '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', CA + '/int.key', '-out', CA + '/int.csr', '-subj', '/CN=Test Issuing CA')
with open(CA + '/int.ext', 'w') as f:
    f.write('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
ossl('x509', '-req', '-in', CA + '/int.csr', '-CA', CA + '/root.pem', '-CAkey', CA + '/root.key', '-CAcreateserial',
     '-out', CA + '/int.pem', '-days', '1825', '-extfile', CA + '/int.ext')
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', CA + '/leaf.key', '-out', CA + '/leaf.pem',
     '-days', '30', '-subj', '/CN=www.example.test', '-addext', 'basicConstraints=CA:FALSE')
root, inter, leaf = (open(CA + '/%s.pem' % n).read() for n in ('root', 'int', 'leaf'))
ANCH = os.path.join(W, 'anchors')
BUNDLE = os.path.join(W, 'bundle.pem')
with open(BUNDLE, 'w') as f:
    f.write(root.replace('Test', 'X') if False else '')
fake('fake-update-ca', 'cat %s/system.pem %s/*.pem > %s 2>/dev/null; exit 0' % (W, ANCH, BUNDLE))
with open(os.path.join(W, 'system.pem'), 'w') as f:
    f.write(open(CA + '/leaf.pem').read() * 0 + '')
os.environ.update(UPSMON_OSROOTS_FLAVOUR='rhel', UPSMON_OSROOTS_DIR=ANCH, UPSMON_OSROOTS_BUNDLE=BUNDLE,
                  UPSMON_OSROOTS_EXTRACT='fake-update-ca', UPSMON_OSROOTS_PKG='echo ca-certificates-2026.1')
c = uw.osroots_do({'do': 'check', 'text': root + inter + leaf})['certs']
check('check: three read', len(c) == 3, [x['cn'] for x in c])
check('… the root a root, the intermediate an intermediate', c[0]['kind'] == 'root' and c[1]['kind'] == 'intermediate')
check('… a server\'s own certificate refused (CA:FALSE)', c[2]['refused'] and 'CA:FALSE' in c[2]['refused'][0], c[2]['refused'])
for txt, words in ((root + open(CA + '/root.key').read(), 'a private key'), ('hello', 'no certificate')):
    try:
        uw.osroots_do({'do': 'check', 'text': txt})
        check('refused: %s' % words, False)
    except uw.Refused:
        check('refused whole: %s' % words, True)
os.makedirs(ANCH, mode=0o755)
with open(os.path.join(ANCH, 'company-old.pem'), 'w') as f:
    f.write(root)
os.symlink('/etc/passwd', os.path.join(ANCH, 'pointing-away.pem'))
r = uw.osroots_do({'do': 'sync', 'certs': [root, inter, leaf]})
fp_root = uw.osroots_facts(*uw.osroots_blocks(root)[0])['fp']
names = sorted(os.listdir(ANCH))
check('sync: upsmon-<sha16>.pem written for the two authorities', 'upsmon-%s.pem' % fp_root[:16] in names and
      sum(1 for n in names if n.startswith('upsmon-')) == 2, names)
check('… the server\'s own certificate refused, said back', len(r['refused']) == 1 and 'CA:FALSE' in r['refused'][0]['why'], r['refused'])
check('… the tool run', any('fake-update-ca run' in x for x in r['said']), r['said'])
check('… in the system\'s list now', all(x.get('in_bundle') for x in r['ours']), [x.get('in_bundle') for x in r['ours']])
check('… somebody else\'s file untouched, shown; the link shown as a link, not followed',
      os.path.exists(os.path.join(ANCH, 'company-old.pem')) and os.path.islink(os.path.join(ANCH, 'pointing-away.pem')) and
      any(o['file'] == 'pointing-away.pem' and o.get('link') for o in r['others']), r['others'])
check('… the package said', r['system'].get('package') == 'ca-certificates-2026.1', r['system'])
check('… root\'s, 0644', oct(os.stat(os.path.join(ANCH, 'upsmon-%s.pem' % fp_root[:16])).st_mode & 0o777) == '0o644')
r = uw.osroots_do({'do': 'sync', 'certs': [root, inter]})
check('the same again: nothing changed, the tool not run', r['said'] == [], r['said'])
with open(os.path.join(ANCH, 'upsmon-%s.pem' % fp_root[:16]), 'w') as f:
    f.write(inter)
r = uw.osroots_do({'do': 'sync', 'certs': [root, inter]})
check('one of upsmon\'s changed by somebody: put back as wanted', any('added' in x for x in r['said']) and
      open(os.path.join(ANCH, 'upsmon-%s.pem' % fp_root[:16])).read().strip() == uw.osroots_blocks(root)[0][0].strip(), r['said'])
r = uw.osroots_do({'do': 'sync', 'certs': [inter]})
check('taken away: its file removed, the tool run', 'removed upsmon-%s.pem' % fp_root[:16] in r['said'] and
      any('run' in x for x in r['said']), r['said'])
check('… somebody else\'s still there', os.path.exists(os.path.join(ANCH, 'company-old.pem')))
os.chmod(ANCH, 0o777)
try:
    uw.osroots_do({'do': 'sync', 'certs': [root]})
    check('a folder anybody may write: refused', False)
except uw.Refused as e:
    check('a folder anybody may write: refused', 'root\'s alone' in str(e), str(e))
os.chmod(ANCH, 0o755)
r = uw.osroots_do({'do': 'sync', 'certs': []})
check('none wanted: upsmon\'s files gone, the others kept', not any(n.startswith('upsmon-') for n in os.listdir(ANCH))
      and 'company-old.pem' in os.listdir(ANCH), os.listdir(ANCH))
print('%d ok, %d failed' % (ok, bad))
sys.exit(1 if bad else 0)
