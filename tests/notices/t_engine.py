"""What is to be done by hand (4.5.0) - the engine on its own: notices.json read
and checked, the ones between two versions, a package's own read from the
.tar.gz, raised once, done, done by itself, taken back by root.
Runs against a database of its own: python3 tests/notices/t_engine.py"""
import io, json, os, sys, tarfile, tempfile
work = tempfile.mkdtemp(prefix='upsmon-nt-')
os.environ['UPSMON_STATE'] = work
os.environ['UPSMON_NOTICES'] = os.path.join(work, 'notices.d')
os.environ['UPSMON_CONFIG'] = os.path.join(work, 'config.json')
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
import upsmon_admin as ua  # noqa: E402

ok = bad = 0


def check(name, cond, got=None):
    global ok, bad
    if cond:
        ok += 1
        print('OK   ' + name)
    else:
        bad += 1
        print('FAIL %s  -> %r' % (name, got))


ua.STATE_DIR = ua.Path(work)
store = ua.Storage()
V = ua.__version__
# -- reading notices.json -----------------------------------------------------------
rows = ua.notices_parse(json.dumps({'notices': [
    {'id': 'a', 'since': V, 'when': 'before', 'confirm': True, 'level': 'danger', 'title': 'Read me',
     'commands': ['echo 1'], 'cs': {'title': 'Přečti'}},
    {'id': 'b', 'since': V, 'when': 'after', 'title': 'After'},
    {'id': 'c', 'since': '1.0.0', 'when': 'after', 'title': 'Old'},
    {'id': 'd', 'since': '999.0.0', 'when': 'after', 'title': 'Future'}]}))
check('notices.json read: 4', len(rows) == 4, rows)
for bad_one in ({'id': 'x y', 'since': V, 'title': 't'}, {'id': 'x', 'since': V},
                {'id': 'x', 'since': 'new', 'title': 't'}, {'id': 'x', 'since': V, 'title': 't', 'level': 'red'},
                {'id': 'x', 'since': V, 'title': 't', 'check': {'run': 'rm -rf /'}},
                {'id': 'x', 'since': V, 'title': 't', 'check': {'file_exists': 'relative'}}):
    try:
        ua.notices_parse(json.dumps([bad_one]))
        check('refused: %s' % bad_one, False, 'taken')
    except ValueError:
        check('refused: %s' % json.dumps(bad_one)[:60], True)
between = ua.notices_between(rows, '4.4.6', V, ('after', 'both'))
check('after, between 4.4.6 and %s: only b' % V, [n['id'] for n in between] == ['b'], between)
# -- a package's own, read from the .tar.gz ------------------------------------------
pkg = os.path.join(work, 'upsmon-9.9.9.tar.gz')
with tarfile.open(pkg, 'w:gz') as t:
    data = json.dumps({'notices': [{'id': 'p1', 'since': '9.9.9', 'when': 'before', 'confirm': True, 'title': 'P'},
                                   {'id': 'p0', 'since': V, 'when': 'before', 'title': 'Already here'}]}).encode()
    ti = tarfile.TarInfo('upsmon-9.9.9/deploy/notices.json')
    ti.size = len(data)
    t.addfile(ti, io.BytesIO(data))
got = ua.notices_of_package(pkg, '9.9.9', V)
check('the package: only the ones after what runs here', [n['id'] for n in got] == ['p1'], got)
# -- raised once, done -------------------------------------------------------------
check('raised', ua.notice_raise(store, between[0], 'package') is True)
check('raised again: nothing new', ua.notice_raise(store, between[0], 'package') is False)
ua.notice_close(store, 'b', 'done', 'tester')
check('done', ua.notices_view(store)['open'] == [] and ua.notices_view(store)['done'][0]['closed_by'] == 'tester')
check('the same one again after it was done: stays done', ua.notice_raise(store, between[0], 'package') is False)
changed = dict(between[0], text='something else now')
check('the same id saying something else: raised again', ua.notice_raise(store, changed, 'package') is True)
ua.notice_close(store, 'b', 'done', 'tester')
# -- root's, with a check -----------------------------------------------------------
nd = os.environ['UPSMON_NOTICES']
ua.NOTICES_DIR = ua.Path(nd)
os.makedirs(nd)
flag = os.path.join(work, 'flag')
with open(os.path.join(nd, 'r1.json'), 'w') as f:
    json.dump({'id': 'r1', 'level': 'warn', 'title': 'Root asks', 'check': {'file_exists': flag}}, f)
with open(os.path.join(nd, 'r2.json'), 'w') as f:
    json.dump({'id': 'r2', 'level': 'info', 'title': 'Root asks too'}, f)
ua.notices_tick(store, force=True)
check('root\'s raised', sorted(n['id'] for n in ua.notices_view(store)['open']) == ['r1', 'r2'])
check('the brief: 2, warn', ua.notices_brief(store) == {'open': 2, 'level': 'warn'}, ua.notices_brief(store))
open(flag, 'w').close()
ua.notices_tick(store, force=True)
st = {n['id']: n['state'] for n in ua.notices_view(store)['done']}
check('its check holds: done by itself', st.get('r1') == 'resolved', st)
os.unlink(os.path.join(nd, 'r2.json'))
ua.notices_tick(store, force=True)
st = {n['id']: n['state'] for n in ua.notices_view(store)['done']}
check('root took its file away: taken back', st.get('r2') == 'taken back', st)
check('nothing open', ua.notices_brief(store) == {'open': 0, 'level': ''})
# -- the version that runs now: its "after" ones, once --------------------------------
ua.NOTICES_PKG = ua.Path(os.path.join(work, 'notices.json'))
with open(str(ua.NOTICES_PKG), 'w') as f:
    json.dump([{'id': 'v1', 'since': V, 'when': 'after', 'title': 'Now'}], f)
store.set_meta('notices:version', '4.4.6')
ua.notices_tick(store, force=True)
check('upgraded from 4.4.6: its after one raised', [n['id'] for n in ua.notices_view(store)['open']] == ['v1'])
check('the version kept', store.get_meta('notices:version') == V)
store.set_meta('notices', '{}')
store.db.run("DELETE FROM meta WHERE k = 'notices:version'")
ua.notices_tick(store, force=True)
check('a first install: nothing raised', ua.notices_view(store)['open'] == [])
# -- the gate before an upgrade ------------------------------------------------------
store.set_meta('upgrade:pkg', json.dumps({'version': '9.9.9', 'notices': got}))
try:
    ua.notices_gate(store, [])
    check('the gate: refused without ack', False, 'went')
except ua.ApiError as e:
    check('the gate: refused without ack (409, notices)', e.status == 409 and e.detail == 'notices', (e.status, e.detail))
try:
    ua.notices_gate(store, ['p1'])
    check('the gate: through with ack', True)
except ua.ApiError as e:
    check('the gate: through with ack', False, str(e))
# -- Clear "Done lately" (4.5.1) --------------------------------------------------------
store.set_meta('notices', '{}')
for i in range(3):
    ua.notice_raise(store, {'id': 'k%d' % i, 'level': 'warn', 'title': 'K%d' % i}, 'daemon')
ua.notice_raise(store, {'id': 'still', 'level': 'danger', 'title': 'Still open'}, 'daemon')
for i in range(3):
    ua.notice_close(store, 'k%d' % i, 'done', 'tester')
done = ua.notices_view(store)['done']
shown = [[n['id'], int(n['closed_at'])] for n in done if n['id'] in ('k0', 'k1')]
gone = ua.notices_done_clear(store, shown, 'tester')
v = ua.notices_view(store)
check('Clear with a list: only those (2)', gone == 2 and [n['id'] for n in v['done']] == ['k2'], (gone, v['done']))
check('Clear never touches what is still to be done', [n['id'] for n in v['open']] == ['still'], v['open'])
check('… a row not in the list stays', any(n['id'] == 'k2' for n in v['done']))
check('a list naming the wrong moment: nothing', ua.notices_done_clear(store, [['k2', 1]], 'tester') == 0)
gone = ua.notices_done_clear(store, None, '')
check('Clear without a list: all of it', gone == 1 and ua.notices_view(store)['done'] == [], gone)
check('… still open: still there', [n['id'] for n in ua.notices_view(store)['open']] == ['still'])
# root's file still there after it was done and cleared: not raised again
with open(os.path.join(nd, 'r9.json'), 'w') as f:
    json.dump({'id': 'r9', 'level': 'warn', 'title': 'Root again'}, f)
ua.notices_tick(store, force=True)
ua.notice_close(store, 'r9', 'done', 'tester')
ua.notices_done_clear(store, None, 'tester')
ua.notices_tick(store, force=True)
check('done, cleared, root\'s file still there: not raised again', not any(n['id'] == 'r9' for n in ua.notices_view(store)['open']))
with open(os.path.join(nd, 'r9.json'), 'w') as f:
    json.dump({'id': 'r9', 'level': 'warn', 'title': 'Root again', 'text': 'something new'}, f)
ua.notices_tick(store, force=True)
check('… saying something else: raised again', any(n['id'] == 'r9' for n in ua.notices_view(store)['open']))
# at most 20 kept, 10 shown
store.set_meta('notices', '{}')
for i in range(25):
    ua.notice_raise(store, {'id': 'm%d' % i, 'level': 'info', 'title': 'M'}, 'daemon')
    ua.notice_close(store, 'm%d' % i, 'done', 'tester')
rows = ua._nt_all(store)
check('"Done lately": 20 kept, 10 shown', len(rows) == 20 and len(ua.notices_view(store)['done']) == 10, (len(rows), len(ua.notices_view(store)['done'])))
check('… the ones past 20 still done (not raised again)', ua.notice_raise(store, {'id': 'm0', 'level': 'info', 'title': 'M'}, 'daemon') is False)
print('%d ok, %d failed' % (ok, bad))
sys.exit(1 if bad else 0)
