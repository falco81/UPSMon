import os, sys, tempfile, importlib.util
spec = importlib.util.spec_from_file_location('ua', '/home/user/UPSMon/upsmon_admin.py')
ua = importlib.util.module_from_spec(spec); spec.loader.exec_module(ua)
def w(p, t):
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'w').write(t)
def fake(cids, cores):
    r = tempfile.mkdtemp()
    os.makedirs(r + '/devices/platform/coretemp.0')
    w(r + '/class/hwmon/hwmon1/name', 'coretemp\n')
    os.symlink(r + '/devices/platform/coretemp.0', r + '/class/hwmon/hwmon1/device')
    for i, c in enumerate(cores):
        w(r + '/class/hwmon/hwmon1/temp%d_label' % (i + 2), 'Core %d\n' % c)
        w(r + '/class/hwmon/hwmon1/temp%d_input' % (i + 2), '%d\n' % (40000 + 4000 * i))
    for n, c in enumerate(cids):
        w(r + '/devices/system/cpu/cpu%d/topology/core_id' % n, '%d\n' % c)
        w(r + '/devices/system/cpu/cpu%d/topology/physical_package_id' % n, '0\n')
    return r
bad = 0
for cids, cores in (([0, 1, 0, 1], [0, 1]), ([0, 4, 0, 4], [0, 4])):
    ua.LOAD_SYS = fake(cids, cores)
    ua.LOAD_DETAIL.update({'at': 0.0, 'raw': None, 'out': None})
    raw = ua._load_detail_raw()
    raw['cores'] = {n: (100, 200) for n in range(4)}
    ua._load_detail_raw = lambda raw=raw: dict(raw, at=raw['at'] + 1)
    d = ua.load_detail()
    t = [c['temp'] for c in d['cpu']['cores']] if 'cpu' in d and isinstance(d['cpu'], dict) else [c['temp'] for c in d.get('cores', [])]
    print(cids, cores, '->', t); bad += None in t or len(t) != 4
fs = [f['kind'] for f in d.get('fs', d.get('filesystems', []))]
print('filesystems asked:', fs); bad += any(k not in ua.LOAD_FS_KINDS for k in fs)
print('FAILED' if bad else 'all ok')
