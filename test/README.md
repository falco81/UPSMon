# Tests

Nothing here ships to the server. These are the checks used while developing.

## phpcheck.py

Structural validation of the PHP without an interpreter, plus a check that no
JavaScript function is defined and then never referenced. That last one exists
because the plug and sensor chart loaders were once orphaned by an edit: the
code stayed perfectly valid, the charts simply never loaded, and nothing said
so. It covers: balanced brackets
through a lexer that understands strings, comments and heredocs, calls to
functions that exist nowhere, and syntax newer than PHP 8.0 which AlmaLinux 9
would reject.

```bash
python3 test/phpcheck.py web/index.php web/upsmon-api.php
```

## smoke.js

Extracts the page's script, gives it a DOM stub, and calls every render
function with realistic data.

This exists because of a real bug: a rename left `renderWritable` referring to
a variable that no longer existed, and the Settings table silently disappeared
from the page. Syntax checks pass on that happily — a ReferenceError only fires
when the code path runs, and each of these functions runs only when its own tab
is opened.

```bash
python3 -c "
src = open('web/index.php').read()
js = src.split('<script>\n', 1)[1].rsplit('</script>', 1)[0]
js = js.replace('<?= json_encode(\$snapshot ?: null, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) ?>', 'null')
open('/tmp/dash.js', 'w').write(js)"
node --check /tmp/dash.js
node test/smoke.js
```

Every line should read `ok`.

## dragtest.js

Drives a chart through a full drag — pointerdown, a stream of moves, pointerup —
and counts how often it is actually redrawn while the button is held.

This exists because panning used to update the view on every move but only
redraw on release, so nothing appeared to happen until the mouse was let go.
The fix follows the pointer on `window` rather than on the `<svg>`, because
redrawing replaces that element and would otherwise tear the gesture apart
mid-drag. The test also covers wheel zoom, double-click reset and pinch.

```bash
node test/dragtest.js
```

Expect roughly one redraw per move, the listeners cleaned up afterwards, and a
right-click that starts nothing.

## mdnstest.py

Feeds `shelly_discover` a real mDNS reply and checks the device is understood,
including that the address reported is the one the device published for itself
rather than the relay's. Both reply paths are covered: to the multicast group on
port 5353, and by unicast to the port the query went out from, which is what a
proxy across a VLAN sends and what `avahi-daemon` would otherwise intercept.

Two answers that are not devices are covered too, because both appeared in real
output: the service type `_shelly._tcp.local`, which is what enumerating
`_services._dns-sd._udp.local` returns, and one device answering with two
spellings of its own name across different record types.

```bash
python3 test/mdnstest.py path/to/upsmon.py
```

Multicast itself cannot be exercised everywhere, so this covers the parsing and
the receive path rather than the network.
