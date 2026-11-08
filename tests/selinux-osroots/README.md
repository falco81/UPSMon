# SELinux and the system's trusted roots (4.6.0)

- `python3 tests/selinux-osroots/t_helper.py` - root's helper, fake SELinux tools on PATH and a fake folder of local additions (as root)
- `CADIR=/path node tests/selinux-osroots/t_ui.js` - the pages of a test instance; root.pem, int.pem, leaf.pem, root.cer in CADIR; the authorities are added to the system for real and taken away again
- `node tests/selinux-osroots/t_report.js` - the SELinux report from the page

See docs/selinux-and-trusted-roots.md.
