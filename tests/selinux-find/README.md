# What SELinux refuses, sorted by what puts it right (4.9.0)

- `python3 tests/selinux-find/t_find.py` - root's helper on its own: stand-in SELinux tools on
  PATH, fixtures of raw `ausearch` output (hex names and proctitles, the records of each event);
  the kinds, the fixes, the local module (compiled with `secilc` when it is there), taking rules
  away, the report. As root.
- `node tests/selinux-find/t_ui.js` - Settings -> SELinux on a test instance whose root helper
  runs with the same stand-ins on its PATH (the `fake()` tools and the fixture of t_find.py, and
  the UPSMON_SELINUX_* variables it sets); `LANG_UI=cs` for Czech, `SHOT=prefix` for screenshots.

See docs/selinux-and-trusted-roots.md.
