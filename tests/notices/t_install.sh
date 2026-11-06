#!/usr/bin/env bash
# What is to be done by hand (4.5.0): install.sh's helpers on their own -
# upsmon_notice writes a file the daemon reads, upsmon_notice_clear takes it
# away, notices_show prints a version's notices between two versions and says
# 1 when one is to be read first. bash tests/notices/t_install.sh
set -u
here=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
ok=0; bad=0
check() { if eval "$2"; then ok=$((ok+1)); echo "OK   $1"; else bad=$((bad+1)); echo "FAIL $1"; fi; }
# the helpers out of install.sh, with what they need around them
{
    echo 'C_BAD=""; C_WARN=""; C_HEAD=""; C_DIM=""; C_OFF=""; DRY_RUN=""'
    echo 'warn() { printf "    %s\n" "$1"; }; note() { printf "    %s\n" "$1"; }'
    sed -n '/^readonly NOTICES_DIR=/,/^usage() {/p' "$here/install.sh" | sed '$d' \
        | sed "s|^readonly NOTICES_DIR=.*|NOTICES_DIR=$work/notices.d|"
} > "$work/helpers.sh"
# shellcheck disable=SC1091
. "$work/helpers.sh"
upsmon_notice t-one warn "The firewall is left to you" "Open 443." "firewall-cmd --add-service=https" \
    --check unit_active=firewalld >/dev/null
check 'upsmon_notice: a file' '[[ -f $work/notices.d/t-one.json ]]'
check '… that reads, with its command and check' "python3 -c \"import json;d=json.load(open('$work/notices.d/t-one.json'));assert d['commands']==['firewall-cmd --add-service=https'] and d['check']=={'unit_active':'firewalld'} and d['level']=='warn'\""
check '… that the daemon takes' "python3 -c \"
import sys,os;os.environ['UPSMON_STATE']='$work';sys.path.insert(0,'$here');import upsmon_admin as ua
ua.notices_parse(open('$work/notices.d/t-one.json').read(),'root')\" 2>/dev/null"
upsmon_notice 'bad id' warn "x" "y" >/dev/null 2>&1
check 'a bad id: no file' '[[ ! -e "$work/notices.d/bad id.json" ]]'
upsmon_notice_clear t-one
check 'upsmon_notice_clear: gone' '[[ ! -e $work/notices.d/t-one.json ]]'
cat > "$work/n.json" <<'EOF'
{"notices": [
 {"id": "b1", "since": "4.6.0", "when": "before", "confirm": true, "level": "danger", "title": "Back up first", "commands": ["upsmon --backup"]},
 {"id": "a1", "since": "4.6.0", "when": "after", "level": "warn", "title": "Run this after"},
 {"id": "o1", "since": "4.4.0", "when": "before", "confirm": true, "title": "Old one"}]}
EOF
out=$(notices_show "$work/n.json" 4.5.0 4.6.0 before); rc=$?
check 'before: shown, said to be read first (1)' '[[ $rc == 1 && $out == *"Back up first"* && $out == *"upsmon --backup"* ]]'
check '… not the old one, not the after one' '[[ $out != *"Old one"* && $out != *"Run this after"* ]]'
out=$(notices_show "$work/n.json" 4.5.0 4.6.0 after); rc=$?
check 'after: shown, nothing to confirm (0)' '[[ $rc == 0 && $out == *"Run this after"* && $out == *"TO BE DONE BY HAND"* ]]'
out=$(notices_show "$work/n.json" 4.6.0 4.6.0 before); rc=$?
check 'the same version: nothing' '[[ $rc == 0 && -z $out ]]'
out=$(notices_show "$work/missing.json" 4.5.0 4.6.0 before); rc=$?
check 'no notices.json: nothing, 0' '[[ $rc == 0 && -z $out ]]'
check 'install.sh reads' 'bash -n "$here/install.sh"'
echo "$ok ok, $bad failed"
[[ $bad == 0 ]]
