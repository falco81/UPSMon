#!/bin/bash
#
# install.sh - set up upsmon on AlmaLinux 9, from packages to a working
# dashboard with its Settings behind a sign-in. Everything the manual
# walkthrough in INSTALL.md does, in order, and safe to run again: an existing
# configuration is kept, certificates are not overwritten, and the databases
# are never touched.
#
#   sudo ./install.sh                       ask for what it needs
#   sudo ./install.sh --nut-host 10.0.0.5 --yes
#   sudo ./install.sh --upgrade             a new version over an installed one -
#                                           also the standalone 3.x, brought over
#                                           to 4.x whole (history, config, certificate)
#   sudo ./install.sh --uninstall           remove it, keeping the history
#
# Settings → Upgrades runs exactly this (--upgrade --yes) as root, through
# upsmon-upgrade.service, once a signed package has been checked.
#
# Run --help for everything it accepts.

set -o errexit
set -o nounset
set -o pipefail

readonly INSTALLER_VERSION='4.1.3'
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly LIB_DIR=/usr/local/lib/upsmon
readonly BIN=/usr/local/bin/upsmon
readonly CONFIG_DIR=/etc/upsmon
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly WEB_DIR=/var/www/upsmon
readonly CERT_DIR=/etc/nginx/certs
readonly UNIT=/etc/systemd/system/upsmon.service
readonly SERVICE_USER=upsmon
readonly WEB_USER=upsmon-www
readonly STATE_DIR=/var/lib/upsmon
readonly NGINX_CONF=/etc/nginx/conf.d/upsmon.conf
readonly POOL=/etc/php-fpm.d/upsmon.conf
readonly CONSOLE_FLAG=/etc/upsmon-console-login
readonly CONSOLE_PROFILE=/etc/profile.d/zz-upsmon-console.sh

# --- what we were asked to do ----------------------------------------------
NUT_HOST=''
NUT_PORT=3493
UPS_NAME=ups
NUT_USER=''
NUT_PASSWORD=''
PIN=''
PLUG_HOST=''
PLUG_PASSWORD=''
PLUG_SWITCH_ID=0
SENSOR_HOST=''
SENSOR_PASSWORD=''
SENSOR_LISTEN=''
SENSOR_PORT=8088
API_HOST=127.0.0.1
API_PORT=9848
POLL_INTERVAL=10
SAMPLE_INTERVAL=60
SAMPLE_INTERVAL_BATTERY=10
FLAG_CONFIRM_POLLS=2
RETAIN_FULL_DAYS=14
RETAIN_HOURLY_DAYS=730
CHARGE_WARN=50
CHARGE_CRIT=25
LOAD_WARN=70
LOAD_CRIT=90
RUNTIME_WARN_S=300
RUNTIME_CRIT_S=120
BATTERY_LIFE_YEARS=4.0
ALLOW_DANGEROUS=false
LOG_FILE=/var/log/upsmon/upsmon.log
LOG_LEVEL=info
LOG_TO_JOURNAL=true
SENSOR_LISTEN_HOST=0.0.0.0
ADVANCED=''
SERVER_NAME=''
CERT_FILE=''
KEY_FILE=''
CA_FILE=''
SELF_SIGNED=''
WITH_WEB=yes
ASSUME_YES=''
DRY_RUN=''
MODE=install
ALLOW_NETS=''
ADMIN_USER=admin
ADMIN_PASSWORD=''
REWRITE_NGINX=''
FIRST_PASSWORD=''
NEW_VERSION=''
PY_FORCE=''
PY_SYSTEM=''
UPSMON_PY=''
PHP_UPDATE=yes
PHP_STREAM=8.3
USE_REMI=''
PHP_RELOAD=''
DO_UPGRADE=''
PKG=''
command -v dnf >/dev/null 2>&1 && PKG=dnf
[[ -z "$PKG" ]] && command -v apt-get >/dev/null 2>&1 && PKG=apt
OS_MAJOR=$( (. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_ID%%.*}") || echo 9)

# --- talking to the person -------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_BAD=$'\e[31m'
    C_DIM=$'\e[90m'; C_HEAD=$'\e[1;36m'; C_OFF=$'\e[0m'
else
    C_OK=''; C_WARN=''; C_BAD=''; C_DIM=''; C_HEAD=''; C_OFF=''
fi

step()  { printf '\n%s==> %s%s\n' "$C_HEAD" "$1" "$C_OFF"; }
say()   { printf '    %s\n' "$1"; }
note()  { printf '    %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
good()  { printf '    %s%s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn()  { printf '    %s%s%s\n' "$C_WARN" "$1" "$C_OFF"; }
fail()  { printf '\n%sERROR: %s%s\n' "$C_BAD" "$1" "$C_OFF" >&2; exit 1; }

run() {
    if [[ -n "$DRY_RUN" ]]; then
        printf '    %s[would run]%s %s\n' "$C_DIM" "$C_OFF" "$*"
        return 0
    fi
    "$@"
}

# Which settings were given on the command line. A variable holding its
# default is not the same as one the person chose, and asking about the first
# while skipping the second is the whole point of an interactive installer.
declare -A GIVEN=()

ask() {
    # ask <variable> <prompt> [default]
    local __var=$1 prompt=$2 default=${3:-} reply
    if [[ -n "${GIVEN[$__var]:-}" ]]; then return 0; fi
    if [[ -n "$ASSUME_YES" ]]; then
        printf -v "$__var" '%s' "$default"
        return 0
    fi
    if [[ -n "$default" ]]; then
        read -r -p "    $prompt [$default]: " reply || true
        reply=${reply:-$default}
    else
        read -r -p "    $prompt: " reply || true
    fi
    printf -v "$__var" '%s' "$reply"
}

ask_secret() {
    local __var=$1 prompt=$2 reply
    if [[ -n "${GIVEN[$__var]:-}" ]] || [[ -n "$ASSUME_YES" ]]; then return 0; fi
    read -r -s -p "    $prompt (leave empty for none): " reply || true
    echo
    printf -v "$__var" '%s' "$reply"
}

confirm() {
    local prompt=$1 reply
    if [[ -n "$ASSUME_YES" ]]; then return 0; fi
    read -r -p "    $prompt [y/N]: " reply || true
    [[ ${reply,,} == y* ]]
}

usage() {
    cat <<'EOF'
install.sh - set up upsmon on AlmaLinux 9

  sudo ./install.sh                     ask for what it needs
  sudo ./install.sh --nut-host 10.0.0.5 --self-signed --yes
  sudo ./install.sh --upgrade           replace the program files and restart
  sudo ./install.sh --uninstall         remove it, keeping the recorded history

the UPS
  --nut-host ADDR       the NAS or other host running NUT (required)
  --nut-port PORT       default 3493
  --ups-name NAME       default "ups", which is what Synology always uses
  --nut-user USER       an account on that host, needed only to change settings
  --nut-password PASS   its password

the dashboard
  --pin DIGITS          four digits, asked for before any control action
  --server-name NAME    the hostname the dashboard answers on
  --cert FILE           TLS certificate, and --key FILE for its private key
  --ca FILE             the issuer chain, if it is in a separate file
  --self-signed         make a certificate instead, for a machine with no name
  --no-web              install the daemon only, no nginx and no dashboard
  --allow CIDR[,CIDR]   who may reach the dashboard and Settings (default RFC 1918)
  --admin-user NAME     the first account of Settings (admin)
  --admin-password PASS its password (otherwise one is made and printed)
  --rewrite-nginx       write the nginx file afresh (otherwise one of 4.x is kept)

Python, as OTP: upsmon runs on the newest Python the system offers beside its
own (3.14, 3.13, 3.12, 3.11 - installed from AppStream when missing):
  --python PATH         run upsmon on this Python instead (kept for later upgrades)
  --system-python       run upsmon on the system's own python3 (kept too)

PHP (php2shell, CVE-2026-109618 / CVE-2026-109619 - fixed 21 October 2026), as OTP:
  --php-stream X.Y      the AppStream stream PHP is put on, install and upgrade (default 8.3)
  --remi                PHP 8.4 from Remi's repository instead
  --no-php-update       leave PHP exactly as it is (it is still checked and guarded)

a smart plug and sensors, both optional
  --plug-host ADDR      a Shelly plug to watch alongside the UPS
  --plug-password PASS  if one is set in its web interface
  --plug-switch-id N    which relay; single-socket plugs are always 0
  --sensor-host ADDR    a sensor to read directly, when it is not on battery
  --sensor-password PASS
  --sensor-listen       receive webhook pushes from a sleeping sensor
  --sensor-port PORT    which port to listen on, default 8088
  --sensor-listen-host ADDR   which address to listen on, default every one

thresholds and timing, all with sensible defaults
  --advanced            ask about all of these rather than taking the defaults
  --charge-warn N       battery percentage that turns the dashboard amber (50)
  --charge-crit N       and red (25)
  --load-warn N         load percentage that turns it amber (70)
  --load-crit N         and red (90)
  --runtime-warn N      seconds of runtime left that turns it amber (300)
  --runtime-crit N      and red (120)
  --battery-life YEARS  how long this battery should last, for its age (4.0)
  --poll-interval N     seconds between readings of the UPS (10)
  --sample-interval N   seconds between rows written to the database (60)
  --retain-full N       days of full-resolution history (14)
  --retain-hourly N     days of hourly averages (730)
  --flag-confirm N      polls a status flag must persist to count as real (2)
  --allow-dangerous     enable the commands that cut power to the load
  --api-host ADDR       where the daemon's local API listens (127.0.0.1)
  --api-port PORT       and on which port (9848)
  --log-level LEVEL     info or debug
  --no-journal          write only to the log file, not to the journal

how it runs
  --yes                 take the defaults for anything not given, ask nothing
  --dry-run             print what it would do and change nothing
  --source DIR          where the project files are, if not beside this script
  --upgrade             program files and a restart, nothing else
  --uninstall           remove the service, the web files and the unit
  --help                this
EOF
}

# --- arguments -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --nut-host) NUT_HOST=$2; GIVEN[NUT_HOST]=1; shift 2;;
        --nut-port) NUT_PORT=$2; GIVEN[NUT_PORT]=1; shift 2;;
        --ups-name) UPS_NAME=$2; GIVEN[UPS_NAME]=1; shift 2;;
        --nut-user) NUT_USER=$2; GIVEN[NUT_USER]=1; shift 2;;
        --nut-password) NUT_PASSWORD=$2; GIVEN[NUT_PASSWORD]=1; shift 2;;
        --pin) PIN=$2; GIVEN[PIN]=1; shift 2;;
        --plug-host) PLUG_HOST=$2; GIVEN[PLUG_HOST]=1; shift 2;;
        --plug-password) PLUG_PASSWORD=$2; GIVEN[PLUG_PASSWORD]=1; shift 2;;
        --plug-switch-id) PLUG_SWITCH_ID=$2; GIVEN[PLUG_SWITCH_ID]=1; shift 2;;
        --sensor-host) SENSOR_HOST=$2; GIVEN[SENSOR_HOST]=1; shift 2;;
        --sensor-password) SENSOR_PASSWORD=$2; GIVEN[SENSOR_PASSWORD]=1; shift 2;;
        --sensor-listen)   SENSOR_LISTEN=yes; GIVEN[SENSOR_LISTEN]=1; shift;;
        --sensor-listen-host) SENSOR_LISTEN_HOST=$2; SENSOR_LISTEN=yes
                              GIVEN[SENSOR_LISTEN_HOST]=1; GIVEN[SENSOR_LISTEN]=1; shift 2;;
        --api-host) API_HOST=$2; GIVEN[API_HOST]=1; shift 2;;
        --api-port) API_PORT=$2; GIVEN[API_PORT]=1; shift 2;;
        --poll-interval) POLL_INTERVAL=$2; GIVEN[POLL_INTERVAL]=1; shift 2;;
        --sample-interval) SAMPLE_INTERVAL=$2; GIVEN[SAMPLE_INTERVAL]=1; shift 2;;
        --retain-full) RETAIN_FULL_DAYS=$2; GIVEN[RETAIN_FULL_DAYS]=1; shift 2;;
        --retain-hourly) RETAIN_HOURLY_DAYS=$2; GIVEN[RETAIN_HOURLY_DAYS]=1; shift 2;;
        --charge-warn) CHARGE_WARN=$2; GIVEN[CHARGE_WARN]=1; shift 2;;
        --charge-crit) CHARGE_CRIT=$2; GIVEN[CHARGE_CRIT]=1; shift 2;;
        --load-warn) LOAD_WARN=$2; GIVEN[LOAD_WARN]=1; shift 2;;
        --load-crit) LOAD_CRIT=$2; GIVEN[LOAD_CRIT]=1; shift 2;;
        --runtime-warn) RUNTIME_WARN_S=$2; GIVEN[RUNTIME_WARN_S]=1; shift 2;;
        --runtime-crit) RUNTIME_CRIT_S=$2; GIVEN[RUNTIME_CRIT_S]=1; shift 2;;
        --battery-life) BATTERY_LIFE_YEARS=$2; GIVEN[BATTERY_LIFE_YEARS]=1; shift 2;;
        --flag-confirm) FLAG_CONFIRM_POLLS=$2; GIVEN[FLAG_CONFIRM_POLLS]=1; shift 2;;
        --allow-dangerous) ALLOW_DANGEROUS=true; GIVEN[ALLOW_DANGEROUS]=1; shift;;
        --log-level) LOG_LEVEL=$2; GIVEN[LOG_LEVEL]=1; shift 2;;
        --no-journal)      LOG_TO_JOURNAL=false; GIVEN[LOG_TO_JOURNAL]=1; shift;;
        --advanced)        ADVANCED=yes; shift;;
        --sensor-port)     SENSOR_PORT=$2; SENSOR_LISTEN=yes
                           GIVEN[SENSOR_PORT]=1; GIVEN[SENSOR_LISTEN]=1; shift 2;;
        --server-name) SERVER_NAME=$2; GIVEN[SERVER_NAME]=1; shift 2;;
        --cert) CERT_FILE=$2; GIVEN[CERT_FILE]=1; shift 2;;
        --key) KEY_FILE=$2; GIVEN[KEY_FILE]=1; shift 2;;
        --ca) CA_FILE=$2; GIVEN[CA_FILE]=1; shift 2;;
        --self-signed)     SELF_SIGNED=yes; GIVEN[SELF_SIGNED]=1; shift;;
        --no-web)          WITH_WEB=''; shift;;
        --allow)           ALLOW_NETS=$2; GIVEN[ALLOW_NETS]=1; shift 2;;
        --admin-user)      ADMIN_USER=$2; shift 2;;
        --admin-password)  ADMIN_PASSWORD=$2; shift 2;;
        --rewrite-nginx)   REWRITE_NGINX=yes; shift;;
        --python)          PY_FORCE=$2; shift 2;;
        --system-python)   PY_SYSTEM=yes; shift;;
        --php-stream)      PHP_STREAM=$2; shift 2;;
        --remi)            USE_REMI=yes; shift;;
        --no-php-update)   PHP_UPDATE=''; shift;;
        --yes|-y)          ASSUME_YES=yes; shift;;
        --dry-run)         DRY_RUN=yes; shift;;
        --upgrade)         MODE=upgrade; DO_UPGRADE=yes; shift;;
        --uninstall)       MODE=uninstall; shift;;
        --source)          SOURCE_DIR=$(cd "$2" && pwd); shift 2;;
        --help|-h)         usage; exit 0;;
        *) fail "unknown option $1 - run --help";;
    esac
done

# ---------------------------------------------------------------------------
# Checks before anything is changed
# ---------------------------------------------------------------------------
preflight() {
    step "Checking this machine"

    [[ $EUID -eq 0 ]] || fail "run this with sudo"

    if [[ -r /etc/os-release ]]; then
        # Read in a subshell: os-release sets VERSION and PRETTY_NAME, which
        # would collide with names used here if it were sourced directly.
        local os_id os_version os_name
        os_id=$(. /etc/os-release && printf '%s' "${ID:-}")
        os_version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")
        os_name=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")
        say "$os_name"
        case $os_id in
            almalinux|rhel|rocky|centos)
                [[ ${os_version%%.*} -ge 9 ]] \
                    || warn "written for version 9; this is $os_version";;
            *) warn "written for AlmaLinux 9; ${os_id:-unknown} may need adjusting";;
        esac
    fi

    local python_version
    python_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null) \
        || fail "python3 is not installed"
    say "python $python_version"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' \
        || fail "python 3.7 or newer is needed"

    local missing=()
    local file
    for file in upsmon.py upsmon_admin.py deploy/upsmon.service deploy/upsmon.logrotate \
                deploy/upsmon_web.py deploy/upsmon_upgrade.py deploy/upsmon-web.path \
                deploy/upsmon-web.service deploy/upsmon-upgrade.path deploy/upsmon-upgrade.service \
                deploy/upsmon-console-login.sh; do
        [[ -f "$SOURCE_DIR/$file" ]] || missing+=("$file")
    done
    if [[ -n "$WITH_WEB" ]]; then
        for file in web/index.php web/upsmon-api.php web/settings/index.php web/settings-api.php \
                    web/upsmon-page.php web/upsmon-lang.php web/acme.php web/assets/settings.js \
                    deploy/nginx-upsmon.conf deploy/php-fpm-upsmon.conf; do
            [[ -f "$SOURCE_DIR/$file" ]] || missing+=("$file")
        done
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        printf '\n%sERROR: this needs the whole project, not just install.sh%s\n' \
            "$C_BAD" "$C_OFF" >&2
        printf '\n    Looked in: %s\n    Missing:   %s\n' \
            "$SOURCE_DIR" "${missing[*]}" >&2
        printf '\n    The files should sit together like this:\n\n' >&2
        cat >&2 <<'LAYOUT'
      upsmon/
        install.sh
        upsmon.py  upsmon_admin.py
        deploy/upsmon.service  upsmon_web.py  upsmon_upgrade.py  release-keys/
        deploy/upsmon.logrotate
        deploy/nginx-upsmon.conf
        deploy/config.json
        web/index.php  settings/index.php  assets/  lang/
        web/upsmon-api.php  settings-api.php  upsmon-page.php  upsmon-lang.php
        web/favicon.svg  favicon.ico  favicon-32.png  apple-touch-icon.png
LAYOUT
        printf '\n    Copy the whole folder across and run it from inside:\n' >&2
        printf '      cd /path/to/upsmon && sudo ./install.sh\n' >&2
        printf '\n    Or point it at the files:\n' >&2
        printf '      sudo ./install.sh --source /path/to/upsmon\n\n' >&2
        exit 1
    fi

    local py
    for py in upsmon.py upsmon_admin.py deploy/upsmon_web.py deploy/upsmon_upgrade.py; do
        python3 - "$SOURCE_DIR/$py" <<'PYCHECK' 2>/dev/null || fail "$py does not compile - is it complete?"
import sys
compile(open(sys.argv[1], encoding='utf-8').read(), sys.argv[1], 'exec')
PYCHECK
    done
    ls "$SOURCE_DIR"/deploy/release-keys/*.pub >/dev/null 2>&1 \
        || fail "deploy/release-keys/ holds no release key"
    local v1 v2
    v1=$(sed -n "s/^__version__ = '\([0-9.]*\)'.*/\1/p" "$SOURCE_DIR/upsmon.py")
    v2=$(sed -n "s/^__version__ = '\([0-9.]*\)'.*/\1/p" "$SOURCE_DIR/upsmon_admin.py")
    [[ "$v1" == "$v2" ]] || fail "upsmon.py says $v1 and upsmon_admin.py says $v2"
    NEW_VERSION=$v1
    good "the files are all here and they compile (upsmon $NEW_VERSION)"
}


# ---------------------------------------------------------------------------
# As OTP 1.0.187 has it: PHP fixed against php2shell, colour, the tools of the
# backups, the clock
# ---------------------------------------------------------------------------
php_fpm_units() {
    local found="" unit listed
    systemctl cat php-fpm.service >/dev/null 2>&1 && found="php-fpm"
    listed="$(systemctl list-unit-files --no-legend 'php*-fpm.service' 2>/dev/null || true)"
    while read -r unit _rest; do
        unit="${unit%.service}"
        [[ -n "$unit" && "$unit" != "php-fpm" && "$unit" =~ ^php[0-9.]*-fpm$ ]] && found="$found $unit"
    done <<< "$listed"
    echo "$found"
}

# PHP, fixed against php2shell
# ---------------------------------------------------------------------------
# On 21 October 2026 PHP fixed two remote code execution flaws reached through
# how PHP takes a request apart before any page runs (CVE-2026-109618,
# CVE-2026-109619). Fixed upstream: 8.2.35, 8.3.36, 8.4.27, 8.5.12. The
# distributions rebuilt their streams the same day - AlmaLinux 9's php:8.3 is
# 8.3.36 and php:8.2 is 8.2.35; its default 8.0 has the fix backported and
# keeps its number - so the version alone does not always say it, and the
# package's changelog is read as well.
#
# What this does: puts PHP on the stream asked for (8.3 unless told), brings
# every PHP package up to the newest build, and checks the result by the
# version and by the CVE in the changelog. Where AppStream has no fixed build
# it offers Remi's PHP 8.4 (fixed in 8.4.27). Either way the guard goes on:
# upload progress off for every PHP on the machine, upsmon's own pool taking no
# request body apart, and nginx refusing every multipart body.

php_fpm_bin() {         # the php-fpm that serves the pages: the newest one installed
    local b
    b="$(command -v php-fpm 2>/dev/null || true)"
    [[ -z "$b" && -x /usr/sbin/php-fpm ]] && b=/usr/sbin/php-fpm
    if [[ -z "$b" ]]; then
        b="$(ls -1 /usr/sbin/php-fpm[0-9]* 2>/dev/null | sort -V | tail -n 1 || true)"
    fi
    echo "$b"
}

php_fpm_version() {     # its version, 8.3.36 - from php-fpm itself, not from the
    local b v           # command-line php, which may be another one or missing (1.0.36)
    b="$(php_fpm_bin)"
    [[ -n "$b" ]] || { echo ""; return; }
    v="$("$b" -v 2>/dev/null | head -n 1 | awk '{print $2}')"
    echo "${v%%[-+~]*}"
}

ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]; }

php_fixed() {           # is the PHP that php-fpm runs fixed? 0 yes, 1 no
    local v b f log
    v="$(php_fpm_version)"
    [[ -n "$v" ]] || return 1
    b="$(echo "$v" | cut -d. -f1,2)"
    case "$b" in
        8.2) f=8.2.35 ;; 8.3) f=8.3.36 ;; 8.4) f=8.4.27 ;; 8.5) f=8.5.12 ;;
        *) if ver_ge "$b" 8.6; then return 0; fi; f="" ;;
    esac
    [[ -n "$f" ]] && ver_ge "$v" "$f" && return 0
    # A backport keeps the old number: the changelog says it instead. Read
    # whole first and searched after (1.0.36): `rpm | grep -q` under
    # pipefail failed when grep found it early and rpm died on the pipe.
    if [[ "$PKG" == "dnf" ]]; then
        log="$(rpm -q --changelog php-fpm php-common 2>/dev/null || true)"
        grep -q 'CVE-2026-109618' <<< "$log" && return 0
    elif [[ "$PKG" == "apt" ]]; then
        for log in /usr/share/doc/php*-fpm/changelog.Debian.gz /usr/share/doc/php*-common/changelog.Debian.gz; do
            [[ -f "$log" ]] || continue
            grep -q 'CVE-2026-109618' <<< "$(zcat "$log" 2>/dev/null || true)" && return 0
        done
    fi
    return 1
}

php_says() {
    local v
    v="$(php_fpm_version)"; v="${v:-?}"
    if php_fixed; then
        good "PHP $v has the php2shell fix (CVE-2026-109618, CVE-2026-109619)"
    else
        warn "PHP $v does NOT have the php2shell fix (CVE-2026-109618, CVE-2026-109619)"
    fi
}

php_guard() {           # the second layer, for every PHP on the machine
    local dir
    for dir in /etc/php.d /etc/php/*/fpm/conf.d /etc/php/*/cli/conf.d; do
        [[ -d "$dir" ]] || continue
        if [[ -f "$dir/99-php2shell.ini" ]] && grep -q 'upload_progress.enabled *= *0' "$dir/99-php2shell.ini"; then
            continue
        fi
        run install -m 0644 "$SOURCE_DIR/deploy/99-php2shell.ini" "$dir/99-php2shell.ini"
        PHP_RELOAD=yes
        good "$dir/99-php2shell.ini - session upload progress off, sessions strict"
    done
}

remi_php() {
    [[ "$PKG" == "dnf" ]] || { warn "Remi's repository is for the RHEL family only"; return 1; }
    local major="${OS_MAJOR:-9}"
    say "Remi's repository (rpms.remirepo.net), PHP 8.4"
    if ! rpm -q remi-release >/dev/null 2>&1; then
        run dnf install -y "https://rpms.remirepo.net/enterprise/remi-release-${major}.rpm" \
            || { warn "remi-release could not be installed (is rpms.remirepo.net reachable?)"; return 1; }
    fi
    if dnf module list php 2>/dev/null | grep -q 'remi-8.4'; then
        run dnf module reset -y php
        run dnf module enable -y php:remi-8.4
    else
        run dnf config-manager --set-enabled remi-modular 2>/dev/null || true
        run dnf module reset -y php || true
        run dnf module enable -y php:remi-8.4 || { warn "php:remi-8.4 could not be enabled"; return 1; }
    fi
    run dnf distro-sync -y 'php*'
    run dnf install -y php-fpm php-cli php-common
}

php_floor() {           # the first build of a stream fixed against php2shell
    case "$1" in
        8.2) echo 8.2.35 ;; 8.3) echo 8.3.36 ;; 8.4) echo 8.4.27 ;; 8.5) echo 8.5.12 ;; *) echo "" ;;
    esac
}

ensure_php() {
    step "PHP, and php2shell"
    if [[ -z "$PHP_UPDATE" ]]; then
        note "--no-php-update: PHP is left as it is"
        php_says
        php_guard
        return 0
    fi
    # upsmon puts PHP on one stream (4.1.2): php:8.3 on AlmaLinux / RHEL 9 -
    # fixed against php2shell in 8.3.36 - on a fresh install and on every
    # upgrade, whatever stream (or AlmaLinux's own 8.0) was there before.
    # --php-stream X.Y chooses another one; --no-php-update leaves PHP alone.
    local had_php="" cur="" want="$PHP_STREAM"
    if command -v php-fpm >/dev/null 2>&1 || ls /usr/sbin/php-fpm* >/dev/null 2>&1; then had_php=yes; fi
    [[ -n "$had_php" ]] && cur="$(php_fpm_version | cut -d. -f1,2)"
    if [[ "$PKG" == "dnf" ]]; then
        if [[ -n "$USE_REMI" ]]; then
            remi_php || true
        else
            local streams now
            streams="$(dnf -q module list php 2>/dev/null || true)"
            now="$(dnf -q module list --enabled php 2>/dev/null || true)"
            now="$(awk '/^php /{print $2; exit}' <<< "$now")"
            if ! grep -qE "^php +${want//./\\.}( |$)" <<< "$streams"; then
                warn "this system offers no stream php:$want (dnf module list php) - PHP is updated where it is"
                if [[ -n "$had_php" ]]; then
                    run dnf upgrade -y --refresh 'php*' || true
                else
                    run dnf install -y php-fpm php-cli php-common
                fi
            elif [[ "$now" == "$want" && "$cur" == "$want" ]]; then
                say "PHP is on the stream php:$want: brought up to its newest build"
                run dnf upgrade -y --refresh 'php*' || true
            else
                say "PHP ${cur:-(none)} → the stream php:$want (the newest build of it: $(php_floor "$want") or later)"
                run dnf module reset -y php
                run dnf module enable -y "php:$want" || fail "the stream php:$want could not be enabled"
                if [[ -n "$had_php" ]]; then
                    # Every PHP package there (its extensions too) moved to the stream.
                    run dnf distro-sync -y --refresh 'php*' || fail "PHP could not be moved to php:$want"
                fi
                run dnf install -y php-fpm php-cli php-common || fail "PHP $want could not be installed"
            fi
        fi
    elif [[ "$PKG" == "apt" ]]; then
        if [[ -n "$had_php" ]]; then
            say "PHP is installed but not fixed: updating the packages that are there"
            run apt-get update
            local have
            have="$(dpkg-query -W -f='${Package} ${Status}\n' 'php*' 2>/dev/null | awk '/ installed$/{print $1}' | tr '\n' ' ' || true)"
            [[ -n "$have" ]] && { run apt-get install -y --only-upgrade $have || true; }
        else
            run apt-get update
            run apt-get install -y php-fpm php-cli
        fi
    else
        warn "this distribution is not one this knows: install php-fpm yourself, fixed against php2shell"
    fi
    [[ -n "$DRY_RUN" ]] && { php_guard; return 0; }
    if ! php_fixed && [[ "$PKG" == "dnf" && -z "$USE_REMI" ]]; then
        warn "the PHP AppStream has here is not fixed yet: $(php_fpm_version)"
        # Never on its own in an upgrade (1.0.44): it moves every PHP site on
        # the machine to 8.4. Asked of a person, or --remi.
        if [[ -n "$DO_UPGRADE" || -n "${UPSMON_UPGRADE_FROM_PAGES:-}" ]]; then
            note "Remi's PHP 8.4 is not taken during an upgrade by itself: ./install.sh --upgrade --remi"
        elif confirm "Take PHP 8.4 from Remi's repository instead (fixed in 8.4.27)?" y; then
            remi_php || true
        fi
    fi
    php_says
    # On the stream chosen it is the fixed build or nothing older (upsmon 4.1.2):
    # php:8.3 - 8.3.36.
    local pvs floor
    pvs="$(php_fpm_version)"
    floor="$(php_floor "$PHP_STREAM")"
    if [[ "$PKG" == "dnf" && -z "$USE_REMI" && -n "$floor" && -n "$pvs" ]]; then
        if ver_ge "$pvs" "$floor" && [[ "$(cut -d. -f1,2 <<< "$pvs")" == "$PHP_STREAM" ]]; then
            good "PHP $pvs from the stream php:$PHP_STREAM ($floor or later)"
        else
            warn "PHP here is $pvs, not $floor or later from the stream php:$PHP_STREAM:"
            warn "  dnf clean all && dnf module reset -y php && dnf module enable -y php:$PHP_STREAM && dnf distro-sync -y 'php*'"
        fi
    fi
    # PHP 8 at least (1.0.94): the pages' relay is written for it, and on a
    # 7.4 every page was a 500 after an install that said it went well.
    local pv
    pv="$(php_fpm_version)"
    if [[ -n "$pv" && -z "$DRY_RUN" ]] && ! ver_ge "$pv" 8.0; then
        fail "php-fpm here is $pv: upsmon's pages need PHP 8.0 or newer (on Debian 11 / Ubuntu 20.04 add a PHP 8 repository first, or install with --no-web)"
    fi
    if ! php_fixed; then
        warn "Until it is fixed: dnf upgrade --refresh 'php*' (or apt upgrade) as soon as the"
        warn "fixed build is out, and ./install.sh --upgrade. upsmon's pages are guarded meanwhile:"
        warn "its pool takes no request body apart, upload progress is off everywhere, and nginx"
        warn "refuses every multipart body."
    fi
    php_guard
    # The new build only counts once php-fpm runs it.
    local unit
    for unit in $(php_fpm_units); do
        run systemctl enable "$unit" >/dev/null 2>&1 || true
        run systemctl restart "$unit" || warn "$unit would not restart"
    done
    if grep -lE ' /(usr|lib|upsmon).*\(deleted\)$' /proc/[0-9]*/maps 2>/dev/null | grep -q .; then
        note "some processes still run files an update replaced; they pick the new ones up when restarted"
    fi
}

# ---------------------------------------------------------------------------
# The pages: the pool, nginx, the certificate

install_colour() {      # colorama: the command line in colour, as OTP's - for the Python upsmon runs on
    # Nothing needs it - without it upsmon writes the same escape sequences
    # itself - so it is offered and never insisted on.
    local py="${UPSMON_PY:-python3}" v
    v="${py##*/python}"
    if "$py" -c 'import colorama' 2>/dev/null; then
        good "colorama is here for $py - the command line is in colour"
        return 0
    fi
    if [[ "$PKG" == "dnf" ]]; then
        if [[ "$v" =~ ^3\.[0-9]+$ ]]; then
            run dnf install -y "python$v-colorama" >/dev/null 2>&1 || true
            "$py" -m pip --version >/dev/null 2>&1 || run dnf install -y "python$v-pip" >/dev/null 2>&1 || true
        else
            run dnf install -y python3-colorama >/dev/null 2>&1 || true
        fi
    elif [[ "$PKG" == "apt" ]]; then
        run apt-get install -y python3-colorama >/dev/null 2>&1 || true
    fi
    # Not in the distribution's own repositories (on RHEL 9 it is EPEL's):
    # pip, for that Python.
    if ! "$py" -c 'import colorama' 2>/dev/null && "$py" -m pip --version >/dev/null 2>&1; then
        run "$py" -m pip install --quiet colorama >/dev/null 2>&1 || true
    fi
    if [[ -n "$DRY_RUN" ]] || "$py" -c 'import colorama' 2>/dev/null; then
        good "colorama installed for $py - the command line is in colour"
    else
        note "colorama is not available for $py; colour is written by hand instead,"
        note "which works on this terminal and is the only difference."
    fi
}

install_backup_tools() {
    local opt=()
    { command -v ssh >/dev/null && command -v sftp >/dev/null && command -v ssh-keygen >/dev/null; } \
        || opt+=("openssh-clients")
    command -v smbclient >/dev/null || opt+=("samba-client")
    ((${#opt[@]})) || return 0
    [[ -n "$DRY_RUN" ]] && { say "would install, for backups: ${opt[*]}"; return 0; }
    if [[ "$PKG" == "dnf" ]]; then
        dnf install -y "${opt[@]}" >/dev/null 2>&1 \
            && good "for backups to SFTP, SCP and SMB: ${opt[*]}" \
            || warn "for backups to SFTP, SCP and SMB, install by hand: dnf install ${opt[*]}"
    elif [[ "$PKG" == "apt" ]]; then
        local deb=()
        for p in "${opt[@]}"; do [[ "$p" == "openssh-clients" ]] && deb+=("openssh-client") || deb+=("smbclient"); done
        apt-get install -y "${deb[@]}" >/dev/null 2>&1 || warn "for backups: apt-get install ${deb[*]}"
    fi
}

install_time_tools() {
    local unit=chronyd
    [[ "$PKG" == "apt" ]] && unit=chrony
    if ! command -v chronyd >/dev/null && ! command -v chronyc >/dev/null; then
        if [[ -n "$DRY_RUN" ]]; then say "would install chrony (the clock)"; return 0; fi
        if [[ "$PKG" == "dnf" ]]; then
            dnf install -y chrony >/dev/null 2>&1 || { warn "chrony could not be installed: dnf install chrony - every sample is written with its time"; return 0; }
        elif [[ "$PKG" == "apt" ]]; then
            apt-get install -y chrony >/dev/null 2>&1 || { warn "chrony could not be installed: apt-get install chrony"; return 0; }
        else
            warn "install chrony by hand - every sample is written with its time"; return 0
        fi
        good "chrony installed (the clock)"
    fi
    [[ -n "$DRY_RUN" ]] && return 0
    # Another time daemon would fight it.
    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
        note "systemd-timesyncd stopped: chrony keeps the clock"
    fi
    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null || ! systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl enable --now "$unit" >/dev/null 2>&1 \
            && good "chrony started and enabled ($unit)" \
            || warn "chrony could not be started: systemctl enable --now $unit"
    fi
    timedatectl set-ntp true >/dev/null 2>&1 || true
    if ! grep -Eq '^[[:space:]]*(server|pool|peer|sourcedir)[[:space:]]' /etc/chrony.conf /etc/chrony/chrony.conf 2>/dev/null; then
        warn "chrony has no time server: set them in Settings → Time (or in /etc/chrony.conf)"
    fi
}


# ---------------------------------------------------------------------------
# What to install
# ---------------------------------------------------------------------------
gather_answers() {
    # An existing configuration is never overwritten, so asking fifteen
    # questions and then discarding every answer wastes the person's time.
    if [[ -f "$CONFIG_FILE" ]]; then
        step "Existing configuration"
        say "$CONFIG_FILE is already here and will be left as it is."
        note "The questions about the UPS, the plug and the sensor are skipped;"
        note "nothing you answered would be used. To start from scratch:"
        note "  sudo rm $CONFIG_FILE"
        gather_web_answers
        return 0
    fi

    step "What this installation should watch"

    ask NUT_HOST "Address of the NAS or host running NUT"
    [[ -n "$NUT_HOST" ]] || fail "the UPS host is required; give --nut-host"
    ask UPS_NAME "Name of the UPS on that host" "$UPS_NAME"

    note "An account is needed only to change UPS settings or run its self"
    note "tests. Reading works without one. On a Synology this is an entry"
    note "you add to /etc/ups/upsd.users over SSH."
    ask NUT_USER "NUT username, or empty for read-only" ""
    [[ -n "$NUT_USER" ]] && ask_secret NUT_PASSWORD "Password for $NUT_USER"

    if [[ -z "$PIN" ]] && [[ -z "$ASSUME_YES" ]]; then
        note "A four-digit PIN is asked for before any control action in the"
        note "dashboard. Leave it empty to allow them without one."
        ask PIN "PIN for the dashboard" ""
    fi
    if [[ -n "$PIN" ]] && ! [[ $PIN =~ ^[0-9]{4}$ ]]; then
        fail "the PIN must be exactly four digits"
    fi

    if [[ -z "$PLUG_HOST" ]] && [[ -z "$ASSUME_YES" ]]; then
        note ""
        note "A Shelly smart plug can be watched alongside the UPS, which is"
        note "worth doing when the UPS reports load but not watts. Leave empty"
        note "to skip; it can be added to the configuration later."
        ask PLUG_HOST "Address of a Shelly plug, or empty" ""
    fi
    [[ -n "$PLUG_HOST" ]] && ask_secret PLUG_PASSWORD "Password for the plug"

    if [[ -z "$SENSOR_HOST$SENSOR_LISTEN" ]] && [[ -z "$ASSUME_YES" ]]; then
        note ""
        note "A temperature sensor can report here. One on USB power can be"
        note "read directly; one on battery sleeps and has to push instead."
        ask SENSOR_HOST "Address of a sensor to read directly, or empty" ""
        if confirm "Listen for pushes from a sleeping sensor?"; then
            SENSOR_LISTEN=yes
            ask SENSOR_PORT "Port to listen on" "$SENSOR_PORT"
        fi
    fi
    [[ -n "$SENSOR_HOST" ]] && ask_secret SENSOR_PASSWORD "Password for the sensor"

    if [[ -n "$SENSOR_LISTEN" ]] && [[ -z "$ASSUME_YES" ]]; then
        note "Listening on every interface is usually right. Give one address"
        note "to accept pushes on that interface only."
        ask SENSOR_LISTEN_HOST "Address to listen on" "$SENSOR_LISTEN_HOST"
    fi

    ask_advanced
    gather_web_answers
}

gather_web_answers() {
    if [[ -n "$WITH_WEB" ]]; then
        ask SERVER_NAME "Hostname the dashboard will answer on" "$(hostname -f 2>/dev/null || hostname)"
        note "The dashboard and Settings answer only these networks (and this machine)."
        ask ALLOW_NETS "Who may reach the pages (CIDR, comma separated)" \
            "${ALLOW_NETS:-192.168.0.0/16,172.16.0.0/12,10.0.0.0/8}"

        # A certificate already in place - this installation's, or the one the
        # standalone 3.x had - is kept, and nothing about it is asked.
        if [[ -z "$CERT_FILE" ]] && [[ -z "$SELF_SIGNED" ]] \
           && { [[ -f "$CERT_DIR/upsmon.pem" ]] || [[ -f "$CERT_DIR/server.pem" ]]; }; then
            say "a certificate is already in place in $CERT_DIR; it is kept"
            note "replace it later on Settings → Certificates and TLS, or by ACME"
            return 0
        fi

        # A certs/ folder shipped alongside the script is the obvious place to
        # look, and saves typing three paths that are already right there.
        if [[ -z "$CERT_FILE" ]] && [[ -z "$SELF_SIGNED" ]] \
           && [[ -d "$SOURCE_DIR/certs" ]]; then
            local found_cert='' found_key='' found_ca=''
            local candidate
            for candidate in server.pem server.crt fullchain.pem cert.pem \
                             "$SERVER_NAME.pem" "$SERVER_NAME.crt"; do
                [[ -f "$SOURCE_DIR/certs/$candidate" ]] && { found_cert="$SOURCE_DIR/certs/$candidate"; break; }
            done
            for candidate in server.key privkey.pem key.pem "$SERVER_NAME.key"; do
                [[ -f "$SOURCE_DIR/certs/$candidate" ]] && { found_key="$SOURCE_DIR/certs/$candidate"; break; }
            done
            for candidate in server.ca chain.pem ca.pem bundle.pem server-ca.pem; do
                [[ -f "$SOURCE_DIR/certs/$candidate" ]] && { found_ca="$SOURCE_DIR/certs/$candidate"; break; }
            done

            if [[ -n "$found_cert" ]] && [[ -n "$found_key" ]]; then
                say "Found a certificate in $SOURCE_DIR/certs:"
                note "  certificate  $(basename "$found_cert")"
                note "  private key  $(basename "$found_key")"
                [[ -n "$found_ca" ]] && note "  issuer chain $(basename "$found_ca")"
                if [[ -n "$ASSUME_YES" ]] || confirm "Use it?"; then
                    CERT_FILE="$found_cert"
                    KEY_FILE="$found_key"
                    CA_FILE="$found_ca"
                fi
            elif [[ -n "$found_cert" || -n "$found_key" ]]; then
                warn "certs/ has only part of a certificate; ignoring it"
                note "  it needs both the certificate and its private key"
            fi
        fi

        if [[ -z "$CERT_FILE" ]] && [[ -z "$SELF_SIGNED" ]]; then
            note ""
            note "The dashboard is served over HTTPS. Give an existing"
            note "certificate, or have one made for this machine."
            if [[ -z "$ASSUME_YES" ]] && confirm "Do you have a certificate to use?"; then
                ask CERT_FILE "Path to the certificate"
                ask KEY_FILE "Path to its private key"
                ask CA_FILE "Path to the issuer chain, or empty" ""
            else
                SELF_SIGNED=yes
            fi
        fi
        if [[ -n "$CERT_FILE" ]]; then
            [[ -r "$CERT_FILE" ]] || fail "cannot read $CERT_FILE"
            [[ -r "$KEY_FILE" ]]  || fail "cannot read the key $KEY_FILE"
        fi
    fi
}

# ---------------------------------------------------------------------------
# The steps themselves
# ---------------------------------------------------------------------------
ask_advanced() {
    # The defaults suit most installations, so this is behind one question
    # rather than fifteen. --advanced skips the question and asks them all.
    if [[ -n "$ASSUME_YES" ]] && [[ -z "$ADVANCED" ]]; then
        return 0
    fi
    if [[ -z "$ADVANCED" ]]; then
        echo
        note "Thresholds, retention and timing all have defaults that suit most"
        note "installations. They can be changed later in $CONFIG_FILE."
        confirm "Go through them now?" || return 0
    fi

    step "When the dashboard should call something a problem"
    note "The battery percentage below which it turns amber, then red."
    ask CHARGE_WARN "Battery amber below (%)" "$CHARGE_WARN"
    ask CHARGE_CRIT "Battery red below (%)" "$CHARGE_CRIT"
    note "The load percentage above which it turns amber, then red."
    ask LOAD_WARN "Load amber above (%)" "$LOAD_WARN"
    ask LOAD_CRIT "Load red above (%)" "$LOAD_CRIT"
    note "Remaining runtime, in seconds. Set the red one above however long"
    note "this machine takes to shut down cleanly."
    ask RUNTIME_WARN_S "Runtime amber below (s)" "$RUNTIME_WARN_S"
    ask RUNTIME_CRIT_S "Runtime red below (s)" "$RUNTIME_CRIT_S"
    note "How long this battery should last, used to colour its age."
    ask BATTERY_LIFE_YEARS "Expected battery life (years)" "$BATTERY_LIFE_YEARS"

    step "How often, and how much is kept"
    note "The UPS is read every poll; a row is written every sample interval."
    ask POLL_INTERVAL "Seconds between readings" "$POLL_INTERVAL"
    ask SAMPLE_INTERVAL "Seconds between rows written" "$SAMPLE_INTERVAL"
    note "Full-resolution rows are rolled into hourly averages after this many"
    note "days. Roughly 10-15 MB in total with the defaults."
    ask RETAIN_FULL_DAYS "Days of full history" "$RETAIN_FULL_DAYS"
    ask RETAIN_HOURLY_DAYS "Days of hourly averages" "$RETAIN_HOURLY_DAYS"
    note "A status flag must be seen this many polls running before it counts."
    note "USB occasionally returns one bad read; 2 filters those out."
    ask FLAG_CONFIRM_POLLS "Polls to confirm a status flag" "$FLAG_CONFIRM_POLLS"

    step "Safety and logging"
    note "The commands that switch the UPS outlets off are disabled by default."
    note "They cut power to everything plugged in, including this machine."
    if confirm "Enable them?"; then
        ALLOW_DANGEROUS=true
    else
        ALLOW_DANGEROUS=false
    fi
    ask LOG_LEVEL "Log level (info or debug)" "$LOG_LEVEL"
    note "The daemon's API is reachable only from this machine. Change the"
    note "address only if something else already uses port $API_PORT."
    ask API_PORT "Port for the local API" "$API_PORT"
}

install_packages() {
    step "Installing packages"
    local wanted=(python3 openssl policycoreutils-python-utils)
    [[ -n "$WITH_WEB" ]] && wanted+=(nginx curl)

    local missing=()
    local package
    for package in "${wanted[@]}"; do
        rpm -q "$package" >/dev/null 2>&1 || missing+=("$package")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        good "everything needed is already installed"
    elif [[ -n "$DRY_RUN" ]]; then
        note "[would run] dnf install -y ${missing[*]}"
    else
        say "installing: ${missing[*]}"
        dnf install -y "${missing[@]}" >/dev/null || fail "package installation failed"
        good "installed"
    fi
    install_backup_tools
    install_time_tools
    # PHP for the pages - put on a release fixed against php2shell, checked by
    # its version and its changelog, guarded either way (as OTP does it).
    [[ -n "$WITH_WEB" ]] && ensure_php
    return 0
}

create_user() {
    step "Creating the service accounts"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        good "user $SERVICE_USER already exists"
    else
        run useradd --system --home-dir "$STATE_DIR" --shell /sbin/nologin \
            --comment 'upsmon daemon' "$SERVICE_USER"
        good "created $SERVICE_USER"
    fi
    [[ -n "$WITH_WEB" ]] || return 0
    # The pages run in a php-fpm pool of their own, as an account that may
    # read the daemon's API tokens (the group upsmon) and nothing else.
    if id "$WEB_USER" >/dev/null 2>&1; then
        good "user $WEB_USER already exists"
    else
        run useradd --system --no-create-home --home-dir /var/www/upsmon --shell /sbin/nologin \
            --comment 'upsmon pages (php-fpm)' "$WEB_USER"
        good "created $WEB_USER, which runs the pages"
    fi
    if id -nG "$WEB_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$SERVICE_USER"; then
        good "$WEB_USER may read the API tokens (group $SERVICE_USER)"
    else
        run usermod -a -G "$SERVICE_USER" "$WEB_USER"
        good "$WEB_USER added to the group $SERVICE_USER"
    fi
}

py_runs_upsmon() {      # py_runs_upsmon PYTHON -> 0 when it can run upsmon
    local py="$1"
    [[ -x "$py" ]] || return 1
    "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || return 1
    "$py" -c 'import ssl, sqlite3, hashlib, json, tarfile, ftplib, curses' 2>/dev/null || return 1
    "$py" -I "$SOURCE_DIR/upsmon.py" --version >/dev/null 2>&1
}

# The Python upsmon runs on (as OTP chooses it): the newest the system offers
# beside its own - on AlmaLinux / RHEL 9 the system's python3 is 3.9, and
# AppStream has python3.11 and python3.12 (and newer where they come) - put in
# when missing, and shown to run upsmon before it is taken. The choice is the
# link $LIB_DIR/python; the service and the command start it. --python PATH and
# --system-python are kept for the next upgrade, the pages' too.
runtime_python() {
    step "Python"
    local cand=() py v kept="$LIB_DIR/python-choice"
    if [[ -n "$PY_FORCE" ]]; then
        [[ -z "$DRY_RUN" ]] && { install -d -m 755 "$LIB_DIR"; printf '%s\n' "$PY_FORCE" > "$kept"; }
        cand=("$PY_FORCE")
    elif [[ -n "$PY_SYSTEM" ]]; then
        [[ -z "$DRY_RUN" ]] && { install -d -m 755 "$LIB_DIR"; printf 'system\n' > "$kept"; }
        cand=(/usr/bin/python3)
    else
        if [[ -f "$kept" && ! -L "$kept" ]]; then
            local was
            was="$(head -n1 "$kept" 2>/dev/null || true)"
            [[ "$was" == "system" ]] && was=/usr/bin/python3
            [[ "$was" == /* ]] && { cand=("$was"); note "the Python chosen before is kept: $was (--python PATH or --system-python to change it)"; }
        fi
        cand+=(/usr/bin/python3.14 /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3)
    fi
    UPSMON_PY=""
    for py in "${cand[@]}"; do
        v="${py##*/python}"
        if [[ ! -x "$py" && "$v" =~ ^3\.[0-9]+$ && "$PKG" == "dnf" ]]; then
            if [[ -n "$DRY_RUN" ]]; then
                note "[would try] dnf install -y python$v"
            elif dnf install -y "python$v" >/dev/null 2>&1; then
                good "python$v installed from AppStream"
            fi
        fi
        [[ -x "$py" ]] || continue
        if [[ -n "$DRY_RUN" ]] || py_runs_upsmon "$py"; then UPSMON_PY="$py"; break; fi
        note "$py ($("$py" --version 2>&1)) cannot run upsmon here - the next one is tried"
    done
    [[ -n "$UPSMON_PY" ]] || fail "no Python here runs upsmon - install python3.12 (dnf), or say which with --python"
    run install -d -m 755 "$LIB_DIR"
    run ln -sfn "$UPSMON_PY" "$LIB_DIR/python"
    good "upsmon runs on $("$UPSMON_PY" --version 2>&1 || echo "$UPSMON_PY") - $UPSMON_PY"
}

install_program() {
    runtime_python
    install_colour
    step "Installing the program"
    run install -d -m 755 "$LIB_DIR"
    run install -m 755 "$SOURCE_DIR/upsmon.py" "$LIB_DIR/upsmon.py"
    run install -m 644 "$SOURCE_DIR/upsmon_admin.py" "$LIB_DIR/upsmon_admin.py"
    # Root's helpers: what the pages ask of root, each started by its path unit.
    run install -m 700 "$SOURCE_DIR/deploy/upsmon_web.py" "$LIB_DIR/upsmon_web.py"
    run install -m 755 "$SOURCE_DIR/deploy/upsmon_upgrade.py" "$LIB_DIR/upsmon_upgrade.py"
    local doc
    for doc in INSTALL.md README.md CHANGELOG.md; do
        [[ -f "$SOURCE_DIR/$doc" ]] && run install -m 644 "$SOURCE_DIR/$doc" "$LIB_DIR/$doc"
    done
    rm -rf "$LIB_DIR/__pycache__" 2>/dev/null || true

    # The release keys a package from the pages must be signed by: root's alone,
    # exactly the ones this version ships (a key no longer shipped is no longer
    # trusted).
    run install -d -m 755 "$LIB_DIR/release-keys"
    if [[ -z "$DRY_RUN" ]]; then
        rm -f "$LIB_DIR"/release-keys/*.pub
        install -m 644 "$SOURCE_DIR"/deploy/release-keys/*.pub "$LIB_DIR/release-keys/"
        # How far back Settings → Upgrades may go: never below the highest floor
        # of any version installed here (only root writes it).
        local floor had
        floor=$(sed -n "s/^DOWNGRADE_FLOOR = '\([0-9.]*\)'.*/\1/p" "$SOURCE_DIR/upsmon_admin.py")
        had=$(cat "$LIB_DIR/downgrade-floor" 2>/dev/null || true)
        if [[ -z "$had" ]] || [[ "$(printf '%s\n%s\n' "$had" "$floor" | sort -V | tail -1)" == "$floor" ]]; then
            printf '%s\n' "$floor" > "$LIB_DIR/downgrade-floor"
        fi
        chmod 644 "$LIB_DIR/downgrade-floor"

        cat > "$BIN" <<EOF
#!/bin/sh
# upsmon - installed by install.sh $INSTALLER_VERSION, on the Python it chose ($LIB_DIR/python)
exec $LIB_DIR/python $LIB_DIR/upsmon.py "\$@"
EOF
        "$LIB_DIR/python" -m py_compile "$LIB_DIR/upsmon.py" "$LIB_DIR/upsmon_admin.py" 2>/dev/null || true
        chmod 755 "$BIN"
        # The folders the daemon lays its requests to root in, made as the
        # daemon's own account (never through a link root would follow).
        install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$STATE_DIR"
        runuser -u "$SERVICE_USER" -- mkdir -p -m 750 "$STATE_DIR/web" "$STATE_DIR/upgrade" 2>/dev/null || true
    else
        note "[would write] $BIN, $LIB_DIR/release-keys, $LIB_DIR/downgrade-floor"
    fi
    good "installed to $LIB_DIR, and $BIN runs it"
}

write_config() {
    step "Writing the configuration"
    run install -d -m 755 "$CONFIG_DIR"

    if [[ -f "$CONFIG_FILE" ]]; then
        # Nothing is written, so there is nothing to back up. A .bak on every
        # run would just accumulate copies of a file that never changed.
        good "$CONFIG_FILE is already here and was left alone"
        return
    fi

    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $CONFIG_FILE"
        return
    fi

    # Values go through the environment, never into the Python source. A
    # password containing a quote, a backslash or a newline would otherwise
    # corrupt the file at best, and run as code at worst.
    UPSMON_NUT_HOST="$NUT_HOST" \
    UPSMON_NUT_PORT="$NUT_PORT" \
    UPSMON_UPS_NAME="$UPS_NAME" \
    UPSMON_NUT_USER="$NUT_USER" \
    UPSMON_NUT_PASSWORD="$NUT_PASSWORD" \
    UPSMON_PIN="$PIN" \
    UPSMON_PLUG_HOST="$PLUG_HOST" \
    UPSMON_PLUG_PASSWORD="$PLUG_PASSWORD" \
    UPSMON_PLUG_SWITCH_ID="$PLUG_SWITCH_ID" \
    UPSMON_SENSOR_HOST="$SENSOR_HOST" \
    UPSMON_SENSOR_PASSWORD="$SENSOR_PASSWORD" \
    UPSMON_SENSOR_LISTEN="$SENSOR_LISTEN" \
    UPSMON_SENSOR_PORT="$SENSOR_PORT" \
    UPSMON_SENSOR_LISTEN_HOST="$SENSOR_LISTEN_HOST" \
    UPSMON_API_HOST="$API_HOST" \
    UPSMON_API_PORT="$API_PORT" \
    UPSMON_POLL_INTERVAL="$POLL_INTERVAL" \
    UPSMON_SAMPLE_INTERVAL="$SAMPLE_INTERVAL" \
    UPSMON_SAMPLE_INTERVAL_BATTERY="$SAMPLE_INTERVAL_BATTERY" \
    UPSMON_FLAG_CONFIRM_POLLS="$FLAG_CONFIRM_POLLS" \
    UPSMON_RETAIN_FULL_DAYS="$RETAIN_FULL_DAYS" \
    UPSMON_RETAIN_HOURLY_DAYS="$RETAIN_HOURLY_DAYS" \
    UPSMON_CHARGE_WARN="$CHARGE_WARN" \
    UPSMON_CHARGE_CRIT="$CHARGE_CRIT" \
    UPSMON_LOAD_WARN="$LOAD_WARN" \
    UPSMON_LOAD_CRIT="$LOAD_CRIT" \
    UPSMON_RUNTIME_WARN_S="$RUNTIME_WARN_S" \
    UPSMON_RUNTIME_CRIT_S="$RUNTIME_CRIT_S" \
    UPSMON_BATTERY_LIFE_YEARS="$BATTERY_LIFE_YEARS" \
    UPSMON_ALLOW_DANGEROUS="$ALLOW_DANGEROUS" \
    UPSMON_LOG_FILE="$LOG_FILE" \
    UPSMON_LOG_LEVEL="$LOG_LEVEL" \
    UPSMON_LOG_TO_JOURNAL="$LOG_TO_JOURNAL" \
    python3 - "$CONFIG_FILE" <<'PYEOF'
import json
import os
import sys


def value(name):
    return os.environ.get('UPSMON_' + name, '')


def number(name, fallback):
    text = value(name)
    if not text:
        return fallback
    return float(text) if '.' in text else int(text)


# Written out in full rather than leaving defaults implicit: a configuration
# you can read and edit beats one where half the behaviour is invisible.
config = {
    "nut_host": value('NUT_HOST'),
    "nut_port": number('NUT_PORT', 3493),
    "ups_name": value('UPS_NAME') or 'ups',

    "api_host": value('API_HOST') or '127.0.0.1',
    "api_port": number('API_PORT', 9848),

    "log_file": value('LOG_FILE') or '/var/log/upsmon/upsmon.log',
    "log_level": value('LOG_LEVEL') or 'info',
    "log_to_journal": value('LOG_TO_JOURNAL') != 'false',

    "poll_interval": number('POLL_INTERVAL', 10),
    "sample_interval": number('SAMPLE_INTERVAL', 60),
    "sample_interval_battery": number('SAMPLE_INTERVAL_BATTERY', 10),
    "flag_confirm_polls": number('FLAG_CONFIRM_POLLS', 2),
    "retain_full_days": number('RETAIN_FULL_DAYS', 14),
    "retain_hourly_days": number('RETAIN_HOURLY_DAYS', 730),

    "charge_warn": number('CHARGE_WARN', 50),
    "charge_crit": number('CHARGE_CRIT', 25),
    "load_warn": number('LOAD_WARN', 70),
    "load_crit": number('LOAD_CRIT', 90),
    "runtime_warn_s": number('RUNTIME_WARN_S', 300),
    "runtime_crit_s": number('RUNTIME_CRIT_S', 120),
    "battery_life_years": number('BATTERY_LIFE_YEARS', 4.0),

    "allow_dangerous_commands": value('ALLOW_DANGEROUS') == 'true',
}
if value('NUT_USER'):
    config["nut_username"] = value('NUT_USER')
    config["nut_password"] = value('NUT_PASSWORD')
if value('PIN'):
    config["pin"] = value('PIN')
    config["pin_attempts"] = 5
    config["pin_lockout_s"] = 300
if value('PLUG_HOST'):
    config["plug_host"] = value('PLUG_HOST')
    config["plug_password"] = value('PLUG_PASSWORD')
    config["plug_switch_id"] = number('PLUG_SWITCH_ID', 0)
    config["plug_poll_interval"] = 15
    config["plug_sample_interval"] = 60
    config["plug_min_request_gap"] = 1.0
if value('SENSOR_HOST'):
    config["sensor_host"] = value('SENSOR_HOST')
    config["sensor_password"] = value('SENSOR_PASSWORD')
if value('SENSOR_LISTEN'):
    config["sensor_listen"] = True
    config["sensor_listen_host"] = value('SENSOR_LISTEN_HOST') or '0.0.0.0'
    config["sensor_listen_port"] = number('SENSOR_PORT', 8088)

with open(sys.argv[1], "w") as handle:
    json.dump(config, handle, indent=2)
    handle.write("\n")
PYEOF
    # Readable by the daemon, and by nobody else: it holds passwords.
    chown root:"$SERVICE_USER" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    good "wrote $CONFIG_FILE (root:$SERVICE_USER, mode 640)"
}

install_service() {
    step "Installing the service"
    run install -m 644 "$SOURCE_DIR/deploy/upsmon.service" "$UNIT"
    run install -m 644 "$SOURCE_DIR/deploy/upsmon.logrotate" /etc/logrotate.d/upsmon
    local u
    for u in upsmon-web.path upsmon-web.service upsmon-upgrade.path upsmon-upgrade.service; do
        run install -m 644 "$SOURCE_DIR/deploy/$u" "/etc/systemd/system/$u"
    done
    run systemctl daemon-reload
    if [[ -z "$DRY_RUN" ]]; then
        systemctl enable upsmon >/dev/null 2>&1 || true
        systemctl enable --now upsmon-web.path upsmon-upgrade.path >/dev/null 2>&1 || true
    fi
    # The console when root signs in: on the first time, as otp has it.
    run install -m 644 "$SOURCE_DIR/deploy/upsmon-console-login.sh" "$CONSOLE_PROFILE"
    if [[ -z "$DRY_RUN" ]] && [[ ! -e "$CONSOLE_FLAG" ]]; then
        printf 'on\n' > "$CONSOLE_FLAG"
        chmod 644 "$CONSOLE_FLAG"
        note "root signing in lands in the upsmon console (q leaves it):"
        note "  upsmon --console-at-login off   to land in the shell instead"
    fi
    good "installed and enabled: upsmon, upsmon-web.path, upsmon-upgrade.path"
}

install_web() {
    [[ -n "$WITH_WEB" ]] || return 0
    step "Installing the pages"

    run install -d -m 755 "$WEB_DIR" "$WEB_DIR/settings" "$WEB_DIR/assets" "$WEB_DIR/lang"
    local file
    for file in index.php upsmon-api.php upsmon-page.php upsmon-lang.php settings-api.php acme.php \
                favicon.svg favicon.ico favicon-32.png apple-touch-icon.png settings/index.php; do
        [[ -f "$SOURCE_DIR/web/$file" ]] || continue
        run install -m 644 "$SOURCE_DIR/web/$file" "$WEB_DIR/$file"
    done
    for file in "$SOURCE_DIR"/web/assets/* "$SOURCE_DIR"/web/lang/*; do
        run install -m 644 "$file" "$WEB_DIR/${file#"$SOURCE_DIR/web/"}"
    done
    good "copied to $WEB_DIR (the dashboard, Settings, the languages)"

    # php-fpm: a pool of upsmon's own, as the account that may read the tokens.
    run install -m 644 "$SOURCE_DIR/deploy/php-fpm-upsmon.conf" "$POOL"
    run install -m 644 "$SOURCE_DIR/deploy/99-php2shell.ini" /etc/php.d/99-php2shell.ini
    if [[ -z "$DRY_RUN" ]]; then
        local unit
        for unit in $(php_fpm_units); do
            systemctl enable "$unit" >/dev/null 2>&1 || true
            systemctl restart "$unit" || fail "$unit did not start with $POOL"
        done
        good "php-fpm: the pool upsmon ($WEB_USER, /run/php-fpm/upsmon.sock)"
    fi
}

install_certificate() {
    [[ -n "$WITH_WEB" ]] || return 0
    step "TLS certificate"
    run install -d -m 755 "$CERT_DIR"

    # The standalone 3.x kept it as server.pem / server.key / server.ca: carried
    # over to the names Settings looks after, the old files left where they are.
    if [[ ! -f "$CERT_DIR/upsmon.pem" ]] && [[ -f "$CERT_DIR/server.pem" ]] \
       && [[ -f "$CERT_DIR/server.key" ]] && [[ -z "$CERT_FILE" ]]; then
        run install -m 644 "$CERT_DIR/server.pem" "$CERT_DIR/upsmon.pem"
        run install -m 600 "$CERT_DIR/server.key" "$CERT_DIR/upsmon.key"
        [[ -f "$CERT_DIR/server.ca" ]] && run install -m 644 "$CERT_DIR/server.ca" "$CERT_DIR/upsmon-ca.pem"
        good "the certificate of upsmon 3.x carried over (server.pem → upsmon.pem)"
        return
    fi

    if [[ -f "$CERT_DIR/upsmon.pem" ]] && [[ -z "$CERT_FILE" ]]; then
        good "a certificate is already in place; leaving it alone"
        return
    fi

    if [[ -n "$CERT_FILE" ]]; then
        check_certificate "$CERT_FILE" "$KEY_FILE" "$CA_FILE"
        if [[ -n "$CA_FILE" ]]; then
            run sh -c "cat '$CERT_FILE' '$CA_FILE' > '$CERT_DIR/upsmon.pem'"
            run install -m 644 "$CA_FILE" "$CERT_DIR/upsmon-ca.pem"
        else
            run install -m 644 "$CERT_FILE" "$CERT_DIR/upsmon.pem"
        fi
        run chmod 644 "$CERT_DIR/upsmon.pem"
        run install -m 600 "$KEY_FILE" "$CERT_DIR/upsmon.key"
        good "installed the certificate"
        return
    fi

    if [[ -n "$DRY_RUN" ]]; then
        note "[would make] a self-signed certificate for $SERVER_NAME"
        return
    fi

    local name=${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERT_DIR/upsmon.key" -out "$CERT_DIR/upsmon.pem" \
        -subj "/CN=$name" \
        -addext "subjectAltName=DNS:$name,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1 || fail "could not create a certificate"
    chmod 600 "$CERT_DIR/upsmon.key"
    chmod 644 "$CERT_DIR/upsmon.pem"
    good "made a self-signed certificate for $name"
    note "replace it on Settings → Certificates and TLS, or have ACME order one"
}

check_certificate() {
    # Whether these three files are actually a usable certificate.
    local cert=$1 key=$2 ca=${3:-}
    command -v openssl >/dev/null 2>&1 || { note "openssl is not here; not checking the certificate"; return 0; }

    openssl x509 -in "$cert" -noout >/dev/null 2>&1 \
        || fail "$cert is not a certificate openssl can read"

    # A key that does not belong to the certificate is the classic way to end
    # up with an nginx that refuses to start, so it is worth a moment here.
    local cert_key key_key
    cert_key=$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null | openssl md5)
    key_key=$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl md5) \
        || fail "$key is not a private key openssl can read"
    [[ "$cert_key" == "$key_key" ]] \
        || fail "$key is not the private key for $cert"

    local subject expiry
    subject=$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject= *//')
    expiry=$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')
    say "certificate for $subject"
    say "valid until $expiry"

    if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
        warn "this certificate has already expired"
    elif ! openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
        warn "it expires within the next 30 days"
    fi

    # nginx sends whatever is in ssl_certificate verbatim, so a certificate
    # without its issuer will fail to validate in some browsers even though it
    # is perfectly good.
    local count
    count=$(grep -c 'BEGIN CERTIFICATE' "$cert" 2>/dev/null || echo 0)
    if [[ $count -eq 1 ]] && [[ -z "$ca" ]]; then
        warn "the certificate has no issuer chain with it"
        note "  browsers may not trust it. Put the chain in certs/server.ca,"
        note "  or append it to the certificate file itself."
    elif [[ $count -gt 1 ]]; then
        say "the file already contains the chain ($count certificates)"
    fi

    if [[ -n "$SERVER_NAME" ]]; then
        local names
        names=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
                | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ')
        if [[ -n "$names" ]] && ! grep -qx "$SERVER_NAME" <<<"$names"; then
            # A wildcard covers one label, so *.example.net matches ups.example.net
            local wildcard="*.${SERVER_NAME#*.}"
            if ! grep -qxF "$wildcard" <<<"$names"; then
                warn "the certificate does not name $SERVER_NAME"
                note "  it names: $(tr '\n' ' ' <<<"$names")"
                note "  browsers will warn unless the hostname matches"
            fi
        fi
    fi
}

configure_nginx() {
    [[ -n "$WITH_WEB" ]] || return 0
    step "Configuring nginx"

    # One of 4.x is kept as it is: Settings writes its certificate and TLS into
    # it (and ACME its port 80). One of the standalone 3.x is written afresh,
    # its host name and its allow list kept.
    if [[ -f "$NGINX_CONF" ]] && grep -q 'location = /settings/' "$NGINX_CONF" && [[ -z "$REWRITE_NGINX" ]]; then
        good "$NGINX_CONF is upsmon 4's own and is kept (--rewrite-nginx writes it afresh)"
        if [[ -z "$DRY_RUN" ]]; then
            nginx -t >/dev/null 2>&1 && { systemctl enable nginx >/dev/null 2>&1 || true
                                          systemctl reload nginx 2>/dev/null || systemctl restart nginx; }
        fi
        return
    fi

    local name="$SERVER_NAME" nets="$ALLOW_NETS"
    if [[ -f "$NGINX_CONF" ]]; then
        [[ -z "$name" ]] && name=$(awk '$1 == "server_name" && $2 !~ /^_;?$/ {gsub(";","",$2); print $2; exit}' "$NGINX_CONF")
        if [[ -z "$nets" ]]; then
            nets=$(awk '$1 == "allow" {gsub(";","",$2); if ($2 != "127.0.0.1" && $2 != "::1") print $2}' \
                   "$NGINX_CONF" | sort -u | paste -sd, -)
        fi
        say "the nginx file of upsmon 3.x: ${name:-no name}, allowed: ${nets:-nothing}"
    fi
    name=${name:-$(hostname -f 2>/dev/null || hostname)}
    nets=${nets:-192.168.0.0/16,172.16.0.0/12,10.0.0.0/8}

    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $NGINX_CONF for $name, allowing $nets"
        return
    fi

    local allow='' one
    IFS=',' read -r -a list <<<"$nets"
    for one in "${list[@]}"; do
        one=$(tr -d ' ' <<<"$one")
        [[ $one =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] || fail "not an address or a network: $one"
        allow+="        allow $one;"$'\n'
    done
    local had=''
    if [[ -f "$NGINX_CONF" ]]; then
        had="$NGINX_CONF.before-4.0"
        cp -a "$NGINX_CONF" "$had"
        note "the old one is kept as $had"
    fi
    python3 - "$SOURCE_DIR/deploy/nginx-upsmon.conf" "$NGINX_CONF" "$name" "$allow" \
              "$([[ -f "$CERT_DIR/upsmon-ca.pem" ]] && echo yes)" <<'PYNGINX'
import re, sys
src, dst, name, allow, ca = sys.argv[1:6]
t = open(src).read()
t = t.replace('ups.example.local', name)
t = re.sub(r'        # ALLOW-BEGIN\n.*?        # ALLOW-END\n',
           '        # ALLOW-BEGIN\n' + allow + '        # ALLOW-END\n', t, flags=re.S)
if ca:
    t = t.replace('    ssl_certificate_key       /etc/nginx/certs/upsmon.key;\n',
                  '    ssl_certificate_key       /etc/nginx/certs/upsmon.key;\n'
                  '    ssl_trusted_certificate   /etc/nginx/certs/upsmon-ca.pem;\n')
open(dst, 'w').write(t)
PYNGINX
    chmod 644 "$NGINX_CONF"
    if [[ -n "$had" ]]; then mv "$had" "/etc/nginx/upsmon.conf.before-4.0"; had=/etc/nginx/upsmon.conf.before-4.0; fi

    if ! nginx -t >/dev/null 2>&1; then
        nginx -t || true
        if [[ -n "$had" ]]; then
            cp -a "$had" "$NGINX_CONF"
            fail "nginx rejected the new configuration; the old one is back in $NGINX_CONF"
        fi
        fail "nginx rejected the configuration; $NGINX_CONF is written but not loaded"
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
    good "serving $name over HTTPS: the dashboard at /, Settings at /settings/"
}

configure_selinux() {
    step "SELinux"
    if ! command -v getenforce >/dev/null 2>&1 || [[ $(getenforce) == Disabled ]]; then
        good "not enforcing; nothing to do"
        return
    fi
    say "$(getenforce)"

    if [[ -n "$WITH_WEB" ]]; then
        # PHP has to open a socket to the daemon's two localhost APIs.
        if [[ -n "$DRY_RUN" ]]; then
            note "[would run] setsebool -P httpd_can_network_connect 1"
            note "[would run] semanage fcontext -a -t httpd_sys_content_t \"$WEB_DIR(/.*)?\""
            note "[would run] restorecon -Rv $WEB_DIR $CERT_DIR"
            return
        fi
        setsebool -P httpd_can_network_connect 1
        semanage fcontext -a -t httpd_sys_content_t "$WEB_DIR(/.*)?" >/dev/null 2>&1 || true
        restorecon -R "$WEB_DIR" "$CERT_DIR" "$NGINX_CONF" >/dev/null 2>&1 || true
        good "allowed php to reach the local APIs, and labelled $WEB_DIR and the certificates"
    fi
}

configure_firewall() {
    step "Firewall"
    local opened=''

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        local rules=()
        [[ -n "$WITH_WEB" ]] && rules+=(--add-service=http --add-service=https) \
            && opened='80 and 443'
        [[ -n "$SENSOR_LISTEN" ]] && rules+=("--add-port=$SENSOR_PORT/tcp") \
            && opened="${opened:+$opened, }$SENSOR_PORT for sensor pushes"
        # Discovery needs inbound mDNS, which is dropped by default.
        rules+=(--add-service=mdns)
        if [[ -n "$DRY_RUN" ]]; then
            note "[would run] firewall-cmd --permanent ${rules[*]}"
            return
        fi
        local rule
        for rule in "${rules[@]}"; do
            firewall-cmd --permanent "$rule" >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null
        good "firewalld: opened ${opened:-nothing new}, and allowed mDNS"
        return
    fi

    if command -v iptables >/dev/null 2>&1; then
        warn "iptables is in use rather than firewalld, so nothing was changed"
        note "if the INPUT chain drops by default, you will need:"
        [[ -n "$WITH_WEB" ]] && \
        note "  iptables -I INPUT -p tcp --dport 443 -j ACCEPT"
        [[ -n "$SENSOR_LISTEN" ]] && \
        note "  iptables -I INPUT -p tcp --dport $SENSOR_PORT -j ACCEPT"
        note "  iptables -I INPUT -p udp --dport 5353 -j ACCEPT   # discovery"
        note "  iptables -I INPUT -p udp --sport 5353 -j ACCEPT"
        note "  service iptables save"
        return
    fi
    good "no firewall found running"
}

start_service() {
    step "Starting the daemon"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would start] upsmon"
        return
    fi
    systemctl restart upsmon
    sleep 4
    if systemctl is-active --quiet upsmon; then
        good "running: $(upsmon --version 2>/dev/null || echo upsmon)"
    else
        warn "it did not start; the last few lines of its log:"
        journalctl -u upsmon -n 15 --no-pager | sed 's/^/      /'
        fail "the daemon is not running"
    fi
}

verify() {
    step "Checking it works"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would run] upsmon --check"
        return
    fi
    if upsmon --check; then
        :
    else
        warn "some checks did not pass; see above"
    fi

    if [[ -n "$WITH_WEB" ]]; then
        local code
        code=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost/" 2>/dev/null || echo '000')
        if [[ $code == 200 ]]; then
            good "the dashboard answers over HTTPS"
        else
            warn "the dashboard answered $code over HTTPS on localhost"
            note "check: systemctl status nginx php-fpm"
        fi
        code=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost/settings/" 2>/dev/null || echo '000')
        if [[ $code == 200 ]]; then
            good "Settings answer over HTTPS"
        else
            warn "Settings answered $code over HTTPS on localhost"
        fi
    fi
}

first_account() {
    # Settings needs an account: one full administrator made the first time,
    # its password printed here and kept in $STATE_DIR/first-login.txt (the
    # daemon's alone) until it is changed on the pages.
    [[ -n "$DRY_RUN" ]] && { note "[would make] the account $ADMIN_USER of Settings"; return 0; }
    local n
    n=$(upsmon --users --json 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("users") or []))' 2>/dev/null || echo 0)
    if [[ "$n" != 0 ]]; then
        good "Settings has $n account(s) already"
        return 0
    fi
    step "The first account of Settings"
    local pw="$ADMIN_PASSWORD"
    [[ -n "$pw" ]] || pw=$(python3 -c 'import secrets, string; a = string.ascii_letters + string.digits; print("".join(secrets.choice(a) for _ in range(16)))')
    UPSMON_PASSWORD="$pw" upsmon --add-user "$ADMIN_USER" --role fulladmin \
        --note 'made by install.sh' >/dev/null || fail "the first account could not be made"
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        FIRST_PASSWORD=$pw
        ( umask 077
          printf 'name: %s\npassword: %s\n' "$ADMIN_USER" "$pw" > "$STATE_DIR/first-login.txt" )
        chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR/first-login.txt"
    fi
    good "made $ADMIN_USER, a full administrator"
}

summary() {
    step "Done"
    local name=${SERVER_NAME:-$(awk '$1 == "server_name" && $2 !~ /^_;?$/ {gsub(";","",$2); print $2; exit}' "$NGINX_CONF" 2>/dev/null)}
    say "Dashboard   https://${name:-localhost}/          (no sign-in)"
    say "Settings    https://${name:-localhost}/settings/ (accounts, certificates, upgrades)"
    if [[ -n "$FIRST_PASSWORD" ]]; then
        say "            sign in as $ADMIN_USER with the password ${C_WARN}$FIRST_PASSWORD${C_OFF}"
        note "            (also in $STATE_DIR/first-login.txt until it is changed)"
    fi
    say "Console     upsmon --console"
    say "Service     systemctl status upsmon"
    say "Log         journalctl -u upsmon -f    or  /var/log/upsmon/upsmon.log"
    say "Config      $CONFIG_FILE"
    say "Health      upsmon --check    and    upsmon --diag"
    if [[ -n "$PLUG_HOST" ]]; then
        say "Plug        upsmon --plug     and    upsmon shelly plug info"
    fi
    if [[ -n "$SENSOR_LISTEN" ]]; then
        echo
        note "The sensor has to be told where to push. Wake it with its button,"
        note "then create the webhook once:"
        note "  curl -X POST http://<sensor-ip>/rpc -H 'Content-Type: application/json' \\"
        note "    -d '{\"id\":1,\"method\":\"Webhook.Create\",\"params\":{\"cid\":0,"
        note "        \"enable\":true,\"event\":\"temperature.change\","
        note "        \"urls\":[\"http://$(hostname -I 2>/dev/null | awk '{print $1}'):$SENSOR_PORT/?t=\${ev.tC}\"]}}'"
        note "Then: upsmon --check | grep sensor"
    fi
    if [[ -n "$SELF_SIGNED" ]]; then
        echo
        note "The certificate is self-signed, so a browser will warn once."
        note "Replace it on Settings → Certificates and TLS, or let Automatic"
        note "certificates order one from Let's Encrypt."
    fi
}

# ---------------------------------------------------------------------------
# The other two modes
# ---------------------------------------------------------------------------
do_upgrade() {
    step "Upgrading"
    [[ -f "$LIB_DIR/upsmon.py" ]] || fail "upsmon is not installed here; run without --upgrade"
    local previous
    previous=$(sed -n "s/^__version__ = '\([0-9.]*\)'.*/\1/p" "$LIB_DIR/upsmon.py" 2>/dev/null || echo unknown)
    say "upsmon ${previous:-unknown} → $NEW_VERSION"
    if [[ "$previous" == 3.* ]]; then
        note "from the standalone 3.x: the dashboard stays as it was, Settings comes"
        note "beside it - the configuration, the history and the certificate are kept"
    fi
    [[ -d "$WEB_DIR" ]] || WITH_WEB=''

    install_packages
    create_user
    install_program
    install_service
    if [[ -n "$WITH_WEB" ]]; then
        install_web
        install_certificate
        configure_nginx
        configure_selinux
    fi
    start_service
    first_account
    say "was ${previous:-unknown}, now $(upsmon --version 2>/dev/null || echo unknown)"
    note "the configuration and the recorded history were not touched"
    if [[ -n "$FIRST_PASSWORD" ]]; then
        local name
        name=$(awk '$1 == "server_name" && $2 !~ /^_;?$/ {gsub(";","",$2); print $2; exit}' "$NGINX_CONF" 2>/dev/null)
        say "Settings    https://${name:-localhost}/settings/"
        say "            sign in as $ADMIN_USER with the password ${C_WARN}$FIRST_PASSWORD${C_OFF}"
        note "            (also in $STATE_DIR/first-login.txt until it is changed)"
    fi
}

do_uninstall() {
    step "Removing upsmon"
    if [[ -z "$ASSUME_YES" ]]; then
        confirm "Remove the service, the program and the pages?" \
            || { say "left alone"; exit 0; }
    fi

    run systemctl disable --now upsmon upsmon-web.path upsmon-upgrade.path 2>/dev/null || true
    run rm -f "$UNIT" /etc/logrotate.d/upsmon /etc/systemd/system/upsmon-web.path \
        /etc/systemd/system/upsmon-web.service /etc/systemd/system/upsmon-upgrade.path \
        /etc/systemd/system/upsmon-upgrade.service "$CONSOLE_PROFILE"
    run systemctl daemon-reload
    run rm -rf "$LIB_DIR" "$BIN"
    run rm -rf "$WEB_DIR"
    run rm -f "$NGINX_CONF" "$POOL"
    if [[ -z "$DRY_RUN" ]] && command -v nginx >/dev/null 2>&1; then
        nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
        systemctl restart php-fpm 2>/dev/null || true
    fi

    good "removed the service, the program and the pages"
    note "kept: $CONFIG_DIR, $STATE_DIR (the history, the accounts, the settings), /var/log/upsmon"
    note "kept: the accounts $SERVICE_USER and $WEB_USER, and the certificate in $CERT_DIR"
    note "to remove those too:"
    note "  sudo rm -rf $CONFIG_DIR $STATE_DIR /var/log/upsmon $CONSOLE_FLAG"
    note "  sudo userdel $WEB_USER; sudo userdel $SERVICE_USER"
}

# ---------------------------------------------------------------------------
main() {
    printf '%supsmon installer %s%s\n' "$C_HEAD" "$INSTALLER_VERSION" "$C_OFF"
    [[ -n "$DRY_RUN" ]] && warn "dry run: nothing will be changed"

    case $MODE in
        uninstall) [[ $EUID -eq 0 ]] || fail "run this with sudo"; do_uninstall; exit 0;;
        upgrade)   preflight; do_upgrade; exit 0;;
    esac

    preflight
    gather_answers
    install_packages
    create_user
    install_program
    write_config
    install_service
    install_web
    install_certificate
    configure_nginx
    configure_selinux
    configure_firewall
    start_service
    first_account
    verify
    summary
}

main "$@"
