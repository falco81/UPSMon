#!/bin/bash
#
# install.sh - set up upsmon on AlmaLinux 9, from packages to a working
# dashboard. Everything the manual walkthrough in INSTALL.md does, in order,
# and safe to run again: an existing configuration is kept, certificates are
# not overwritten, and the database is never touched.
#
#   sudo ./install.sh                       ask for what it needs
#   sudo ./install.sh --nut-host 10.0.0.5 --yes
#   sudo ./install.sh --upgrade             just the program files, then restart
#   sudo ./install.sh --uninstall           remove it, keeping the history
#
# Run --help for everything it accepts.

set -o errexit
set -o nounset
set -o pipefail

readonly INSTALLER_VERSION='1.2.1'
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly LIB_DIR=/usr/local/lib/upsmon
readonly BIN=/usr/local/bin/upsmon
readonly CONFIG_DIR=/etc/upsmon
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly WEB_DIR=/var/www/upsmon
readonly CERT_DIR=/etc/nginx/certs
readonly UNIT=/etc/systemd/system/upsmon.service
readonly SERVICE_USER=upsmon

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
        --yes|-y)          ASSUME_YES=yes; shift;;
        --dry-run)         DRY_RUN=yes; shift;;
        --upgrade)         MODE=upgrade; shift;;
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
    for file in upsmon.py deploy/upsmon.service deploy/upsmon.logrotate; do
        [[ -f "$SOURCE_DIR/$file" ]] || missing+=("$file")
    done
    if [[ -n "$WITH_WEB" ]]; then
        for file in web/index.php web/upsmon-api.php deploy/nginx-upsmon.conf; do
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
        upsmon.py
        deploy/upsmon.service
        deploy/upsmon.logrotate
        deploy/nginx-upsmon.conf
        deploy/config.json
        web/index.php
        web/upsmon-api.php
        web/favicon.svg  favicon.ico  favicon-32.png  apple-touch-icon.png
LAYOUT
        printf '\n    Copy the whole folder across and run it from inside:\n' >&2
        printf '      cd /path/to/upsmon && sudo ./install.sh\n' >&2
        printf '\n    Or point it at the files:\n' >&2
        printf '      sudo ./install.sh --source /path/to/upsmon\n\n' >&2
        exit 1
    fi

    python3 -m py_compile "$SOURCE_DIR/upsmon.py" 2>/dev/null \
        || fail "upsmon.py does not compile - is it complete?"
    rm -rf "$SOURCE_DIR/__pycache__" 2>/dev/null || true
    good "the files are all here and upsmon.py compiles"
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
    local wanted=(python3 policycoreutils-python-utils)
    [[ -n "$WITH_WEB" ]] && wanted+=(nginx php-fpm php-json)
    [[ -n "$SELF_SIGNED" ]] && wanted+=(openssl)

    local missing=()
    local package
    for package in "${wanted[@]}"; do
        rpm -q "$package" >/dev/null 2>&1 || missing+=("$package")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
        good "everything needed is already installed"
        return
    fi
    say "installing: ${missing[*]}"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would run] dnf install -y ${missing[*]}"
        return
    fi
    dnf install -y "${missing[@]}" >/dev/null || fail "package installation failed"
    good "installed"
}

create_user() {
    step "Creating the service user"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        good "user $SERVICE_USER already exists"
    else
        run useradd --system --home-dir /var/lib/upsmon --shell /sbin/nologin \
            --comment 'upsmon daemon' "$SERVICE_USER"
        good "created $SERVICE_USER"
    fi

    # PHP reads the API token, which only the upsmon group may read.
    if [[ -n "$WITH_WEB" ]] && id nginx >/dev/null 2>&1; then
        if id -nG nginx | tr ' ' '\n' | grep -qx "$SERVICE_USER"; then
            good "nginx is already in the $SERVICE_USER group"
        else
            run usermod -a -G "$SERVICE_USER" nginx
            good "added nginx to the $SERVICE_USER group"
        fi
    fi
}

install_program() {
    step "Installing the program"
    run install -d -m 755 "$LIB_DIR"
    run install -m 755 "$SOURCE_DIR/upsmon.py" "$LIB_DIR/upsmon.py"
    [[ -f "$SOURCE_DIR/INSTALL.md" ]] && run install -m 644 "$SOURCE_DIR/INSTALL.md" "$LIB_DIR/INSTALL.md"

    if [[ -z "$DRY_RUN" ]]; then
        cat > "$BIN" <<EOF
#!/bin/sh
# upsmon - installed by install.sh $INSTALLER_VERSION
exec /usr/bin/python3 $LIB_DIR/upsmon.py "\$@"
EOF
        chmod 755 "$BIN"
    else
        note "[would write] $BIN"
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
    run systemctl daemon-reload
    if [[ -z "$DRY_RUN" ]]; then
        systemctl enable upsmon >/dev/null 2>&1 || true
    fi
    good "installed and enabled"
}

install_web() {
    [[ -n "$WITH_WEB" ]] || return 0
    step "Installing the dashboard"

    run install -d -m 755 "$WEB_DIR"
    local file
    for file in index.php upsmon-api.php favicon.svg favicon.ico favicon-32.png \
                apple-touch-icon.png; do
        [[ -f "$SOURCE_DIR/web/$file" ]] || continue
        run install -m 644 "$SOURCE_DIR/web/$file" "$WEB_DIR/$file"
    done
    good "copied to $WEB_DIR"

    # php-fpm serves it over a socket nginx can reach; the default pool runs as
    # apache, which is not in the upsmon group and so cannot read the token.
    if [[ -f /etc/php-fpm.d/www.conf ]] && [[ -z "$DRY_RUN" ]]; then
        if grep -q '^user = apache' /etc/php-fpm.d/www.conf; then
            cp -a /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf.bak
            sed -i 's/^user = apache/user = nginx/; s/^group = apache/group = nginx/' \
                /etc/php-fpm.d/www.conf
            sed -i 's/^listen.acl_users = apache,nginx/listen.acl_users = nginx/' \
                /etc/php-fpm.d/www.conf
            good "php-fpm now runs as nginx (the original is kept as www.conf.bak)"
        else
            good "php-fpm is already running as nginx"
        fi
    fi
    if [[ -z "$DRY_RUN" ]]; then
        systemctl enable --now php-fpm >/dev/null 2>&1 || true
    fi
}

install_certificate() {
    [[ -n "$WITH_WEB" ]] || return 0
    step "TLS certificate"
    run install -d -m 700 "$CERT_DIR"

    if [[ -f "$CERT_DIR/server.pem" ]] && [[ -z "$CERT_FILE" ]]; then
        good "a certificate is already in place; leaving it alone"
        return
    fi

    if [[ -n "$CERT_FILE" ]]; then
        check_certificate "$CERT_FILE" "$KEY_FILE" "$CA_FILE"
        run install -m 644 "$CERT_FILE" "$CERT_DIR/server.pem"
        run install -m 600 "$KEY_FILE" "$CERT_DIR/server.key"
        [[ -n "$CA_FILE" ]] && run install -m 644 "$CA_FILE" "$CERT_DIR/server.ca"
        good "installed the certificate"
        return
    fi

    if [[ -n "$DRY_RUN" ]]; then
        note "[would make] a self-signed certificate for $SERVER_NAME"
        return
    fi

    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.pem" \
        -subj "/CN=$SERVER_NAME" \
        -addext "subjectAltName=DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1 || fail "could not create a certificate"
    chmod 600 "$CERT_DIR/server.key"
    chmod 644 "$CERT_DIR/server.pem"
    good "made a self-signed certificate for $SERVER_NAME"
    note "browsers will warn about it until you replace it with a real one"
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

    local target=/etc/nginx/conf.d/upsmon.conf
    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $target for $SERVER_NAME"
        return
    fi

    sed "s/ups\.falco81\.net/$SERVER_NAME/g" \
        "$SOURCE_DIR/deploy/nginx-upsmon.conf" > "$target"
    chmod 644 "$target"

    if ! nginx -t >/dev/null 2>&1; then
        nginx -t || true
        fail "nginx rejected the configuration; $target is written but not loaded"
    fi
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
    good "serving $SERVER_NAME over HTTPS"
}

configure_selinux() {
    step "SELinux"
    if ! command -v getenforce >/dev/null 2>&1 || [[ $(getenforce) == Disabled ]]; then
        good "not enforcing; nothing to do"
        return
    fi
    say "$(getenforce)"

    if [[ -n "$WITH_WEB" ]]; then
        # PHP has to open a socket to the daemon's localhost API.
        if [[ -n "$DRY_RUN" ]]; then
            note "[would run] setsebool -P httpd_can_network_connect 1"
            note "[would run] semanage fcontext -a -t httpd_sys_content_t \"$WEB_DIR(/.*)?\""
            note "[would run] restorecon -Rv $WEB_DIR"
            return
        fi
        setsebool -P httpd_can_network_connect 1
        semanage fcontext -a -t httpd_sys_content_t "$WEB_DIR(/.*)?" >/dev/null 2>&1 || true
        restorecon -Rv "$WEB_DIR" >/dev/null 2>&1 || true
        good "allowed php to reach the local API, and labelled $WEB_DIR"
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
    fi
}

summary() {
    step "Done"
    say "Dashboard   https://$SERVER_NAME/"
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
        note "Replace it later with: sudo ./install.sh --cert FILE --key FILE"
    fi
}

# ---------------------------------------------------------------------------
# The other two modes
# ---------------------------------------------------------------------------
do_upgrade() {
    step "Upgrading"
    [[ -f "$LIB_DIR/upsmon.py" ]] || fail "upsmon is not installed here; run without --upgrade"
    local previous
    previous=$(upsmon --version 2>/dev/null || echo unknown)

    install_program
    if [[ -n "$WITH_WEB" ]] && [[ -d "$WEB_DIR" ]]; then
        install_web
        [[ -z "$DRY_RUN" ]] && restorecon -Rv "$WEB_DIR" >/dev/null 2>&1 || true
    fi
    run install -m 644 "$SOURCE_DIR/deploy/upsmon.service" "$UNIT"
    run install -m 644 "$SOURCE_DIR/deploy/upsmon.logrotate" /etc/logrotate.d/upsmon
    run systemctl daemon-reload
    start_service
    say "was $previous, now $(upsmon --version 2>/dev/null || echo unknown)"
    note "the configuration and the recorded history were not touched"
}

do_uninstall() {
    step "Removing upsmon"
    if [[ -z "$ASSUME_YES" ]]; then
        confirm "Remove the service, the program and the dashboard?" \
            || { say "left alone"; exit 0; }
    fi

    run systemctl disable --now upsmon 2>/dev/null || true
    run rm -f "$UNIT" /etc/logrotate.d/upsmon
    run systemctl daemon-reload
    run rm -rf "$LIB_DIR" "$BIN"
    run rm -rf "$WEB_DIR"
    run rm -f /etc/nginx/conf.d/upsmon.conf
    if [[ -z "$DRY_RUN" ]] && command -v nginx >/dev/null 2>&1; then
        nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
    fi

    good "removed the service, the program and the dashboard"
    note "kept: $CONFIG_DIR, /var/lib/upsmon (the history), /var/log/upsmon"
    note "kept: the $SERVICE_USER account, and the certificate in $CERT_DIR"
    note "to remove those too:"
    note "  sudo rm -rf $CONFIG_DIR /var/lib/upsmon /var/log/upsmon"
    note "  sudo userdel $SERVICE_USER"
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
    verify
    summary
}

main "$@"
