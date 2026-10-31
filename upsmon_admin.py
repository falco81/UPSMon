# -*- coding: utf-8 -*-
"""
upsmon_admin.py - the Settings side of upsmon, built on the engine of upsmon.

upsmon.py watches the UPS and draws the dashboard, which anybody on the
allowed networks may look at without signing in. This module is everything
behind Settings, which may not be reached without an account:

  * accounts of the settings pages: roles, passwords, sign-ins, lockouts,
    the columns of every table laid out per person;
  * certificates and TLS of the web server (uploaded, PFX, a request made
    here, self-signed), the protocols and ciphers - put in by root;
  * automatic certificates by ACME (Let's Encrypt or another CA, HTTP-01 or
    DNS-01), renewed by themselves;
  * new versions of upsmon: a signed package sent from the pages or found
    on the web (GitHub), checked and put in by root;
  * About: the version, what it runs on, the language, the console at login.

It is upsmon's code - the same API, the same pages, the same checks - on one
server (upsmon never runs as a cluster) and SQLite only. upsmon.py starts
it in its own threads; the PHP pages of /settings/ relay to it over
127.0.0.1 with the API token from /run/upsmon.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import ftplib
import getpass
import hashlib
import hmac
import html
import ipaddress
import json
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import io
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Bumped with upsmon.py: the two are one version.
__version__ = '4.1.11'
# The oldest version this one may go back to (Settings → Upgrades): 4.0.0 is
# the first with these pages, the database and the signed packages.
DOWNGRADE_FLOOR = '4.0.0'

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CONFIG_FILE = Path(os.environ.get('UPSMON_CONFIG', '/etc/upsmon/config.json'))
STATE_DIR = Path(os.environ.get('UPSMON_STATE', '/var/lib/upsmon'))
DB_FILE = STATE_DIR / 'upsmon.db'
RUN_DIR = Path(os.environ.get('UPSMON_RUN', '/run/upsmon'))
TOKEN_FILE = RUN_DIR / 'admin-token'
LOG_DIR = Path(os.environ.get('UPSMON_LOGDIR', '/var/log/upsmon'))
LOG_NAME = 'upsmon.log'
LIB_DIR = Path(os.environ.get('UPSMON_LIB', str(Path(__file__).resolve().parent)))
SERVICE_USER = 'upsmon'
WEB_GROUP = 'upsmon'
CONSOLE_FLAG = Path(os.environ.get('UPSMON_CONSOLE_FLAG', '/etc/upsmon-console-login'))

# Who may do what on the settings pages: a full administrator changes
# everything; read only looks and changes nothing.
ROLES_ALL = ('fulladmin', 'readonly')
ROLE_WORDS = {'fulladmin': 'full admin', 'readonly': 'read only'}

DEFAULTS = {'site_name': '',
 'ui_lang': 'cs',
 'debug': False,
 'debug_api': 0,
 'session_hours': 12,
 'session_idle_min': 120,
 'login_tries': 5,
 'login_wait_min': 15,
 'upgrade_check': 1,
 'upgrade_url': 'https://github.com/falco81/UPSMon/tree/main/release',
 'upgrade_downgrade': 0,
 'proxy': 0,
 'proxy_url': '',
 'proxy_user': '',
 'proxy_password': '',
 'proxy_no': 'localhost, 127.0.0.1, ::1',
 'proxy_os': 1,
 'proxy_sms': 1,
  'acme': 0,
 'acme_email': '',
 'acme_ca': 'letsencrypt',
 'acme_url': '',
 'acme_ca_pem': '',
 'acme_for': 'node',
 'acme_node_name': '',
 'acme_days': 30,
 'acme_key': 'dual',
 'acme_account_key': 'ec',
 'acme_challenge': 'http-01',
 'acme_dns': 'manual',
 'acme_dns_server': '',
 'acme_dns_zone': '',
 'acme_dns_tsig_name': '',
 'acme_dns_tsig_alg': 'hmac-sha256',
 'acme_dns_tsig_secret': '',
 'acme_dns_token': '',
 'acme_dns_url': '',
 'acme_dns_user': '',
 'acme_dns_key': '',
 'acme_dns_subdomain': '',
 'acme_desec_domain': '',
 'acme_desec_token': '',
 'acme_dns_alias': '',
 'acme_dns_wait': 30,
 'acme_resolvers': ''}

NAMES = {'site_name': 'What to call this installation',
 'ui_lang': 'Language of the pages',
 'debug': 'Debug log',
 'debug_api': '...every API call',
 'session_hours': 'A sign-in lasts (h)',
 'session_idle_min': '...and may sit untouched (min)',
 'login_tries': 'Wrong passwords before a pause',
 'login_wait_min': '...and the pause (min)',
 'upgrade_check': 'Look for a new version every day',
 'upgrade_url': 'Where new versions are looked for',
 'upgrade_downgrade': 'Offer going back to an older version',
 'proxy': 'Go out through a proxy',
 'proxy_url': 'The proxy',
 'proxy_user': 'User name at the proxy',
 'proxy_password': 'Password at the proxy',
 'proxy_no': 'Straight, not through the proxy',
 'proxy_os': 'The system updates through it too',
 'proxy_sms': 'The SMS gateway through it too',
 'acme': 'Certificates from an ACME CA',
 'acme_email': 'Mail of the account at the CA',
 'acme_ca': 'The CA',
 'acme_url': 'Its ACME directory',
 'acme_ca_pem': 'The CA’s own certificate',
 'acme_for': 'For',
 'acme_node_name': 'The node’s DNS name',
 'acme_days': 'Renewed when fewer days are left than',
 'acme_key': 'The key of the certificate',
 'acme_account_key': 'The key of the ACME account',
 'acme_challenge': 'How the CA checks the name',
 'acme_dns': 'Who puts the TXT record in DNS',
 'acme_dns_server': 'The DNS server taking the updates',
 'acme_dns_zone': 'The zone',
 'acme_dns_tsig_name': 'The name of the TSIG key',
 'acme_dns_tsig_alg': 'Its algorithm',
 'acme_dns_tsig_secret': 'The TSIG secret',
 'acme_dns_token': 'The Cloudflare API token',
 'acme_dns_url': 'The acme-dns server',
 'acme_dns_user': 'acme-dns user',
 'acme_dns_key': 'acme-dns key',
 'acme_dns_subdomain': 'acme-dns subdomain',
 'acme_desec_domain': 'The domain at deSEC',
 'acme_desec_token': 'The deSEC API token',
 'acme_dns_alias': 'The TXT records go into',
 'acme_dns_wait': 'Wait for DNS to carry it (s)',
 'acme_resolvers': 'DNS servers for ACME'}

SAYS = {'site_name': 'The name at the top of the administration pages. Empty: the machine’s own name.',
 'ui_lang': 'The language every page opens in until somebody chooses another for themselves.',
 'debug': 'Write everything into <code>/var/log/upsmon/upsmon.log</code>. Loud: for finding something '
          'out, not for leaving on.',
 'debug_api': 'Every API call the web pages make.',
 'session_hours': 'How long an administrator stays signed in, however busy.',
 'session_idle_min': 'How long a sign-in may sit without anything being asked before it has to be '
                     'done again.',
 'login_tries': 'Wrong passwords from one address before it has to wait.',
 'login_wait_min': 'How long it waits.',
 'upgrade_check': 'Once a day (and when Look now is pressed) the address below is asked for '
                  'upsmon-X.Y.Z.tar.gz packages; a newer one than runs here is offered on this page - '
                  'put in with one click, after its signature has been checked like any package '
                  'sent by hand. Nothing is put in by itself.',
 'upgrade_url': 'A GitHub folder (<code>https://github.com/OWNER/REPO/tree/BRANCH/FOLDER</code>), '
                "a web page or folder listing that links to the packages, or one package's own "
                "address. HTTPS only; a proxy is taken from https_proxy in the service's "
                'environment.',
 'upgrade_downgrade': 'Off: nothing on these pages offers going back to an older version. On: '
                      'Settings → Upgrades shows <i>Going back to an older version</i> - only the '
                      'versions it is safe to go back to, each with what changed in it. On the '
                      'server, root can always: upsmon --downgrade.',
 'proxy': 'An HTTP proxy for what upsmon asks of the web: the new versions, the SMS gateway, the '
          'system updates. Mail, Active Directory, the database and syslog never use it.',
 'proxy_url': '<code>http://proxy.example.cz:3128</code>',
 'proxy_user': 'Where the proxy asks for one. Empty: none.',
 'proxy_password': 'Kept sealed, like the other passwords.',
 'proxy_no': 'Names and addresses reached without it, separated by commas: '
             '<code>.example.cz</code> is every name under it, <code>10.0.0.0/8</code> a net.',
 'proxy_os': 'dnf or apt fetch the updates of System → Updates through it.',
 'proxy_sms': 'The HTTP SMS gateway asked through it.',
 'acme': 'The certificates ordered from the CA by HTTP-01 and renewed by themselves - port 80 of '
         'the name must reach a node. In a cluster the answer is kept in the database, so '
         'whichever node has the VIP address gives it. Off until switched on.',
 'acme_email': 'Where the CA writes when a certificate runs out unrenewed. Empty: none.',
 'acme_ca': 'Let’s Encrypt, its staging (certificates browsers do not trust - to try it), or '
            'another.',
 'acme_url': 'The directory of another ACME CA, '
             '<code>https://ca.example.cz/acme/acme/directory</code>.',
 'acme_ca_pem': 'The CA’s root (PEM), where the system does not trust it already.',
 'acme_for': 'Which certificates are ordered.',
 'acme_node_name': 'The name a node’s own certificate is for - each node its own, the others’ '
                   'under the box. Empty: the name of the certificate it has now, else its full '
                   'host name. The VIP address’s: <i>Its name…</i> on its card above.',
 'acme_days': 'Let’s Encrypt’s certificates last 90 days; 30 is what it advises.',
 'acme_key': 'Let’s Encrypt takes RSA keys of 2048, 3072 or 4096 bits and ECDSA keys on P-256 or P-384. '
             'Both - what Let’s Encrypt advises - orders two certificates for the name: RSA served by default, '
             'the much smaller ECDSA one to the clients that say they take it.',
 'acme_account_key': 'The key the account with the CA signs with - never one of a certificate. '
                     'RSA 2048, 3072, 4096 or ECDSA P-256, P-384. A change makes a new account at the next order.',
 'acme_challenge': 'HTTP-01 needs port 80 of the name reachable from the internet (or from the CA, '
                   'for a CA of your own). DNS-01 needs nothing open: the CA reads a TXT record.',
 'acme_dns': 'By hand the order waits up to an hour for you; the others renew by themselves.',
 'acme_dns_server': 'The primary DNS server of the zone, <code>ns1.example.cz</code> or with a '
                    'port <code>10.0.0.53:53</code>.',
 'acme_dns_zone': 'Where the record goes, <code>example.cz</code>. Empty: as the server finds it.',
 'acme_dns_tsig_name': 'As the DNS server knows it, <code>upsmon-acme.</code>; allowed to update '
                       '_acme-challenge records only.',
 'acme_dns_tsig_alg': 'As the key was made (tsig-keygen makes hmac-sha256).',
 'acme_dns_tsig_secret': 'The key’s secret (base64). Kept sealed; written to a file only upsmon reads '
                         'for the moment nsupdate runs.',
 'acme_dns_token': 'A token with Zone - DNS - Edit for the zone. Kept sealed.',
 'acme_dns_url': '<code>https://auth.acme-dns.example.cz</code>; _acme-challenge.NAME is a CNAME '
                 'to the subdomain below.',
 'acme_dns_user': 'From the registration at acme-dns.',
 'acme_dns_key': 'From the registration at acme-dns. Kept sealed.',
 'acme_dns_subdomain': 'From the registration at acme-dns.',
 'acme_desec_domain': 'Your domain at deSEC, <code>example.dedyn.io</code> (free) or one of your '
                      'own whose DNS is there. The records go into it; your DNS has a CNAME to it '
                      'for each name - <i>In your DNS</i> above says which.',
 'acme_desec_token': 'A token from deSEC (Token management) - one that may change this domain’s '
                     'records. Kept sealed.',
 'acme_dns_alias': 'A zone the records go into instead of the name’s own '
                   '(<code>acme.example.net</code>), each name with a CNAME to it in your DNS - '
                   '<i>In your DNS</i> above says which. Empty: _acme-challenge.NAME itself.',
 'acme_dns_wait': 'How long the record is given to reach every DNS server before the CA is asked.',
 'acme_resolvers': 'The DNS servers asked for everything on this page: the address of the CA and '
                   'of the DNS API, <i>Check DNS</i>, <i>Try port 80</i>, and whether the TXT '
                   'record can be seen before the CA is asked - <code>1.1.1.1, 9.9.9.9</code> to '
                   'see what the internet sees. Empty: the machine’s own (/etc/resolv.conf).'}

SAYS_SHORT = {}

TUNABLE = {'ui_lang': ('cs', 'en'),
 'debug_api': (0, 1),
 'session_hours': (1, 168),
 'session_idle_min': (5, 1440),
 'login_tries': (1, 100),
 'login_wait_min': (1, 1440),
 'upgrade_check': (0, 1),
 'upgrade_downgrade': (0, 1),
 'proxy': (0, 1),
 'proxy_os': (0, 1),
 'proxy_sms': (0, 1),
 'acme': (0, 1),
 'acme_ca': ('letsencrypt', 'letsencrypt-staging', 'custom'),
 'acme_for': ('vip', 'node', 'both'),
 'acme_days': (7, 60),
 'acme_key': ('dual', 'dual-strong', 'ec', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'),
 'acme_account_key': ('ec', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'),
 'acme_challenge': ('http-01', 'dns-01'),
 'acme_dns': ('manual', 'rfc2136', 'cloudflare', 'acmedns', 'desec'),
 'acme_dns_tsig_alg': ('hmac-sha256',
                       'hmac-sha512',
                       'hmac-sha384',
                       'hmac-sha224',
                       'hmac-sha1',
                       'hmac-md5'),
 'acme_dns_wait': (0, 600)}

CHOICE_WORDS = {'ui_lang': {'cs': 'Čeština', 'en': 'English'},
 'acme_ca': {'letsencrypt': 'Let’s Encrypt',
             'letsencrypt-staging': 'Let’s Encrypt - staging (to try it)',
             'custom': 'another ACME CA (step-ca, an internal CA...)'},
 'acme_for': {'vip': 'the VIP address (or this node, where there is none)',
              'node': 'each node’s own name',
              'both': 'the VIP address and each node'},
 'acme_key': {'dual': 'Both: RSA 2048 + ECDSA P-256 (advised)',
              'dual-strong': 'Both: RSA 4096 + ECDSA P-384',
              'ec': 'ECDSA P-256', 'ec384': 'ECDSA P-384',
              'rsa2048': 'RSA 2048', 'rsa3072': 'RSA 3072', 'rsa4096': 'RSA 4096'},
 'acme_account_key': {'ec': 'ECDSA P-256 (ES256)', 'ec384': 'ECDSA P-384 (ES384)',
                      'rsa2048': 'RSA 2048 (RS256)', 'rsa3072': 'RSA 3072 (RS256)',
                      'rsa4096': 'RSA 4096 (RS256)'},
 'acme_challenge': {'http-01': 'HTTP-01 - the CA asks port 80 of the name',
                    'dns-01': 'DNS-01 - a TXT record in DNS (no port open to the internet)'},
 'acme_dns': {'manual': 'by hand - the record is shown here, you put it in',
              'rfc2136': 'RFC 2136 dynamic update with a TSIG key (BIND, PowerDNS, Knot...)',
              'cloudflare': 'Cloudflare, with an API token',
              'acmedns': 'an acme-dns server',
              'desec': 'deSEC.io (free), with an API token - a CNAME in your DNS'}}

ONLY_WHEN = {'proxy_url': ['proxy', '1'],
 'proxy_user': ['proxy', '1'],
 'proxy_password': ['proxy', '1'],
 'proxy_no': ['proxy', '1'],
 'proxy_os': ['proxy', '1'],
 'proxy_sms': ['proxy', '1'],
 'acme_for': ['acme', '1'],
 'acme_email': ['acme', '1'],
 'acme_ca': ['acme', '1'],
 'acme_url': ['acme_ca', 'custom'],
 'acme_ca_pem': ['acme_ca', 'custom'],
 'acme_node_name': ['acme_for', 'vip-not'],
 'acme_days': ['acme', '1'],
 'acme_key': ['acme', '1'],
 'acme_account_key': ['acme', '1'],
 'acme_challenge': ['acme', '1'],
 'acme_dns': ['acme_challenge', 'dns-01'],
 'acme_dns_wait': ['acme_challenge', 'dns-01'],
 'acme_dns_server': ['acme_dns', 'rfc2136'],
 'acme_dns_zone': ['acme_dns', 'rfc2136'],
 'acme_dns_tsig_name': ['acme_dns', 'rfc2136'],
 'acme_dns_tsig_alg': ['acme_dns', 'rfc2136'],
 'acme_dns_tsig_secret': ['acme_dns', 'rfc2136'],
 'acme_dns_token': ['acme_dns', 'cloudflare'],
 'acme_dns_url': ['acme_dns', 'acmedns'],
 'acme_dns_user': ['acme_dns', 'acmedns'],
 'acme_dns_key': ['acme_dns', 'acmedns'],
 'acme_dns_subdomain': ['acme_dns', 'acmedns'],
 'acme_desec_domain': ['acme_dns', 'desec'],
 'acme_desec_token': ['acme_dns', 'desec'],
 'acme_dns_alias': ['acme_dns', 'acmedns-not'],
 'acme_resolvers': ['acme', '1'],
 'debug_api': ['debug', '1']}



DEFAULTS['admin_port'] = 9849
TUNABLE['admin_port'] = (1024, 65535)
NAMES['admin_port'] = 'The port of the settings API'
SAYS['admin_port'] = ('The port on 127.0.0.1 the settings pages ask this daemon on. The pages read '
                    'it from <code>/run/upsmon/admin-port</code>, written when the daemon starts.')
SAYS['debug'] = 'Write everything into <code>/var/log/upsmon/upsmon.log</code>. Loud: for finding something out, not for leaving on.'
SAYS['site_name'] = 'The name at the top of the settings pages. Empty: the machine’s own name.'
SAYS['acme'] = ('The certificate of this server ordered from the CA and renewed by itself - by HTTP-01 '
                '(port 80 of the name must reach this server) or DNS-01. Off until switched on.')
SAYS['acme_node_name'] = ('The name the certificate is for. Empty: the name of the certificate it has '
                          'now, else the full host name of this machine.')
SAYS['upgrade_check'] = ('Once a day (and when Look now is pressed) the address below is asked for '
                         'upsmon-X.Y.Z.tar.gz packages; a newer one than runs here is offered on this page - '
                         'put in with one click, after its signature has been checked like any package '
                         'sent by hand. Nothing is put in by itself.')
SAYS['upgrade_downgrade'] = ('Off: nothing on these pages offers going back to an older version. On: '
                             'Settings → Upgrades shows <i>Going back to an older version</i> - only the '
                             'versions it is safe to go back to, each with what changed in it. On the '
                             'server, root can always: upsmon --downgrade.')
SAYS['proxy'] = ('An HTTP proxy for what upsmon asks of the web: the new versions and the CA of the '
                 'automatic certificates. The UPS, the plug and the sensors never use it.')
SAYS['acme_dns_tsig_name'] = ('As the DNS server knows it, <code>upsmon-acme.</code>; allowed to update '
                              '_acme-challenge records only.')
SAYS['acme_dns_tsig_secret'] = ('The key’s secret (base64). Kept sealed; written to a file only upsmon reads '
                                'for the moment nsupdate runs.')
for _k in ('proxy_sms', 'proxy_os'):
    DEFAULTS.pop(_k, None); NAMES.pop(_k, None); SAYS.pop(_k, None); TUNABLE.pop(_k, None)
    ONLY_WHEN.pop(_k, None)
TUNABLE['acme_for'] = ('node',)
CHOICE_WORDS['acme_for'] = {'node': 'this server'}
ONLY_WHEN['acme_node_name'] = ['acme', '1']
NAMES['acme_node_name'] = 'The name of the certificate'

SAYS_SHORT = {}
SECRET_KEYS = ('proxy_password', 'acme_dns_tsig_secret', 'acme_dns_token', 'acme_dns_key',
               'acme_desec_token')
SEALED_KEYS = SECRET_KEYS
FILE_ONLY_KEYS = ()
NODE_KEYS = ()
DB_KEYS = ()

# Which settings sit on which page of Settings, in order.
PANES = {
    'people': ['session_hours', 'session_idle_min', 'login_tries', 'login_wait_min'],
    'acme': ['acme', 'acme_email', 'acme_ca', 'acme_url', 'acme_ca_pem',
             'acme_node_name', 'acme_days', 'acme_key', 'acme_account_key', 'acme_challenge', 'acme_dns',
             'acme_dns_server', 'acme_dns_zone', 'acme_dns_tsig_name', 'acme_dns_tsig_alg',
             'acme_dns_tsig_secret', 'acme_dns_token', 'acme_dns_url', 'acme_dns_user',
             'acme_dns_key', 'acme_dns_subdomain', 'acme_desec_domain', 'acme_desec_token',
             'acme_dns_alias', 'acme_dns_wait', 'acme_resolvers'],
    'upgrade': ['upgrade_check', 'upgrade_url', 'upgrade_downgrade', 'proxy', 'proxy_url',
                'proxy_user', 'proxy_password', 'proxy_no'],
    'about': ['site_name', 'ui_lang', 'admin_port', 'debug', 'debug_api'],
}
HIDDEN_KEYS = ('acme_for',)

# ---- the settings of The database, Backups, System updates, Restart and power off (4.1)
DEFAULTS.update({'backup_daily': 1,
 'backup_keep': 14,
 'backup_at': '03:30',
 'rbackup': 0,
 'rbackup_at': '04:15',
 'rbackup_every': 'daily',
 'rbackup_day': 7,
 'rbackup_keep': 30,
 'rbackup_keep_days': 0,
 'rbackup_password': '',
 'rbackup_verify': 'off',
 'osup_check': 0,
 'osup_check_at': '06:15',
 'osup_auto': 0,
 'osup_auto_what': 'security',
 'osup_auto_every': 'weekly',
 'osup_auto_day': '7',
 'osup_auto_at': '04:45',
 'osup_auto_reboot': 'auto',
 'power_auto': 0,
 'power_auto_every': 'weekly',
 'power_auto_day': '7',
 'power_auto_at': '05:40',
 'power_auto_needed': 1})

NAMES.update({'backup_daily': 'A copy of the database every day',
 'backup_keep': 'Copies kept',
 'backup_at': 'At',
 'rbackup': 'Backups to the destinations on a schedule',
 'rbackup_at': 'At',
 'rbackup_every': 'How often',
 'rbackup_day': 'On (1 Monday - 7 Sunday)',
 'rbackup_keep': 'Backups kept at each destination',
 'rbackup_keep_days': 'And none older than (days)',
 'rbackup_password': 'The password of the backups',
 'rbackup_verify': 'Try the backups',
 'osup_check': 'Look for updates every day',
 'osup_check_at': 'At',
 'osup_auto': 'Updates on a schedule',
 'osup_auto_what': 'Which',
 'osup_auto_every': 'How often',
 'osup_auto_day': 'On the day',
 'osup_auto_at': 'At',
 'osup_auto_reboot': 'After the update',
 'power_auto': 'A restart on a schedule',
 'power_auto_every': 'How often',
 'power_auto_day': 'On the day',
 'power_auto_at': 'At',
 'power_auto_needed': 'Only the nodes that need one'})

SAYS.update({'backup_daily': 'A copy of the database once a day, into <code>/var/lib/upsmon/backups</code>, with '
                 'the key that opens the tokens beside it.',
 'backup_keep': 'How many of those copies are kept; the oldest goes first.',
 'backup_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
 'rbackup': 'Each node makes its backup and sends it to every destination switched on, at the time '
            'below. Without it, only Back up now sends one.',
 'rbackup_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
 'rbackup_every': 'daily, or weekly on the day below.',
 'rbackup_day': 'The day of a weekly backup: 1 is Monday, 7 Sunday.',
 'rbackup_keep': 'How many of this node’s backups each destination keeps; the oldest go first, the '
                 'newest never.',
 'rbackup_keep_days': 'Older ones are taken away too - 0: only the count above decides.',
 'rbackup_password': 'Every backup is locked with it (AES-256, opened with upsmon or with openssl '
                     'alone). Keep it apart from the backups as well - in a password vault: '
                     'without it nobody, you included, opens them. Empty: the backups are not '
                     'locked, and anybody with one has every token.',
 'rbackup_verify': 'The newest backup fetched back, opened with the password, every file checked, '
                   'the database read through and the tokens tried against the key in it - nothing '
                   'is put back. After every backup, or once a week.',
 'osup_check': 'Each node looks what dnf (or apt) has waiting, every day at the time below - for '
               'the cards here, the alerts and the report. Nothing is put in.',
 'osup_check_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
 'osup_auto': 'The updates put in by themselves in the window below, one node at a time as by hand '
              '- each out of service while it is updated, the VIP address on the other. Off until '
              'switched on.',
 'osup_auto_what': 'Only the security updates (dnf --security, unattended-upgrade on apt), or '
                   'every update.',
 'osup_auto_every': 'A day, a week or a month.',
 'osup_auto_day': 'The day a weekly update goes.',
 'osup_auto_at': 'When, as <code>HH:MM</code> - a quiet hour, away from the backups.',
 'osup_auto_reboot': 'A node that needs a restart after the update - restarted by itself, one '
                     'after the other, or offered on the page.',
 'power_auto': 'The nodes restarted in the window below, one after the other, each out of service '
               'while it is. Off until switched on.',
 'power_auto_every': 'A week or a month.',
 'power_auto_day': 'The day a weekly restart goes.',
 'power_auto_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
 'power_auto_needed': 'Only the nodes an update left waiting for a restart; off: every node, every '
                      'time.'})

SAYS_SHORT.update({})

TUNABLE.update({'backup_daily': (0, 1),
 'backup_keep': (1, 365),
 'rbackup': (0, 1),
 'rbackup_every': ('daily', 'weekly'),
 'rbackup_day': (1, 7),
 'rbackup_keep': (1, 1000),
 'rbackup_keep_days': (0, 3650),
 'rbackup_verify': ('off', 'after', 'weekly'),
 'osup_check': (0, 1),
 'osup_auto': (0, 1),
 'osup_auto_what': ('security', 'all'),
 'osup_auto_every': ('daily', 'weekly', 'monthly'),
 'osup_auto_day': ('1', '2', '3', '4', '5', '6', '7'),
 'osup_auto_reboot': ('ask', 'auto'),
 'power_auto': (0, 1),
 'power_auto_every': ('weekly', 'monthly'),
 'power_auto_day': ('1', '2', '3', '4', '5', '6', '7'),
 'power_auto_needed': (0, 1)})

CHOICE_WORDS.update({'rbackup_verify': {'off': 'only by hand',
                    'after': 'after every backup, the one just sent',
                    'weekly': 'once a week, the newest one'},
 'osup_auto_what': {'security': 'only the security updates', 'all': 'every update'},
 'osup_auto_every': {'daily': 'every day',
                     'weekly': 'every week, on the day below',
                     'monthly': 'on the first of every month'},
 'osup_auto_day': {'1': 'Monday',
                   '2': 'Tuesday',
                   '3': 'Wednesday',
                   '4': 'Thursday',
                   '5': 'Friday',
                   '6': 'Saturday',
                   '7': 'Sunday'},
 'osup_auto_reboot': {'auto': 'restarted by itself where an update needs it',
                      'ask': 'a restart offered on the page'},
 'power_auto_every': {'weekly': 'every week, on the day below',
                      'monthly': 'on the first of every month'},
 'power_auto_day': {'1': 'Monday',
                    '2': 'Tuesday',
                    '3': 'Wednesday',
                    '4': 'Thursday',
                    '5': 'Friday',
                    '6': 'Saturday',
                    '7': 'Sunday'}})

ONLY_WHEN.update({'backup_at': ['backup_daily', '1'],
 'backup_keep': ['backup_daily', '1'],
 'osup_auto_at': ['osup_auto', '1'],
 'osup_auto_day': ['osup_auto_every', 'weekly'],
 'osup_auto_every': ['osup_auto', '1'],
 'osup_auto_reboot': ['osup_auto', '1'],
 'osup_auto_what': ['osup_auto', '1'],
 'osup_check_at': ['osup_check', '1'],
 'power_auto_at': ['power_auto', '1'],
 'power_auto_day': ['power_auto_every', 'weekly'],
 'power_auto_every': ['power_auto', '1'],
 'power_auto_needed': ['power_auto', '1'],
 'rbackup_at': ['rbackup', '1'],
 'rbackup_day': ['rbackup_every', 'weekly'],
 'rbackup_every': ['rbackup', '1']})

PANES.update({'db': ['backup_daily', 'backup_keep', 'backup_at'], 'backup': ['rbackup', 'rbackup_at', 'rbackup_every', 'rbackup_day', 'rbackup_keep', 'rbackup_keep_days', 'rbackup_password', 'rbackup_verify'], 'osup': ['osup_check', 'osup_check_at', 'osup_auto', 'osup_auto_what', 'osup_auto_every', 'osup_auto_day', 'osup_auto_at', 'osup_auto_reboot'], 'power': ['power_auto', 'power_auto_every', 'power_auto_day', 'power_auto_at', 'power_auto_needed']})

SECRET_KEYS = SECRET_KEYS + ('rbackup_password',)
SEALED_KEYS = SECRET_KEYS

CONFIG = dict(DEFAULTS)
FILE_CONFIG = dict(DEFAULTS)
FILE_KEYS = set()
FROM_ARGV = {}
BAD_CONFIG = []
HA_REBUILDING = threading.Event()        # never set: upsmon is one server
HA_STORE = {}
ENGINE = [None]


# ---------------------------------------------------------------------------
# The log: upsmon's own (/var/log/upsmon/upsmon.log), by upsmon.py's writer
# ---------------------------------------------------------------------------
_LOGGER = [None]
_LOG_LOCK = threading.Lock()


def set_logger(fn):
    """upsmon.py hands its log() over, so both halves write one log."""
    _LOGGER[0] = fn


def log(words, level='info'):
    words = str(words)
    if len(words) > 20000:
        words = words[:20000] + ' ... (%d characters more)' % (len(words) - 20000)
    words = re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', lambda m: '\\x%02x' % ord(m.group(0)),
                   words).replace('\n', '\n    ')
    if level == 'debug' and not CONFIG.get('debug'):
        return
    fn = _LOGGER[0]
    try:
        if fn:
            fn(words, level={'warn': 'warning', 'bad': 'error', 'crit': 'error'}.get(level, level))
        else:
            sys.stderr.write('%s %-5s %s\n' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                               level, words))
    except Exception:                                   # noqa: BLE001
        pass


_LOG_SPARING = {}


def log_sparing(key, words, level='warn', every=30):
    t = time.time()
    with _LOG_LOCK:
        at, quiet = _LOG_SPARING.get(key, (0.0, 0))
        if t - at < every:
            _LOG_SPARING[key] = (at, quiet + 1)
            return
        _LOG_SPARING[key] = (t, 0)
    log(words + (' (and %d more like it in the last %d s)' % (quiet, int(t - at)) if quiet else ''),
        level)


def debugging(what):
    return bool(CONFIG.get('debug')) and bool(CONFIG.get('debug_' + what, 1))


def log_tail(lines=400):
    path = LOG_DIR / LOG_NAME
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 400 * 1024))
            got = f.read().decode('utf-8', 'replace').splitlines()
        return got[-int(lines):]
    except OSError as e:
        return ['%s cannot be read: %s' % (path, e)]


# ---------------------------------------------------------------------------
# One server: what upsmon asks of its cluster, answered for this machine alone
# ---------------------------------------------------------------------------
def this_node_name(conf=None):
    return socket.gethostname().split('.')[0] or 'upsmon'


def node_name():
    return this_node_name()


def node_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('192.0.2.1', 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return '127.0.0.1'


def ha_nodes(store):
    return [{'name': node_name(), 'me': True, 'alive': True, 'version': __version__,
             'address': node_address(), 'age': 0, 'host': socket.gethostname()}]


def ha_peer_db():
    raise OSError('upsmon is one server: there is no other node')


def alerts_lead(store):
    return True


def vip_conf(store):
    return {'on': False}


def vip_set(store, by, **changes):
    raise ValueError('upsmon is one server: it has no VIP address')


def hisec_ui(key):
    return None


def hisec_tls(prof):
    return None


def hisec_enforced(rule, store=None):
    return False


def hisec_guard_settings(store, checked):
    return None


def mfa_pending(s):
    return ''


def mfa_stage(store, name):
    return ''


def mfa_all(store):
    return {}


MFA_ALLOWED = ()


def name_letters_problem(name):
    return ''


def boot_time():
    try:
        with open('/proc/stat') as f:
            for line in f:
                if line.startswith('btime '):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def fw_desired(store):
    return None


def access_desired(store):
    return None


def fw_now_read():
    return {}


def name_clash_words():
    return ''


ACCOUNT_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z')
PHP_FIXED = {'8.2': (8, 2, 35), '8.3': (8, 3, 36), '8.4': (8, 4, 27), '8.5': (8, 5, 12)}
_PHP_STATE = {'at': 0, 'state': None}
_SOFTWARE = {'at': 0.0, 'state': None}


def _first_line(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ''
    text = (r.stdout or '') + (r.stderr or '')
    return (text.strip().splitlines() or [''])[0].strip()[:200]


def root_ask(ask_name, answer_name, data, wait=60):
    """One request to root's helper (upsmon_web.py, by upsmon-web.path), and its answer."""
    ask_id = secrets.token_hex(8)
    data = dict(data, id=ask_id)
    tmp = WEB_DIR / ('.%s.%d.%d' % (ask_name, os.getpid(), threading.get_ident() % 100000))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(data))
    os.replace(str(tmp), str(WEB_DIR / ask_name))
    end = time.time() + wait
    while time.time() < end:
        try:
            got = json.loads((WEB_DIR / answer_name).read_text())
        except (OSError, ValueError):
            got = None
        if isinstance(got, dict) and got.get('id') == ask_id:
            if not got.get('ok'):
                raise ValueError(got.get('said') or 'the root helper said no')
            return got.get('data') or {}
        time.sleep(0.4)
    raise ValueError('the root helper did not answer in %d s - is upsmon-web.path '
                     'running?  systemctl status upsmon-web.path' % wait)


def console_at_login():
    try:
        fd = os.open(str(CONSOLE_FLAG), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        import stat as _stat
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        return os.read(fd, 8).decode('ascii', 'replace').strip() == 'on'
    finally:
        os.close(fd)


def console_at_login_set(on):
    if os.geteuid() != 0:
        raise SystemExit('upsmon: only root sets that')
    tmp = '%s.%d.tmp' % (CONSOLE_FLAG, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, b'on\n' if on else b'off\n')
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, str(CONSOLE_FLAG))
    return ('the upsmon console opens when root signs in at the console or over SSH (q leaves '
            'it for the shell)' if on else 'root signs in to the ordinary shell; '
            '`upsmon --console` opens the console')


CONSOLE_WORK = {'busy': False, 'seen': 0.0}


def norm_name(name):
    return str(name or '').strip().lower()[:190]


def hisec_backup_target(t):
    return None


def write_file_settings(changes, path=None):
    return None


def node_carry(store, old, new, by=''):
    return None


def ha_lead(store):
    return True


# ======== carried over from OTP 1.0.187 (lines 1576-1634): settings: coerced ========
class BadSetting(ValueError):
    """A value that cannot be read as the setting it was given for."""


class NodeMoved(BadSetting):
    """Saved on another machine than the one meant (1.0.110)."""


def _coerce(current, value):
    """A value made to look like the default beside it - or refused.

    Refused rather than quietly replaced, as on isemon: a setting nobody can
    read must be a setting nobody accepts, so that what runs is either what
    was asked for or plainly said to be otherwise.
    """
    if isinstance(current, bool):
        if isinstance(value, str):
            said = value.strip().lower()
            if said in ('1', 'true', 'yes', 'on'):
                return True
            if said in ('0', 'false', 'no', 'off', ''):
                return False
            raise BadSetting('%r is not yes or no' % value)
        if value is None:
            raise BadSetting('a yes-or-no setting cannot be nothing')
        return bool(value)
    if isinstance(current, int):
        if value is None or (isinstance(value, str) and not value.strip()):
            raise BadSetting('a number is needed, and nothing was given')
        if isinstance(value, bool):
            return int(value)
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            raise BadSetting('%r is not a number' % (value,))
    if isinstance(current, list):
        if isinstance(value, str):
            return [p.strip() for p in re.split(r'[,;\n\r]', value) if p.strip()]
        if isinstance(value, (list, tuple)):
            return list(value)
        raise BadSetting('%r is not a list' % (value,))
    if isinstance(current, str):
        if value is None:
            raise BadSetting('nothing was given')
        if isinstance(value, (list, tuple)):
            return ', '.join(str(one).strip() for one in value if str(one).strip())
        if isinstance(value, (dict, set)):
            raise BadSetting('%r is not something this setting can hold' % (value,))
        if isinstance(value, bool):
            return 'yes' if value else ''
        return str(value)
    return value


# Settings of several lines (1.0.103): the rest are one line each.
SETTING_TALL = ('portal_help', 'portal_groups', 'sms_body', 'sms_headers', 'isemon_targets', 'isemon_ca', 'siem_ca', 'acme_ca_pem',
                'admin_group_full', 'admin_group_token', 'admin_group_readonly', 'mail_ca')




# ======== carried over from OTP 1.0.187 (lines 1635-1827): settings: checked ========
def check_setting(key, value):
    """The value as it will be kept, or BadSetting saying why not."""
    if key not in DEFAULTS:
        raise BadSetting('%s is not a setting this version knows' % key)
    got = _coerce(DEFAULTS[key], value)
    shape = TUNABLE.get(key)
    if isinstance(shape, tuple) and shape and isinstance(shape[0], str):
        if str(got) not in shape:
            raise BadSetting('%s: %r is not one of %s' % (key, got, ', '.join(shape)))
    elif isinstance(shape, tuple) and len(shape) == 2:
        if not (shape[0] <= int(got) <= shape[1]):
            raise BadSetting('%s must be between %d and %d' % (key, shape[0], shape[1]))
    if key.startswith(('mail_', 'smtp_')) and isinstance(got, str) and \
            key not in ('smtp_password',) and re.search(r'[\x00-\x1f\x7f]', got):
        # A new line in a header (1.0.94): refused here, not a ValueError out
        # of the mail library at the moment a token's mail goes.
        raise BadSetting('%s: no line breaks or control characters' % key)
    if isinstance(got, str) and key not in SECRET_KEYS:
        # A length and no control characters for every text (1.0.103): an
        # issuer of 3000 letters made every token's QR code fail after its key
        # was replaced, and a name held a NUL and new lines.
        tall = key in SETTING_TALL
        most = 64 if key in ('totp_issuer', 'totp_label') else (20000 if tall else 500)
        if len(got) > most:
            raise BadSetting('%s: %d characters at most' % (key, most))
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]' if tall else r'[\x00-\x1f\x7f]', got):
            raise BadSetting('%s: no line breaks or other control characters' % key)
    if key == 'acme_email' and str(got).strip() and \
            not re.match(r'^[^@\s<>"]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z', str(got).strip()):
        raise BadSetting('acme_email: a mail address')
    if key == 'acme_url' and str(got).strip() and \
            not re.match(r'^https://[^\s"<>]+\Z', str(got).strip()):
        raise BadSetting('acme_url: an address starting https://')
    if key == 'acme_dns_url' and str(got).strip() and \
            not re.match(r'^(https://[^\s"<>]+|http://(127\.0\.0\.1|localhost)(:\d+)?(/[^\s"<>]*)?)\Z',
                         str(got).strip()):
        raise BadSetting('acme_dns_url: an address starting https://')
    if key in ('acme_dns_server',) and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9.\-:\[\]]{1,260}\Z', str(got).strip()):
        raise BadSetting('acme_dns_server: a name or an address, :port if not 53')
    if key in ('acme_desec_domain', 'acme_dns_alias') and str(got).strip() and \
            not re.match(r'^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?\Z',
                         str(got).strip()):
        raise BadSetting('%s: a DNS name, like example.dedyn.io' % key)
    if key == 'acme_desec_token' and str(got).strip() and not is_masked(got) and \
            not re.match(r'^[A-Za-z0-9_.-]{20,100}\Z', str(got).strip()):
        raise BadSetting('acme_desec_token: the token as deSEC shows it')
    if key in ('acme_dns_zone', 'acme_dns_tsig_name') and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-_]{0,252}\Z', str(got).strip()):
        raise BadSetting('%s: a DNS name' % key)
    if key == 'acme_dns_tsig_secret' and str(got).strip() and not is_masked(got) and \
            not re.match(r'^[A-Za-z0-9+/=]{8,512}\Z', str(got).strip()):
        raise BadSetting('acme_dns_tsig_secret: the secret in base64, as tsig-keygen makes it')
    if key in ('acme_dns_user', 'acme_dns_subdomain') and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9-]{1,64}\Z', str(got).strip()):
        raise BadSetting('%s: letters, digits and dashes' % key)
    if key == 'acme_ca_pem' and str(got).strip() and '-----BEGIN CERTIFICATE-----' not in str(got):
        raise BadSetting('acme_ca_pem: a certificate in PEM, -----BEGIN CERTIFICATE-----')
    if key == 'acme_node_name' and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z', str(got).strip()):
        raise BadSetting('acme_node_name: a DNS name')
    if key == 'proxy_url' and str(got).strip() and \
            not re.match(r'^https?://[A-Za-z0-9.\-]+(?::\d{1,5})?/?\Z|^https?://\[[0-9a-fA-F:]+\]'
                         r'(?::\d{1,5})?/?\Z', str(got).strip()):
        raise BadSetting('proxy_url: http://host:port - the user name and the password go '
                         'in the fields below, not in the address')
    if key == 'proxy_user' and re.search(r'[\s:@/]', str(got)):
        raise BadSetting('proxy_user: no spaces, no : @ or /')
    if key == 'proxy_no' and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9.*:/\[\]_-]+([\s,;]+[A-Za-z0-9.*:/\[\]_-]+)*[\s,;]*\Z',
                         str(got).strip()):
        raise BadSetting('proxy_no: names, .domains and addresses, separated by commas')
    if key == 'upgrade_url' and str(got).strip() and \
            not re.match(r'^https://[^\s]+\Z', str(got).strip()):
        raise BadSetting('upgrade_url: an address starting https://')
    return got


CONFIG_LOADED = [False]



# ======== carried over from OTP 1.0.187 (lines 1912-1934): files written whole ========
def write_replacing(path, text, mode=0o640, owner=None):
    """A file written beside itself and renamed over: never half of one.
    Its mode and owner set on the open file, not by name (1.0.101): run by
    root in a folder the service's account can write, a name can be made a
    link to any file of the machine between the write and the chmod."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if owner is not None and os.geteuid() == 0:
            os.fchown(fd, owner[0], owner[1])
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path



# ======== carried over from OTP 1.0.187 (lines 1970-2150): secrets sealed ========
# ---------------------------------------------------------------------------
# Secrets kept in the database, sealed
# ---------------------------------------------------------------------------
# The tokens' keys, the RADIUS clients' shared secrets and the directories'
# passwords are kept in the database - sealed, with a key in a file of its
# own in the state directory, exactly as isemon seals its passwords. A copy of
# the database alone opens none of them; the daily copy is made with the key
# beside it, because a database of tokens without the key that opens them is
# a database of nothing, and every person in it would have to enrol again.
# Built from HMAC-SHA256 alone - a keystream and a tag - because the standard
# library has no cipher and this must not need anything installed.
SEALED = 'sealed:1:'


def scrub_secret(text):
    """Words that may carry a database password (a conninfo in an error, say)
    with the password taken out, before they are logged or shown."""
    # A quoted value whole, up to the quote a space or the end follows (so
    # one with spaces, \' or SQL's '' inside goes too); otherwise up to the
    # next space - taking a quote with it rather than leaving a letter of
    # the password behind.
    return re.sub(r"(password\s*=\s*)('.*?'(?=\s|$)|\S+)", r'\1***', str(text or ''),
                  flags=re.I | re.S)


def sealing_key_path():
    return Path(STATE_DIR) / 'secrets.key'


_KEY_CACHE = {}
_KEY_LOCK = threading.Lock()


def sealing_key(make=False):
    """The key every secret in the database is sealed with. Read once and
    kept while the file is unchanged (1.0.33) - it was read from disk for
    every secret opened, every token in a list of thousands. Made only where
    there is none, and then with O_EXCL, so two processes starting at once
    cannot each make one of their own."""
    path = sealing_key_path()
    try:
        st = os.stat(str(path))
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    except FileNotFoundError:
        stamp = None
    except OSError:
        stamp = 'unreadable'
    if stamp is not None and stamp != 'unreadable':
        got = _KEY_CACHE.get(str(path))
        if got and got[0] == stamp:
            return got[1]
    try:
        key = bytes.fromhex(path.read_text(encoding='ascii').strip())
    except FileNotFoundError:
        key = None
    except (OSError, ValueError):
        key = b''
    if key and len(key) == 32:
        if stamp and stamp != 'unreadable':
            _KEY_CACHE[str(path)] = (stamp, key)
        return key
    if not make:
        return b''
    if key is not None:
        raise OSError('%s is there but cannot be read as a key - it is never replaced, '
                      'because every token sealed with it would be lost' % path)
    with _KEY_LOCK:
        key = secrets.token_bytes(32)
        # Written whole beside it, then linked into place (1.0.94): created
        # empty first, another process starting just then read an empty
        # key and stopped.
        tmp = '%s.new-%d-%s' % (path, os.getpid(), secrets.token_hex(4))
        # A name nobody made before, never through a link (1.0.101), and
        # given to the folder's owner while it is still open.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.geteuid() == 0:
                st = os.stat(str(path.parent))
                os.fchown(fd, st.st_uid, st.st_gid)
        except OSError:
            pass
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(key.hex() + '\n')
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, str(path))
        except FileExistsError:
            # Made by somebody else a moment ago: theirs is the key.
            os.unlink(tmp)
            return sealing_key(make=False) or b''
        os.unlink(tmp)
        log('a new key to seal secrets with was made: %s - keep a copy of it beside every '
            'copy of the database' % path, 'warn')
    return key


def _seal_stream(key, nonce, size):
    out = bytearray()
    block = 0
    while len(out) < size:
        out += hmac.new(key, b'stream' + nonce + block.to_bytes(8, 'big'),
                        hashlib.sha256).digest()
        block += 1
    return bytes(out[:size])


SEALED2 = 'sealed:2:'
# Set once every token's secrets carry the name they belong to (1.0.33): from
# then on a secret of a token sealed the old way, without it, is not opened.
BIND_STRICT = {'tokens': False}


def token_bind(name):
    """What a token's sealed secrets are tied to: its name. Copied into
    another token's row, they no longer open (1.0.33)."""
    return 'token:' + str(name or '').strip().lower()


def seal_secret(text, bind=None):
    """Sealed with the key of this installation: a keystream from HMAC-SHA256,
    then a tag over it. With `bind`, the tag covers that too (sealed:2:), so
    the value opens only where it was sealed for."""
    key = sealing_key(make=True)
    if not key:
        raise OSError('no key to seal with')
    data = str(text).encode('utf-8')
    nonce = secrets.token_bytes(16)
    hide = hmac.new(key, b'hide', hashlib.sha256).digest()
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    body = bytes(a ^ b for a, b in zip(data, _seal_stream(hide, nonce, len(data))))
    if bind is not None:
        tag = hmac.new(sign, b'2|' + str(bind).encode('utf-8') + b'|' + nonce + body,
                       hashlib.sha256).digest()[:16]
        return SEALED2 + base64.urlsafe_b64encode(nonce + body + tag).decode('ascii')
    tag = hmac.new(sign, nonce + body, hashlib.sha256).digest()[:16]
    return SEALED + base64.urlsafe_b64encode(nonce + body + tag).decode('ascii')


def unseal_secret(value, bind=None):
    """The secret back, or None where this machine's key is not the one it was
    sealed with - or, for one bound to a place, where it is not that place. A
    value never sealed is given back as it is."""
    if not isinstance(value, str):
        return value
    if value.startswith(SEALED2):
        v2, prefix = True, SEALED2
    elif value.startswith(SEALED):
        v2, prefix = False, SEALED
    else:
        if value and bind is not None and str(bind).startswith('token:') and \
                BIND_STRICT.get('tokens'):
            # A token's key that was never sealed (1.0.101): every one was
            # sealed at start, so this one was written by somebody without
            # the key - taken for nothing.
            return None
        return value
    if not v2 and bind is not None and str(bind).startswith('token:') and \
            BIND_STRICT.get('tokens'):
        return None
    if v2 and bind is None:
        return None
    key = sealing_key()
    try:
        raw = base64.urlsafe_b64decode(value[len(prefix):].encode('ascii'))
    except (ValueError, TypeError):
        return None
    if not key or len(raw) < 32:
        return None
    nonce, body, tag = raw[:16], raw[16:-16], raw[-16:]
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    signed = (b'2|' + str(bind).encode('utf-8') + b'|' if v2 else b'') + nonce + body
    if not hmac.compare_digest(tag, hmac.new(sign, signed, hashlib.sha256).digest()[:16]):
        return None
    hide = hmac.new(key, b'hide', hashlib.sha256).digest()
    try:
        return bytes(a ^ b for a, b in zip(body, _seal_stream(hide, nonce, len(body)))
                     ).decode('utf-8')
    except UnicodeDecodeError:
        return None



# ======== carried over from OTP 1.0.187 (lines 2328-2438): small helpers, passwords ========
def now():
    return time.time()


def human_span(seconds):
    s = max(0, int(seconds or 0))
    if s < 60:
        return '%d s' % s
    if s < 3600:
        return '%d min' % (s // 60)
    if s < 86400:
        return '%d h %d min' % (s // 3600, (s % 3600) // 60)
    days = s // 86400
    return '%s %d h' % ('1 day' if days == 1 else '%d days' % days, (s % 86400) // 3600)


def stamp(ts):
    if not ts:
        return '-'
    return datetime.fromtimestamp(float(ts)).strftime('%d-%m-%Y %H:%M:%S')


def short_host():
    try:
        return socket.gethostname().split('.')[0] or 'upsmon'
    except OSError:
        return 'upsmon'


# Letters beyond ASCII a name takes (1.0.154, split in 1.0.155): Czech's and
# Slovak's with names_czsk_letters, every language's with names_any_letters;
# both off, none.
NAME_LETTERS_HOME = set('áäčďéěíĺľňóôŕřšťúůýž' + 'áäčďéěíĺľňóôŕřšťúůýž'.upper())


def name_letters_problem(name):
    """'' when the name's letters are ones this server takes, else what is
    wrong with it, in words."""
    if CONFIG.get('names_any_letters'):
        return ''
    import unicodedata
    said = unicodedata.normalize('NFC', str(name or ''))
    home = bool(CONFIG.get('names_czsk_letters'))
    odd = sorted({c for c in said if ord(c) > 127 and not (home and c in NAME_LETTERS_HOME)})
    if not odd:
        return ''
    if home:
        return ('the name %s has letters of another language (%s) - only Czech and Slovak ones '
                'are taken (Settings - The tokens - Letters of other languages in names)'
                % (said[:60], ' '.join(odd[:8])))
    return ('the name %s has letters with accents or of another language (%s) - only letters '
            'without accents are taken (Settings - The tokens - Czech and Slovak letters in '
            'names, Letters of other languages in names)' % (said[:60], ' '.join(odd[:8])))


def dn_list(text):
    """Group names or DNs out of one setting: split on semicolons and new
    lines, never on commas - a DN is mostly commas."""
    if isinstance(text, (list, tuple)):
        pieces = list(text)
    else:
        pieces = re.split(r'[;\n]', str(text or ''))
    return [p.strip() for p in pieces if str(p).strip()]


def cn_of(dn):
    """`CN=VPN Users,OU=Groups,...` as `VPN Users`; a plain name as itself."""
    said = str(dn or '').strip()
    m = re.match(r'(?i)^cn=((?:\\.|[^,])*)', said)
    if m:
        return re.sub(r'\\(.)', r'\1', m.group(1)).strip()
    return said


def password_hash(password, salt=None, rounds=310000):
    salt = salt or secrets.token_bytes(16)
    got = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt, rounds)
    return 'pbkdf2_sha256$%d$%s$%s' % (rounds, base64.b64encode(salt).decode('ascii'),
                                       base64.b64encode(got).decode('ascii'))


def password_ok(password, stored):
    try:
        kind, rounds, salt, want = str(stored or '').split('$')
        if kind != 'pbkdf2_sha256':
            return False
        got = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'),
                                  base64.b64decode(salt), int(rounds))
        return hmac.compare_digest(got, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


def password_problem(password):
    """Why a password for an account here will not do, or ''."""
    p = str(password or '')
    if len(p) < 8:
        return 'a password needs at least eight characters'
    if len(p) > 200:
        return 'that password is longer than anybody types'
    return ''


# ---------------------------------------------------------------------------
# One-time passwords: RFC 4226 (HOTP) and RFC 6238 (TOTP)
# ---------------------------------------------------------------------------
# What the phone does, done again here: the key and the number of thirty-
# second periods since 1970 go through HMAC, and six digits are cut out of the
# answer. Nothing in this needs anything but hashlib and hmac.
HASHES = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}



# ======== carried over from OTP 1.0.187 (lines 5861-5877): secrets shown ========
def secret_shown(value, last=True):
    """A secret as the page may see it: dots and its last two characters, so
    that "the one I set" can be told from "something else". Only a full
    administrator is ever given this (the routes give everybody else dots
    alone); `last=False` for what leaves the pages - an export without its
    secrets carries dots only (1.0.101)."""
    said = str(value or '')
    if not said:
        return ''
    if not last:
        return '••••••••'
    return '•' * min(10, max(4, len(said) - 2)) + said[-2:] if len(said) > 4 else '•' * 6


def is_masked(value):
    return isinstance(value, str) and value.startswith('•')



# ======== carried over from OTP 1.0.187 (lines 5886-5910): addresses ========
PLAIN_ADDR_RE = re.compile(r'^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z')


def plain_ip(text, how='network'):
    """An address, a network or an address with its prefix, and nothing else
    (1.0.57): ipaddress keeps an IPv6 scope id (fe80::1%eth0) with any
    character in it - newlines and braces too - which then went on into the
    files root writes (nginx, keepalived, ip6tables)."""
    said = str(text or '').strip()
    if not PLAIN_ADDR_RE.match(said):
        raise ValueError('%r is not a plain address' % said[:60])
    got = {'address': ipaddress.ip_address, 'interface': ipaddress.ip_interface,
           'network': lambda t: ipaddress.ip_network(t, strict=False)}[how](said)
    if '%' in str(got):
        raise ValueError('a scope id is not taken')
    return got


def address_net(text):
    """An address or a range of them, as a network - ValueError if neither."""
    said = str(text or '').strip()
    if not said:
        raise ValueError('an address is needed')
    return plain_ip(said, 'network')



# ======== carried over from OTP 1.0.187 (lines 16505-16621): DNS asked without a library ========
# ---- the recipients' servers, without a library to ask DNS with -----------------
def own_dns():
    """The DNS servers set for mail going direct (`mail_dns`), if any."""
    good = []
    for w in re.split(r'[\s,;]+', str(CONFIG.get('mail_dns') or '')):
        try:
            good.append(str(ipaddress.ip_address(w)))
        except ValueError:
            pass
    return good


def dns_servers():
    if own_dns():
        return own_dns()
    out = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                bits = line.split()
                if len(bits) >= 2 and bits[0] == 'nameserver':
                    out.append(bits[1])
    except OSError:
        pass
    return out or ['127.0.0.1']


def _dns_name(data, at):
    labels, jumped, end = [], False, at
    for _ in range(64):
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at = ((n & 0x3F) << 8) | data[at + 1]
            jumped = True
            continue
        labels.append(data[at + 1:at + 1 + n].decode('ascii', 'replace'))
        at += 1 + n
    return '.'.join(labels), (end if jumped else at)


def _dns_ask(server, name, qtype, timeout):
    """One question to one DNS server: the raw answer. EDNS0 asks for room
    for a long answer; one that is cut short anyway is asked again over TCP
    (1.0.22)."""
    ident = secrets.randbits(16)
    q = struct.pack('>HHHHHH', ident, 0x0100, 1, 0, 0, 1)
    for label in name.split('.'):
        if not label:
            continue
        raw = label.encode('idna') if any(ord(c) > 127 for c in label) else label.encode()
        q += bytes([len(raw)]) + raw
    q += b'\x00' + struct.pack('>HH', qtype, 1)
    q += b'\x00' + struct.pack('>HHIH', 41, 4096, 0, 0)          # OPT: 4096 bytes
    fam = socket.AF_INET6 if ':' in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    deadline = time.time() + timeout
    question = q[12:-11]                    # the name, the type and the class asked
    try:
        # connect(): only answers from the server asked are read at all.
        s.connect((server, 53))
        s.send(q)
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout('no answer from %s' % server)
            s.settimeout(left)
            data = s.recv(65535)
            # Its own answer: the same ID, and the same question (1.0.33) -
            # and no waiting past the deadline however many others come.
            if len(data) >= 12 + len(question) and struct.unpack('>H', data[:2])[0] == ident \
                    and data[12:12 + len(question)].lower() == question.lower():
                break
    finally:
        s.close()
    if struct.unpack('>H', data[2:4])[0] & 0x0200:                # TC: cut short
        t = socket.create_connection((server, 53), timeout=timeout)
        try:
            t.sendall(struct.pack('>H', len(q)) + q)
            want, got = None, b''
            while want is None or len(got) < want + 2:
                chunk = t.recv(65535)
                if not chunk:
                    break
                got += chunk
                if want is None and len(got) >= 2:
                    want = struct.unpack('>H', got[:2])[0]
            data = got[2:]
        finally:
            t.close()
    return data


def _dns_records(data):
    """(rcode, [(type, name, rdata-offset, size)]) of an answer."""
    flags, qd, an = struct.unpack('>HHH', data[2:8])
    at = 12
    for _ in range(qd):
        _, at = _dns_name(data, at)
        at += 4
    out = []
    for _ in range(an):
        rname, at = _dns_name(data, at)
        rtype, _cls, _ttl, size = struct.unpack('>HHIH', data[at:at + 10])
        at += 10
        out.append((rtype, rname, at, size))
        at += size
    return flags & 0x0F, out


DNS_RCODES = {1: 'could not read the question', 2: 'failed (SERVFAIL)', 4: 'does not do that',
              5: 'refused to answer'}



# ======== carried over from OTP 1.0.187 (lines 6104-6115): like ========
def like_pattern(text):
    """`*` a wildcard, everything else itself; `!` is the escape."""
    out = ''
    for c in str(text):
        if c == '*':
            out += '%'
        elif c in '%_!':
            out += '!' + c
        else:
            out += c
    return out



# ======== carried over from OTP 1.0.187 (lines 13595-13735): what it runs on ========
def software_info(store=None):
    """What _software_now found, made in a thread of its own once in 10 minutes
    (1.0.186): asked in the heartbeat, its ten programs (5 s each at most) and
    the database's version held the main loop, and the other node took this
    one for gone."""
    now = time.time()
    if now - _SOFTWARE.get('full_at', 0) > 600 and not _SOFTWARE.get('busy'):
        _SOFTWARE['busy'] = True

        def go():
            try:
                _SOFTWARE['full'] = _software_now(store)
                _SOFTWARE['full_at'] = time.time()
            except Exception:                           # noqa: BLE001
                _SOFTWARE['full_at'] = time.time()
            finally:
                _SOFTWARE['busy'] = False
        threading.Thread(target=go, name='upsmon-software', daemon=True).start()
    return dict(_SOFTWARE.get('full') or {'upsmon': __version__})


def _software_now(store=None):
    """What this node runs on (1.0.99): upsmon, its Python and the modules it
    uses, the libraries under them, the programs beside it and the system -
    for Settings → About, of every node. Asked at most once an hour."""
    if time.time() - _SOFTWARE['at'] < 3600 and _SOFTWARE['state'] is not None:
        out = dict(_SOFTWARE['state'])
    else:
        import platform
        import sqlite3
        out = {'upsmon': __version__,
               'python': '%s %s' % (platform.python_implementation(), platform.python_version()),
               'python_path': os.path.realpath(sys.executable),
               'openssl': ssl.OPENSSL_VERSION, 'sqlite': sqlite3.sqlite_version,
               'kernel': '%s %s' % (platform.system(), platform.release()),
               'arch': platform.machine(), 'modules': {}, 'programs': {}}
        try:
            with open('/etc/os-release', encoding='utf-8') as f:
                rel = dict(l.strip().split('=', 1) for l in f if '=' in l)
            out['os'] = rel.get('PRETTY_NAME', '').strip('"')
        except OSError:
            out['os'] = ''
        for mod, attr in (('psycopg2', '__version__'), ('pymysql', '__version__'),
                          ('colorama', '__version__')):
            try:
                m = __import__(mod)
                v = str(getattr(m, attr, '') or '').split(' ')[0]
                if mod == 'psycopg2':
                    lib = getattr(m, '__libpq_version__', 0)
                    if lib:
                        v += ' (libpq %d.%d)' % (lib // 10000, lib % 10000 // 100 if lib < 100000
                                                 else lib % 100)
                out['modules'][mod] = v
            except Exception:                           # noqa: BLE001
                out['modules'][mod] = ''
        progs = (('nginx', ['nginx', '-v']), ('php', ['php', '-v']),
                 ('php-fpm', None), ('keepalived', ['keepalived', '--version']),
                 ('pg_dump', ['pg_dump', '--version']),
                 ('mariadb-dump', ['mariadb-dump', '--version']),
                 ('openssl', ['openssl', 'version']), ('systemd', ['systemctl', '--version']),
                 ('iptables', ['iptables', '--version']),
                 ('firewalld', ['firewall-cmd', '--version']))
        for name, cmd in progs:
            if name == 'php-fpm':
                import glob
                fpm = sorted(glob.glob('/usr/sbin/php-fpm*') + glob.glob('/usr/sbin/php*-fpm*'))
                line = _first_line([fpm[-1], '-v']) if fpm else ''
            else:
                exe = shutil.which(cmd[0]) or next((p for p in ('/usr/sbin/' + cmd[0], '/sbin/' + cmd[0])
                                                    if os.path.exists(p)), None)
                line = _first_line([exe] + cmd[1:]) if exe else ''
            m = re.search(r'(\d+\.\d+(?:\.\d+)?[^\s,()]*)', line or '')
            if m and not re.search(r'(?i)denied|not found|error', line):
                out['programs'][name] = m.group(1)
            elif name == 'systemd':
                m = re.search(r'^systemd\s+(\d+)', line or '')
                if m:
                    out['programs'][name] = m.group(1)
        _SOFTWARE.update(at=time.time(), state=dict(out))
    # What changes without a restart, asked each time it is wanted.
    if store is not None:
        try:
            out['database'] = store.db.version() or ''
        except Exception:                               # noqa: BLE001
            pass
    try:
        out['php_cli'] = (php_state() or {}).get('version') or ''
    except Exception:                                   # noqa: BLE001
        pass
    return out


def php_state():
    if time.time() - _PHP_STATE['at'] < 3600 and _PHP_STATE['state'] is not None:
        return _PHP_STATE['state']
    out = {'version': '', 'fixed': None, 'how': ''}
    php = shutil.which('php') or next((p for p in ('/usr/bin/php', '/usr/local/bin/php')
                                       if os.path.exists(p)), None)
    if php:
        try:
            out['version'] = subprocess.run([php, '-r', 'echo PHP_VERSION;'], capture_output=True,
                                            text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)', out['version'])
    if m:
        v = tuple(int(x) for x in m.groups())
        want = PHP_FIXED.get('%d.%d' % v[:2])
        if want and v >= want or (not want and v[:2] > (8, 5)):
            out.update(fixed=True, how='version')
    if not out['fixed']:
        said = ''
        rpm = shutil.which('rpm')
        if rpm:
            for pkg in ('php-fpm', 'php-common'):
                try:
                    said += subprocess.run([rpm, '-q', '--changelog', pkg], capture_output=True,
                                           text=True, timeout=20).stdout
                except (OSError, subprocess.SubprocessError):
                    pass
        else:
            import gzip
            import glob
            for f in glob.glob('/usr/share/doc/php*-fpm/changelog.Debian.gz') + glob.glob(
                    '/usr/share/doc/php*-common/changelog.Debian.gz'):
                try:
                    with gzip.open(f, 'rt', errors='replace') as g:
                        said += g.read(200000)
                except OSError:
                    pass
        if 'CVE-2026-109618' in said:
            out.update(fixed=True, how='changelog')
        elif out['version']:
            out['fixed'] = False
    _PHP_STATE.update(at=time.time(), state=out)
    return out


# ---------------------------------------------------------------------------
# The daemon
# ---------------------------------------------------------------------------


# ======== carried over from OTP 1.0.187 (lines 21437-22278): maintenance and upgrades, from the web ========
# ---------------------------------------------------------------------------
# Maintenance, and a new version put in from the pages (1.0.37)
# ---------------------------------------------------------------------------
# Maintenance is per node: the node stops answering RADIUS (the VPN goes to
# the other one, as it would to a node that is down) and /healthz says 503
# (the load balancer takes it out). The pages go on working, so the node can
# be looked at and brought back.
#
# An upgrade: the package goes into the database, in pieces (so the other
# node of a cluster has it too), and a plan says which nodes, in which
# order. Each node does its own turn when it comes - maintenance on, a
# moment for the balancer to notice, the package handed to root
# (upsmon_upgrade.py, by upsmon-upgrade.path), and after its restart its own
# check before it leaves maintenance. Then the next one.
#
# Every row has ONE node that writes it (the plan: the one that started it;
# `upgrade:node:X` and `maint:X`: node X - or, for maintenance, the pages,
# which only ever UPDATE it). Replicated, a newer version may add a column,
# and the older node then takes nothing more from it until it is upgraded
# too; so a node's own rows are also written straight into the other's
# database - an UPDATE of a row both have, never an INSERT, which the
# replication arriving later would then collide with.
UPGRADE_DIR = STATE_DIR / 'upgrade'
UPGRADE_HELPER = Path(os.environ.get('UPSMON_UPGRADE_HELPER',
                                     str(Path(__file__).resolve().parent / 'upsmon_upgrade.py')))
UPGRADE_MOST = 64 * 1024 * 1024
UPGRADE_PIECE = 40000                       # base64 characters in one meta row
UPGRADE_DRAIN_S = int(os.environ.get('UPSMON_UPGRADE_DRAIN_S', '20'))
UPGRADE_TIMEOUT_S = 30 * 60
MAINT_CACHE = {'at': 0.0, 'row': None}
RESTORE_RUNNING = threading.Event()
RESTORE_WHY = ['']


def _meta_json(store, k):
    try:
        got = store.get_meta(k)
        return json.loads(got) if got else None
    except (ValueError, TypeError):
        return None


def _peer_update(k, v):
    """The same row changed in the other node's database too - UPDATE only."""
    if CONFIG.get('ha_mode') != 'replicated' or not CONFIG.get('ha_peer'):
        return False
    try:
        far = ha_peer_db()
    except Exception:                                   # noqa: BLE001
        return False
    try:
        return bool(far.run('UPDATE meta SET v = ? WHERE k = ?', (v, k)))
    except Exception:                                   # noqa: BLE001
        return False
    finally:
        try:
            far.close()
        except Exception:                               # noqa: BLE001
            pass


def _row_write(store, k, data, mine=True, mirror=True):
    """A row of this node's own (made here if need be), or someone else's
    (only ever UPDATEd)."""
    v = json.dumps(data, default=str)
    if store.db.value('SELECT k FROM meta WHERE k = ?', (k,)) is None:
        if not mine:
            raise ValueError('that node has not been heard of here yet')
        store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k, v))
    else:
        store.db.run('UPDATE meta SET v = ? WHERE k = ?', (v, k))
    if mirror:
        _peer_update(k, v)


# ---- maintenance ---------------------------------------------------------------------
def maintenance_row(store, name=None):
    return _meta_json(store, 'maint:' + (name or node_name())) or {'on': False}


def maintenance_now(store):
    """This node's maintenance, read at most every two seconds - asked for
    every RADIUS packet."""
    if HA_REBUILDING.is_set():
        return {'on': True, 'why': 'rebuilt from the other node'}
    if RESTORE_RUNNING.is_set():
        # A backup put back (1.0.149): RADIUS waited for the whole of it with
        # the database held, or met tables being made again and refused. Room
        # given back in a cluster too (1.0.150): VACUUM FULL holds each table
        # shut - the other node answers meanwhile.
        return {'on': True, 'why': RESTORE_WHY[0] or 'a backup is being put back'}
    now = time.time()
    if now - MAINT_CACHE['at'] > 2:
        MAINT_CACHE['at'] = now
        try:
            MAINT_CACHE['row'] = maintenance_row(store)
        except Exception:                               # noqa: BLE001
            pass                                        # the last one known stands
    return MAINT_CACHE['row'] or {'on': False}


def maintenance_ensure(store):
    """The row of this node, made by this node: the pages only change it."""
    if HA_REBUILDING.is_set():
        return
    try:
        if store.get_meta('maint:' + node_name()) is None:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)',
                         ('maint:' + node_name(), json.dumps({'on': False})))
    except Exception:                                   # noqa: BLE001
        pass


def maintenance_set(store, on, why='', by='', name=None):
    name = name or node_name()
    row = {'on': bool(on), 'why': str(why or '')[:200], 'by': str(by or '')[:100],
           'at': time.time()}
    _row_write(store, 'maint:' + name, row, mine=(name == node_name()))
    MAINT_CACHE['at'] = 0
    store.add_event('starting and stopping', '%s: %s%s' % (
        name, 'in maintenance' if on else 'back in service',
        (' - ' + why) if why and on else ''), 'warn' if on else 'info', who=by or None)
    return row


# ---- the package --------------------------------------------------------------------
def upgrade_inspect(path):
    """What the package is, asked of upsmon_upgrade.py - the same check root
    makes again before putting it in."""
    if not UPGRADE_HELPER.exists():
        raise ValueError('upsmon_upgrade.py is not installed beside upsmon.py; upgrade once on the '
                         'command line (install.sh --upgrade)')
    try:
        r = subprocess.run([sys.executable, '-I', str(UPGRADE_HELPER), '--inspect', str(path)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        got = json.loads(r.stdout.decode('utf-8', 'replace') or '{}')
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        raise ValueError('the package could not be checked: %s' % e)
    if not got.get('ok'):
        raise ValueError(got.get('said') or 'the package was refused')
    return got


def upgrade_store_package(store, path, info, by):
    """The package into the database in pieces, the one before taken out."""
    raw = Path(path).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    text = base64.b64encode(raw).decode('ascii')
    pieces = [text[i:i + UPGRADE_PIECE] for i in range(0, len(text), UPGRADE_PIECE)]
    old = _meta_json(store, 'upgrade:pkg') or {}
    # Every other package's pieces out, not only the last one's (1.0.44).
    store.db.run("DELETE FROM meta WHERE k LIKE 'upgrade:piece:%' AND k NOT LIKE ?",
                 ('upgrade:piece:%s:%%' % sha[:16],))
    for i, one in enumerate(pieces):
        k = 'upgrade:piece:%s:%04d' % (sha[:16], i)
        if store.get_meta(k) is None:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (k, one))
    meta = {'sha': sha, 'version': info['version'], 'bytes': len(raw), 'pieces': len(pieces),
            'signed_by': info.get('signed_by'), 'changelog': info.get('changelog', ''),
            'by': by, 'at': time.time()}
    store.set_meta('upgrade:pkg', json.dumps(meta))
    return meta


def upgrade_package_file(store, meta):
    """The package back out of the database, to the folder root takes it
    from - from the other node's database when this one has not all of it
    yet."""
    UPGRADE_DIR.mkdir(mode=0o750, exist_ok=True)
    out = UPGRADE_DIR / ('upsmon-%s.tar.gz' % meta['version'])

    def pieces_of(db):
        rows = db.rows("SELECT k, v FROM meta WHERE k LIKE ? ESCAPE '!' ORDER BY k",
                       ('upgrade:piece:%s:%%' % meta['sha'][:16],))
        return [r['v'] for r in rows]
    got = pieces_of(store.db)
    if len(got) != int(meta['pieces']) and CONFIG.get('ha_mode') == 'replicated':
        far = ha_peer_db()
        try:
            got = pieces_of(far)
        finally:
            far.close()
    if len(got) != int(meta['pieces']):
        raise ValueError('the package has not all arrived in this node\'s database')
    raw = base64.b64decode(''.join(got))
    if hashlib.sha256(raw).hexdigest() != meta['sha']:
        raise ValueError('the package in the database is damaged')
    tmp = out.with_suffix('.part')
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
    os.replace(str(tmp), str(out))
    return out


# ---- the plan ------------------------------------------------------------------------
def upgrade_nodes_now(store):
    """The nodes an upgrade goes over: every one heard from lately, or this
    one alone."""
    nodes = [n for n in ha_nodes(store) if n.get('alive')]
    if not nodes:
        nodes = [{'name': node_name(), 'version': __version__, 'me': True, 'alive': True}]
    return nodes


def upgrade_plan(store):
    plan = _meta_json(store, 'upgrade:plan')
    if not plan:
        return None
    plan['steps'] = []
    plan['drain_s'] = UPGRADE_DRAIN_S
    for name in plan.get('order') or []:
        row = _meta_json(store, 'upgrade:node:' + name) or {}
        if row.get('id') != plan.get('id'):
            row = {'state': 'waiting'}
        row['name'] = name
        plan['steps'].append(row)
    states = [s.get('state') for s in plan['steps']]
    if any(s == 'failed' for s in states):
        plan['state'] = 'failed'
    elif states and all(s == 'done' for s in states):
        plan['state'] = 'done'
    elif plan.get('cancelled'):
        plan['state'] = 'cancelled'
    else:
        plan['state'] = 'running'
    return plan


def upgrade_checks(store, meta, pages=False):
    """What must be so before an upgrade starts - (ok, [why not]). A package
    to go back to (1.0.143) is looked at again as it was when it was taken."""
    why = []
    if not meta:
        return False, ['no package has been sent yet']
    down = bool(meta.get('downgrade'))
    if down:
        why += downgrade_why_not(store, meta['version'])
        if pages and not CONFIG.get('upgrade_downgrade'):
            # Switched off since it was fetched (1.0.146): not started from the pages.
            why.append('going back to an older version is switched off (Settings → Upgrades)')
    nodes = upgrade_nodes_now(store)
    for n in ha_nodes(store):
        if not n.get('alive'):
            why.append('%s has not been heard from for %d s - bring it back, or forget it '
                       '(Settings - High availability)' % (n['name'], int(n.get('age') or 0)))
    for n in nodes:
        have = str(n.get('version') or '')
        try:
            if have and not down and tuple(int(x) for x in have.split('.')) > \
                    tuple(int(x) for x in meta['version'].split('.')):
                why.append('%s runs %s, newer than %s' % (n['name'], have, meta['version']))
        except ValueError:
            pass
    plan = upgrade_plan(store)
    if plan and plan['state'] == 'running':
        why.append('an upgrade is going on already')
    return not why, why


def upgrade_start(store, by, pages=False):
    meta = _meta_json(store, 'upgrade:pkg')
    ok, why = upgrade_checks(store, meta, pages)
    if not ok:
        raise ValueError('; '.join(why))
    names = [n['name'] for n in upgrade_nodes_now(store)]
    me = node_name()
    # The others first and this node last: the pages it shows stay up the
    # longest, and the first node is the one somebody can look at while it
    # is done.
    order = sorted(n for n in names if n != me) + ([me] if me in names else [])
    ident = '%d-%s' % (int(time.time()), secrets.token_hex(4))
    for name in order:
        k = 'upgrade:node:' + name
        if store.get_meta(k) is None:
            # Made here, for every node, before anything else: from then on
            # each node only UPDATEs its own.
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)',
                         (k, json.dumps({'state': 'none'})))
    plan = {'id': ident, 'version': meta['version'], 'sha': meta['sha'], 'order': order,
            'by': by, 'at': time.time(), 'from': me, 'downgrade': bool(meta.get('downgrade'))}
    store.set_meta('upgrade:plan', json.dumps(plan))
    store.add_event('starting and stopping', '%s started %s %s: %s, one at a time' % (
        by, 'going back to' if plan['downgrade'] else 'the upgrade to', meta['version'],
        ', '.join(order)), 'warn', who=by)
    return upgrade_plan(store)


def upgrade_cancel(store, by):
    plan = _meta_json(store, 'upgrade:plan')
    if not plan:
        raise ValueError('no upgrade is going on')
    plan['cancelled'] = {'by': by, 'at': time.time()}
    store.set_meta('upgrade:plan', json.dumps(plan))
    _peer_update('upgrade:plan', json.dumps(plan))
    store.add_event('starting and stopping', '%s stopped the upgrade to %s: the nodes not '
                    'begun stay as they are' % (by, plan.get('version')), 'warn', who=by)


def _my_step(store, plan, **fields):
    k = 'upgrade:node:' + node_name()
    row = _meta_json(store, k) or {}
    if row.get('id') != plan['id']:
        row = {'id': plan['id']}
    row.update(fields)
    row['at'] = time.time()
    _row_write(store, k, row, mine=False)
    return row


def _helper_status():
    try:
        fd = os.open(str(UPGRADE_DIR / 'status.json'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            return json.loads(f.read(1 << 20).decode('utf-8'))
    except (OSError, ValueError):
        return {}


def upgrade_log_tail(lines=200):
    try:
        fd = os.open(str(UPGRADE_DIR / 'last.log'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            text = f.read(4 << 20).decode('utf-8', 'replace')
        return text.splitlines()[-lines:]
    except OSError:
        return []


def upgrade_tick(daemon):
    """This node's part of the plan, every few seconds."""
    store = daemon.store
    if HA_REBUILDING.is_set():
        return
    plan = upgrade_plan(store)
    # A cancelled plan is still finished where a node has begun (1.0.44):
    # one that drains goes back into service, one that installs is checked
    # and comes back - it never stays in maintenance for good.
    if plan and plan['state'] == 'failed':
        _back_after_marked(store, plan)
    if not plan or plan['state'] not in ('running', 'cancelled'):
        return
    me = node_name()
    if store.get_meta('upgrade:node:' + me) is None:
        return                          # its row has not come over from the other node yet
    steps = plan['steps']
    turn = next((s for s in steps if s.get('state') != 'done'), None)
    if turn and turn['name'] != me and turn.get('state') in ('draining', 'installing',
                                                             'checking'):
        # The node whose turn it is gone for longer than an upgrade takes
        # (1.0.59): marked failed from here, or the plan ran for ever and
        # stopped every new upload and start until somebody cancelled it.
        alive = any(n.get('name') == turn['name'] and n.get('alive')
                    for n in ha_nodes(store))
        if not alive and now_minus(turn.get('at')) > UPGRADE_TIMEOUT_S + 300 and \
                not _peer_still_at_it(turn):
            row = dict(turn)
            row.pop('name', None)
            row.update({'state': 'failed', 'at': time.time(), 'marked_by': me,
                        'said': 'not heard from for %d min while %s - marked failed by %s'
                                % (UPGRADE_TIMEOUT_S // 60 + 5, turn.get('state'), me)})
            try:
                _row_write(store, 'upgrade:node:' + turn['name'], row, mine=False)
                store.add_event('starting and stopping', 'the upgrade of %s to %s failed: '
                                'the node has not been heard from' % (turn['name'],
                                                                      plan['version']), 'bad')
            except Exception as e:                      # noqa: BLE001
                log('the upgrade of %s could not be marked failed: %s' % (turn['name'], e),
                    'warn')
        return
    if not turn or turn['name'] != me:
        return
    state = turn.get('state')
    now = time.time()
    if plan.get('cancelled') and state in ('waiting', 'none', None, 'cancelled'):
        return
    if plan.get('cancelled') and state == 'draining':
        if not turn.get('was_maint'):
            maintenance_set(store, False, by=plan.get('by') or '')
        _my_step(store, plan, state='cancelled', said='cancelled before it was installed; '
                 'back in service')
        return
    if state in ('waiting', 'none', None) and len(steps) > 1:
        # Never both out at once (1.0.44): the others have to be alive and
        # in service before this one leaves.
        for n in ha_nodes(store):
            if n['name'] == me or n['name'] not in [x['name'] for x in steps]:
                continue
            if not n.get('alive') or maintenance_row(store, n['name']).get('on'):
                if turn.get('said') != 'waiting for %s to be in service' % n['name']:
                    _my_step(store, plan, state='waiting',
                             said='waiting for %s to be in service' % n['name'])
                return
    if state in ('waiting', 'none', None):
        was = maintenance_row(store)
        alone = len(steps) == 1
        maintenance_set(store, True, 'upgrade to %s' % plan['version'], plan.get('by') or '')
        _my_step(store, plan, state='draining', was_maint=bool(was.get('on')),
                 began=now, said='in maintenance; the balancer and the VPN go to the other '
                 'node' if not alone else 'in maintenance')
        if not alone:
            return
        state = 'draining'
        turn = _meta_json(store, 'upgrade:node:' + me)
    if state == 'draining':
        if len(steps) > 1 and now - float(turn.get('at') or 0) < UPGRADE_DRAIN_S:
            return
        meta = _meta_json(store, 'upgrade:pkg') or {}
        try:
            if meta.get('sha') != plan['sha']:
                raise ValueError('the package in the database is not the one this upgrade '
                                 'was started with')
            path = upgrade_package_file(store, meta)
            req = {'id': plan['id'], 'file': path.name, 'sha': plan['sha'],
                   'version': plan['version'], 'by': plan.get('by'), 'at': now,
                   'downgrade': bool(plan.get('downgrade'))}
            tmp = UPGRADE_DIR / 'request.part'
            try:
                tmp.unlink()
            except OSError:
                pass
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'w') as f:
                json.dump(req, f)
            os.replace(str(tmp), str(UPGRADE_DIR / 'request.json'))
        except Exception as e:                          # noqa: BLE001
            _upgrade_failed(store, plan, turn, 'the package could not be handed over: %s' % e)
            return
        _my_step(store, plan, state='installing', asked=now,
                 said='handed to root (upsmon-upgrade.service)')
        log('the upgrade to %s is handed to upsmon-upgrade.service' % plan['version'])
        return
    if state == 'installing':
        if __version__ == plan['version'] and float(daemon.started or 0) > \
                float(turn.get('asked') or 0):
            _my_step(store, plan, state='checking', said='restarted as %s' % __version__)
            state = 'checking'
            turn = _meta_json(store, 'upgrade:node:' + me)
        else:
            got = _helper_status()
            if got.get('id') == plan['id'] and got.get('state') == 'failed':
                _upgrade_failed(store, plan, turn, got.get('said') or
                                'install.sh ended with %s' % got.get('rc'),
                                tail=got.get('tail'))
                return
            if not (UPGRADE_DIR / 'request.json').exists() and \
                    not (UPGRADE_DIR / 'request.taken').exists() and \
                    got.get('id') != plan['id'] and now - float(turn.get('asked') or now) > 120:
                _upgrade_failed(store, plan, turn, 'upsmon-upgrade.service never took the request '
                                '- is upsmon-upgrade.path installed and running? (install.sh '
                                '--upgrade once on the command line puts it in)')
                return
            if now - float(turn.get('asked') or now) > UPGRADE_TIMEOUT_S:
                _upgrade_failed(store, plan, turn, 'it has not come back as %s in %d min'
                                % (plan['version'], UPGRADE_TIMEOUT_S // 60))
                return
            # How far install.sh is (1.0.67): its sections, "==> ...", for the
            # bar on the pages - written when one more has begun.
            if got.get('id') == plan['id'] and got.get('state') == 'running':
                parts = [x[4:].strip() for x in upgrade_log_tail(400) if x.startswith('==> ')]
                if parts and len(parts) != int(turn.get('part') or 0):
                    _my_step(store, plan, part=len(parts), part_words=parts[-1][:120],
                             asked=turn.get('asked'))
            return
    if state == 'checking':
        trouble = []
        try:
            store.db.value('SELECT 1')
        except Exception as e:                          # noqa: BLE001
            trouble.append('the database: %s' % e)
        got = _helper_status()
        if got.get('id') == plan['id'] and got.get('state') == 'running':
            if now - float(turn.get('at') or now) < 600:
                return                  # install.sh is still finishing (the firewall, its checks)
            # Not done just because it took long (1.0.44).
            trouble.append('install.sh has not said it finished in 10 min (see '
                           'journalctl -u upsmon-upgrade)')
        if got.get('id') == plan['id'] and got.get('state') == 'failed':
            trouble.append(got.get('said') or 'install.sh ended with %s' % got.get('rc'))
        if trouble:
            _upgrade_failed(store, plan, turn, '; '.join(trouble), tail=got.get('tail'))
            return
        if not turn.get('was_maint'):
            maintenance_set(store, False, by=plan.get('by') or '')
        _my_step(store, plan, state='done', said='%s, checked, back in service' % __version__,
                 tail=(got.get('tail') or [])[-12:])
        store.add_event('starting and stopping', '%s is upgraded to %s' % (me, __version__))
        log('upgraded to %s and back in service' % __version__)
        if all((s.get('state') == 'done') or s['name'] == me for s in steps):
            store.add_event('starting and stopping', 'the upgrade to %s is done on every node'
                            % plan['version'])


def _peer_still_at_it(turn):
    """Its own row read in its own database (1.0.61): while it runs the new
    version, what it writes does not come over to this one - its heartbeat
    looks stale, and a node that was fine was marked failed."""
    try:
        far = ha_peer_db()
    except Exception:                                   # noqa: BLE001
        return False                    # not reachable either: gone indeed
    try:
        row = json.loads(far.value('SELECT v FROM meta WHERE k = ?',
                                   ('upgrade:node:' + turn['name'],)) or '{}')
        beat = json.loads(far.value('SELECT v FROM meta WHERE k = ?',
                                    ('node:' + turn['name'],)) or '{}')
        return row.get('state') == 'done' or now_minus(row.get('at')) < 600 or \
            now_minus(beat.get('at')) < 120
    except Exception:                                   # noqa: BLE001
        return False
    finally:
        try:
            far.close()
        except Exception:                               # noqa: BLE001
            pass


def _back_after_marked(store, plan):
    """A node the other one marked failed while it drained, come back on
    its old version (1.0.61): taken out of the maintenance the upgrade put
    it in, once - nothing else would."""
    me = node_name()
    row = _meta_json(store, 'upgrade:node:' + me) or {}
    if row.get('id') != plan.get('id') or row.get('state') != 'failed' or \
            not row.get('marked_by') or row.get('back') or __version__ == plan.get('version'):
        return
    if not row.get('was_maint'):
        try:
            maintenance_set(store, False, by=plan.get('by') or '')
        except Exception:                               # noqa: BLE001
            return
    row['back'] = True
    try:
        _row_write(store, 'upgrade:node:' + me, row, mine=False)
    except Exception:                                   # noqa: BLE001
        pass
    log('back in service: the upgrade had been marked failed by %s while this node waited'
        % row.get('marked_by'), 'warn')


def now_minus(at):
    try:
        return time.time() - float(at or time.time())
    except (TypeError, ValueError):
        return 0.0


def _upgrade_failed(store, plan, turn, said, tail=None):
    # Already running the new version and its checks failed (1.0.59): kept
    # in maintenance - it is the broken version that would be put in service.
    # Only once it has started again as that version (1.0.61): the same
    # version put in again, failing before anything was installed, left a
    # working node out.
    broken_new = __version__ == plan.get('version') and turn.get('state') == 'checking'
    if broken_new:
        said = '%s - left in maintenance: it runs %s, which did not pass its checks' % (
            said, __version__)
    _my_step(store, plan, state='failed', said=str(said)[:500], tail=(tail or [])[-40:])
    # Back in service where it still runs as it did: a failed upgrade must
    # not leave a working node out.
    if not turn.get('was_maint') and not broken_new:
        try:
            maintenance_set(store, False, by=plan.get('by') or '')
        except Exception:                               # noqa: BLE001
            pass
    store.add_event('starting and stopping', 'the upgrade of %s to %s failed: %s'
                    % (node_name(), plan['version'], said), 'bad')
    log('the upgrade to %s failed: %s' % (plan['version'], said), 'error')


def ha_refresh_tables(store):
    return None


ONLINE_PKG_RE = re.compile(r'(?:^|/)(upsmon-(\d+)\.(\d+)\.(\d+)\.tar\.gz)(?:\?|#|$)')
ONLINE_EVERY_S = 86400
ONLINE_WORK = {'busy': False, 'at': 0.0}
ONLINE_LOCK = threading.Lock()


def _online_get(url, limit=4 * 1024 * 1024, accept='*/*', timeout=30):
    if not str(url).startswith('https://'):
        raise ValueError('only https:// addresses are asked: %s' % url)
    req = urllib.request.Request(url, headers={
        'User-Agent': 'upsmon/%s (+upgrade check)' % __version__, 'Accept': accept})
    ctx = ssl.create_default_context()
    with url_open(req, timeout=timeout, context=ctx) as r:
        final = r.geturl()
        if not str(final).startswith('https://'):
            raise ValueError('it was sent on to an address that is not https: %s' % final)
        data = r.read(limit + 1)
        if len(data) > limit:
            raise ValueError('the answer from %s is bigger than %d MB' % (url, limit >> 20))
        return data, r.headers.get('Content-Type') or '', final


def _online_ver(m):
    return tuple(int(x) for x in m.group(2, 3, 4))


# Where the releases were before 1.0.138: a value saved as it was the default
# then is taken as the new place.
ONLINE_URL_OLD = 'https://github.com/falco81/UPSMon/tree/main/releases'


def online_url():
    url = str(CONFIG.get('upgrade_url') or '').strip()
    return DEFAULTS['upgrade_url'] if url.rstrip('/') == ONLINE_URL_OLD else url


def online_list(url):
    """The packages at `url`: [{'name', 'version', 'url', 'bytes'}], newest first."""
    url = str(url or '').strip()
    if not url:
        raise ValueError('no address to look at (Settings → Upgrades)')
    found = {}

    def add(name, link, size=None):
        m = ONLINE_PKG_RE.search('/' + name)
        if not m or not str(link).startswith('https://'):
            return
        found[m.group(1)] = {'name': m.group(1), 'version': '%d.%d.%d' % _online_ver(m),
                             'v': _online_ver(m), 'url': link, 'bytes': size}

    gh = re.match(r'^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)'
                  r'(?:/tree/([^/]+)(?:/(.*?))?)?/?$', url)
    m1 = ONLINE_PKG_RE.search(urllib.parse.urlparse(url).path)
    if m1:
        # One package's own address - a GitHub page of it read as the file.
        link = url
        b = re.match(r'^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$', url)
        if b:
            link = 'https://raw.githubusercontent.com/%s/%s/%s' % b.groups()
        add(m1.group(1), link)
    elif gh:
        owner, repo, ref, folder = gh.group(1), gh.group(2), gh.group(3), gh.group(4) or ''
        api = 'https://api.github.com/repos/%s/%s/contents/%s' % (
            owner, repo, urllib.parse.quote(folder.strip('/')))
        if ref:
            api += '?ref=' + urllib.parse.quote(ref)
        try:
            data, _ct, _f = _online_get(api, accept='application/vnd.github+json')
            items = json.loads(data.decode('utf-8'))
        except Exception as e:                          # noqa: BLE001
            # GitHub's API refused (60 questions an hour without an account,
            # or not let through): the folder's own page, read for the names.
            try:
                data, _ct, _f = _online_get(url)
            except Exception:                           # noqa: BLE001
                raise ValueError('GitHub did not answer: %s' % (getattr(e, 'reason', None) or e))
            items = []
            base = 'https://raw.githubusercontent.com/%s/%s/%s/%s' % (
                owner, repo, ref or 'HEAD', (folder.strip('/') + '/') if folder.strip('/') else '')
            for name in set(re.findall(r'upsmon-\d+\.\d+\.\d+\.tar\.gz',
                                       data.decode('utf-8', 'replace'))):
                items.append({'type': 'file', 'name': name, 'download_url': base + name})
        if isinstance(items, dict):
            items = [items]
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and it.get('type') == 'file' and it.get('download_url'):
                add(str(it.get('name') or ''), str(it['download_url']), it.get('size'))
    else:
        data, ct, final = _online_get(url)
        text = data.decode('utf-8', 'replace')
        try:
            items = json.loads(text) if 'json' in ct or text.lstrip()[:1] in '[{' else None
        except ValueError:
            items = None
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    link = it.get('download_url') or it.get('url') or ''
                    add(str(it.get('name') or link), urllib.parse.urljoin(final, str(link)),
                        it.get('size'))
        else:
            for href in re.findall(r'''href\s*=\s*["']([^"']+)["']''', text, re.I):
                link = urllib.parse.urljoin(final, html.unescape(href))
                mm = ONLINE_PKG_RE.search(urllib.parse.urlparse(link).path)
                if mm:
                    add(mm.group(1), link)
    out = sorted(found.values(), key=lambda x: x['v'], reverse=True)
    for x in out:
        x.pop('v', None)
    return out


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in str(v).split('.')[:3])
    except ValueError:
        return (0, 0, 0)


def online_look(store, by=''):
    """Asks the address now; what it found goes into meta 'upgrade:online'."""
    url = online_url()
    row = {'at': time.time(), 'url': url, 'by': by, 'node': node_name(), 'here': __version__}
    try:
        got = online_list(url)
        row['packages'] = got[:10]
        newest = got[0] if got else None
        row['newest'] = newest
        row['newer'] = bool(newest and _ver_tuple(newest['version']) > _ver_tuple(__version__))
        if row['newer']:
            was = _meta_json(store, 'upgrade:online') or {}
            if ((was.get('newest') or {}).get('version') != newest['version']):
                store.add_event('starting and stopping', 'upsmon %s is out (%s) - Settings → '
                                'Upgrades' % (newest['version'], url), 'info')
    except Exception as e:                              # noqa: BLE001
        row['error'] = str(getattr(e, 'reason', None) or e).split('\n')[0][:300]
    store.set_meta('upgrade:online', json.dumps(row, default=str))
    return row


def online_tick(daemon):
    """Once a day, from whichever node it falls to first."""
    if not CONFIG.get('upgrade_check') or not online_url():
        return
    if time.time() - float(ONLINE_WORK['at'] or 0) < 300:
        return
    ONLINE_WORK['at'] = time.time()
    store = daemon.store
    last = _meta_json(store, 'upgrade:online') or {}
    # Asked again once the address changed, or a day after the last look.
    if last.get('url') == online_url() and \
            time.time() - float(last.get('at') or 0) < ONLINE_EVERY_S:
        return
    with ONLINE_LOCK:
        if ONLINE_WORK['busy']:
            return
        ONLINE_WORK['busy'] = True

    def go():
        try:
            online_look(store)
        except Exception as e:                          # noqa: BLE001
            log('looking for a new version: %s' % e, 'warn')
        finally:
            ONLINE_WORK['busy'] = False
    threading.Thread(target=go, name='upsmon-online', daemon=True).start()


def online_view(store):
    row = _meta_json(store, 'upgrade:online') or {}
    if row:
        n = row.get('newest') or {}
        row['newer'] = bool(n and _ver_tuple(n.get('version')) > _ver_tuple(__version__))
        row['here'] = __version__
        # Every version there newer than this one, newest first (1.0.142): with
        # more than one the page lets you choose which to go to.
        row['newer_list'] = sorted(
            (p for p in row.get('packages') or []
             if _ver_tuple(p.get('version')) > _ver_tuple(__version__)),
            key=lambda p: _ver_tuple(p.get('version')), reverse=True)
    return {'online': row, 'url': online_url(),
            'check': bool(CONFIG.get('upgrade_check'))}


def online_fetch(store, version, by, older=False):
    """The package of `version` fetched from where it was found, checked and
    kept as one sent by hand would be: its meta. `older`: one to go back to
    (1.0.143), kept only if downgrade_take finds nothing in its way."""
    pk = [p for p in online_list(online_url())
          if p['version'] == str(version)]
    if not pk:
        raise ValueError('upsmon %s is not at %s any more' % (version, online_url()))
    pk = pk[0]
    if older and _ver_tuple(pk['version']) >= _ver_tuple(__version__):
        raise ValueError('upsmon %s is not older than %s, which runs here' % (pk['version'],
                                                                           __version__))
    if not older and _ver_tuple(pk['version']) <= _ver_tuple(__version__):
        raise ValueError('upsmon %s is not newer than %s, which runs here' % (pk['version'], __version__))
    UPGRADE_DIR.mkdir(mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='online-', suffix='.tar.gz', dir=str(UPGRADE_DIR))
    os.close(fd)
    tmp = Path(tmp)
    try:
        data, _ct, final = _online_get(pk['url'], limit=UPGRADE_MOST, timeout=300)
        tmp.write_bytes(data)
        try:
            info = upgrade_inspect(tmp)
        except ValueError as e:
            store.add_event('starting and stopping', 'upsmon %s from %s was refused: %s'
                            % (version, final, e), 'warn', who=by)
            raise ValueError('the package from %s was refused: %s' % (final, e))
        if older:
            if not info.get('older') and _ver_tuple(info['version']) >= _ver_tuple(__version__):
                raise ValueError('%s is not older than %s' % (info['version'], __version__))
            return downgrade_take(store, tmp, info, by)
        if info.get('older'):
            raise ValueError('%s is older than %s, which runs here' % (info['version'],
                                                                         info.get('installed')))
        meta = upgrade_store_package(store, tmp, info, by)
        store.add_event('starting and stopping', '%s fetched upsmon %s from %s (signed by %s), '
                        'ready to be put in' % (by, meta['version'], final, meta.get('signed_by')),
                        'warn', who=by)
        return meta
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass




# ======== carried over from OTP 1.0.187 (lines 22279-22504): proxy ========
# ---- going out through a proxy (1.0.166) --------------------------------------------
# Settings → Proxy: what upsmon asks of the web itself - the new versions, the SMS
# gateway - and, handed to the root helper in its request (never on a command
# line), dnf or apt fetching the system updates. Mail, Active Directory, the
# database, syslog and the other node never go through it.
def proxy_on(purpose='web'):
    if not CONFIG.get('proxy') or not str(CONFIG.get('proxy_url') or '').strip():
        return False
    if purpose == 'sms':
        return bool(CONFIG.get('proxy_sms', 1))
    if purpose == 'os':
        return bool(CONFIG.get('proxy_os', 1))
    return True


def proxy_full(purpose='web'):
    """The proxy's address with its user and password in it, for urllib, dnf
    and apt - '' where none is to be used. Never logged, never shown."""
    if not proxy_on(purpose):
        return ''
    url = str(CONFIG.get('proxy_url') or '').strip().rstrip('/')
    user = str(CONFIG.get('proxy_user') or '').strip()
    if not user:
        return url
    pw = unseal_secret(CONFIG.get('proxy_password') or '') or ''
    scheme, _, rest = url.partition('://')
    return '%s://%s:%s@%s' % (scheme, urllib.parse.quote(user, safe=''),
                              urllib.parse.quote(pw, safe=''), rest)


def proxy_no_list():
    return [w.strip().lower() for w in re.split(r'[\s,;]+', str(CONFIG.get('proxy_no') or ''))
            if w.strip()]


def proxy_skips(host):
    """Whether this host is reached straight, as proxy_no says."""
    host = str(host or '').strip('[]').lower()
    if not host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for one in proxy_no_list():
        if one == '*':
            return True
        if ip is not None and ('/' in one or re.match(r'^[0-9a-f.:]+\Z', one)):
            try:
                if ip in ipaddress.ip_network(one.strip('[]'), strict=False):
                    return True
            except ValueError:
                pass
            continue
        one = one.lstrip('*')
        if one.startswith('.'):
            if host.endswith(one) or host == one[1:]:
                return True
        elif host == one:
            return True
    return False


class _ProxyOnly(urllib.request.ProxyHandler):
    """ProxyHandler without its look at no_proxy in the environment: only
    proxy_no says what goes straight."""
    def proxy_open(self, req, proxy, type):
        proxy_type, user, password, hostport = urllib.request._parse_proxy(proxy)
        if user and password:
            creds = base64.b64encode(('%s:%s' % (urllib.parse.unquote(user),
                                                 urllib.parse.unquote(password))).encode())
            req.add_header('Proxy-authorization', 'Basic ' + creds.decode('ascii'))
        req.set_proxy(urllib.parse.unquote(hostport), proxy_type or req.type)
        return None


def url_open(req, timeout=30, context=None, purpose='web'):
    """urllib.request.urlopen, through the proxy where one is set and the host
    is not one reached straight; never through what the environment says."""
    if not isinstance(req, urllib.request.Request):
        req = urllib.request.Request(req)
    proxy = proxy_full(purpose)
    host = urllib.parse.urlsplit(req.full_url).hostname or ''
    handlers = [_ProxyOnly(
        {'http': proxy, 'https': proxy} if proxy and not proxy_skips(host) else {})]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(req, timeout=timeout)


def proxy_try(url=''):
    """Settings → Proxy → Try it (1.0.169): an address asked the way upsmon asks
    the web - through the proxy where one is set and the address is not one
    reached straight, else straight - one step at a time: the name looked up,
    the connection, the tunnel through the proxy, TLS and the certificate,
    the answer. Always tried; each step with how long it took."""
    url = str(url or '').strip() or online_url() or 'https://github.com/'
    if not re.match(r'^https?://[^\s/]+[^\s]*\Z', url):
        raise ValueError('an address starting https:// (or http://)')
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ''
    tls_on = u.scheme == 'https'
    port = u.port or (443 if tls_on else 80)
    via, why = '', ''
    if not proxy_on():
        why = 'no proxy is set' if not CONFIG.get('proxy') else 'the proxy has no address'
    elif proxy_skips(host):
        why = '%s is in the list reached straight' % host
    else:
        via = proxy_full()
    px = urllib.parse.urlsplit(via) if via else None
    out = {'url': url, 'host': host, 'port': port, 'mode': 'proxy' if via else 'direct',
           'why_direct': why, 'node': node_name(), 'steps': [], 'ok': False,
           'proxy': '%s:%d' % (px.hostname, px.port or 3128) if px else '',
           'proxy_auth': bool(px and px.username)}
    began = time.time()
    sock = [None]

    def step(what, fn):
        t0 = time.time()
        try:
            said = fn() or ''
        except Exception as e:                          # noqa: BLE001
            out['steps'].append({'what': what, 'ok': False, 'ms': int((time.time() - t0) * 1000),
                                 'said': str(getattr(e, 'reason', '') or e)[:300]})
            raise
        out['steps'].append({'what': what, 'ok': True, 'ms': int((time.time() - t0) * 1000),
                             'said': said})

    def resolve(name, p):
        got = socket.getaddrinfo(name, p, 0, socket.SOCK_STREAM)
        addrs = []
        for g in got:
            if g[4][0] not in addrs:
                addrs.append(g[4][0])
        out.setdefault('addrs', {})[name] = addrs
        return ', '.join(addrs[:4])

    def connect(name, p):
        sock[0] = socket.create_connection((name, p), timeout=10)
        sock[0].settimeout(15)
        peer = sock[0].getpeername()
        return '%s port %d' % (peer[0], peer[1])

    def read_head():
        data = b''
        while b'\r\n\r\n' not in data and len(data) < 65536:
            chunk = sock[0].recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
        m = re.match(r'^HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)$', line)
        if not m:
            raise ValueError('no HTTP answer: %r' % line[:80])
        return int(m.group(1)), m.group(2).strip(), data

    def auth_header():
        if not (px and px.username):
            return ''
        creds = '%s:%s' % (urllib.parse.unquote(px.username), urllib.parse.unquote(px.password or ''))
        return 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(creds.encode()).decode()

    try:
        if via:
            step('the proxy looked up (%s)' % px.hostname, lambda: resolve(px.hostname, px.port or 3128))
            step('connected to the proxy', lambda: connect(px.hostname, px.port or 3128))
            if tls_on:
                def tunnel():
                    sock[0].sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%s'
                                     'User-Agent: upsmon/%s (+proxy check)\r\n\r\n' % (
                                         host, port, host, port, auth_header(), __version__)).encode())
                    code, words, _ = read_head()
                    if code == 407:
                        raise ValueError('the proxy asks for a user name and a password (407) - '
                                         'they are %s' % ('wrong' if px.username else 'missing'))
                    if code != 200:
                        raise ValueError('the proxy said %d %s' % (code, words))
                    return '%d %s%s' % (code, words, ' - with the user name and password'
                                        if px.username else '')
                step('a tunnel through the proxy to %s:%d' % (host, port), tunnel)
        else:
            step('%s looked up' % host, lambda: resolve(host, port))
            step('connected to %s' % host, lambda: connect(host, port))
        if tls_on:
            def handshake():
                ctx = ssl.create_default_context()
                sock[0] = ctx.wrap_socket(sock[0], server_hostname=host)
                c = sock[0].getpeercert() or {}
                subj = dict(x[0] for x in c.get('subject', ()) if x)
                iss = dict(x[0] for x in c.get('issuer', ()) if x)
                out['tls'] = {'version': sock[0].version(), 'cipher': (sock[0].cipher() or [''])[0],
                              'subject': subj.get('commonName', ''),
                              'issuer': iss.get('organizationName') or iss.get('commonName', ''),
                              'until': c.get('notAfter', '')}
                return '%s, %s - %s, by %s' % (out['tls']['version'], out['tls']['cipher'],
                                               out['tls']['subject'], out['tls']['issuer'])
            step('TLS, the certificate of %s checked' % host, handshake)

        def ask():
            path = (u.path or '/') + ('?' + u.query if u.query else '')
            target = url if (via and not tls_on) else path
            sock[0].sendall(('HEAD %s HTTP/1.1\r\nHost: %s\r\n%sUser-Agent: upsmon/%s (+proxy check)'
                             '\r\nConnection: close\r\n\r\n' % (
                                 target, u.netloc.split('@')[-1],
                                 auth_header() if (via and not tls_on) else '', __version__)).encode())
            code, words, _ = read_head()
            out['status'] = code
            if code == 407:
                raise ValueError('the proxy asks for a user name and a password (407)')
            return '%d %s' % (code, words)
        step('asked for %s' % (u.path or '/'), ask)
        out['ok'] = True
    except Exception:                                   # noqa: BLE001
        pass
    finally:
        try:
            if sock[0]:
                sock[0].close()
        except OSError:
            pass
    out['ms'] = int((time.time() - began) * 1000)
    return out





# ======== carried over from OTP 1.0.187 (lines 23091-23358): going back to an older version ========
# ---- going back to an older version (1.0.143) ---------------------------------------
# Never by putting a database back: the tables stay as they are - every column
# a newer version added is one an older one leaves alone (they are all added
# NULL) - and the older program runs on them. That is safe only for a version
# that reads what the newer ones wrote, so each version says how far back it
# may go (DOWNGRADE_FLOOR), and going back is refused below the highest floor
#   * of any version that ran on this database (each node keeps its own in
#     'downgrade:floor:NODE' - one writer a row, as replication wants), and
#   * of any version installed on this machine (install.sh keeps it in
#     /usr/local/lib/upsmon/downgrade-floor, root's alone: the upsmon account cannot
#     lower it, so it cannot take the server back to a version with a hole);
# and the package itself is looked at before anything is put in: a column the
# database has as NOT NULL with no default that the older version does not
# know would make every row it writes there fail. Then it goes the road of an
# upgrade - one node at a time, each in maintenance while it is done.
DOWNGRADE_FLOOR_FILE = UPGRADE_HELPER.parent / 'downgrade-floor'


def downgrade_floor_note(store):
    """This node's floor in the database: the highest of what it had and what
    this version says."""
    k = 'downgrade:floor:' + node_name()
    had = _meta_json(store, k) or {}
    if had and _ver_tuple(had.get('floor')) >= _ver_tuple(DOWNGRADE_FLOOR):
        return
    store.set_meta(k, json.dumps({'floor': DOWNGRADE_FLOOR, 'version': __version__,
                                  'at': time.time()}))


def downgrade_db_floor(store):
    """(floor, set by): the highest floor of any version that ran on this
    database, on any node."""
    best, by = DOWNGRADE_FLOOR, '%s (%s)' % (__version__, node_name())
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'downgrade:floor:%'"):
        try:
            got = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(got, dict) and _ver_tuple(got.get('floor')) > _ver_tuple(best):
            best, by = str(got['floor']), '%s (%s)' % (got.get('version'),
                                                      r['k'][len('downgrade:floor:'):])
    return best, by


def downgrade_root_floor():
    """The floor root keeps, or None where no version that knows it was ever
    installed here."""
    try:
        text = DOWNGRADE_FLOOR_FILE.read_text().strip()
    except OSError:
        return None
    return text if re.match(r'^\d+\.\d+\.\d+\Z', text) else None


def downgrade_why_not(store, version):
    """What stands in the way of going back to `version` - before the package
    is fetched: [] when nothing does."""
    why = []
    v = _ver_tuple(version)
    if v >= _ver_tuple(__version__):
        why.append('%s is not older than %s, which runs here - that is an upgrade'
                   % (version, __version__))
        return why
    floor, by = downgrade_db_floor(store)
    if v < _ver_tuple(floor):
        why.append('older than %s: upsmon %s, which ran on this database, wrote what older '
                   'versions do not read the same (or have holes it fixed)' % (floor, by))
    root = downgrade_root_floor()
    if root is None:
        why.append('this machine was never upgraded on the command line to a version that '
                   'can go back (install.sh --upgrade once)')
    elif v < _ver_tuple(root):
        why.append('older than %s, the oldest the versions installed on this machine allow'
                   % root)
    return why


def downgrade_live_strict(db):
    """{table: [column]} - the columns of this database that are NOT NULL and
    have no default: a row written without one of them fails."""
    out = {}
    if db.engine == 'sqlite':
        for t in ('meta', 'settings', 'events', 'accounts', 'sessions'):
            for r in db.rows('PRAGMA table_info(%s)' % t):
                if r['notnull'] and r['dflt_value'] is None and not r['pk']:
                    out.setdefault(t, []).append(str(r['name']).lower())
        return out
    if db.engine == 'postgres':
        rows = db.rows("SELECT table_name AS t, column_name AS c FROM information_schema.columns "
                       "WHERE table_schema = current_schema() AND is_nullable = 'NO' "
                       "AND column_default IS NULL")
    else:
        rows = db.rows("SELECT table_name AS t, column_name AS c FROM information_schema.columns "
                       "WHERE table_schema = DATABASE() AND is_nullable = 'NO' "
                       "AND column_default IS NULL AND extra NOT LIKE '%auto_increment%'")
    for r in rows:
        t, c = str(r['t']).lower(), str(r['c']).lower()
        if c != 'id':
            out.setdefault(t, []).append(c)
    return out


# Run in a process of its own, on the package's own upsmon.py: its tables as it
# makes them, made in a database in memory and read back.
_DOWNGRADE_SCHEMA_PY = r'''
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
sys.argv = ['upsmon']
import upsmon_admin as m
c = sqlite3.connect(':memory:')
c.executescript(m.SCHEMA)
out = {}
for (name,) in list(c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")):
    out[name] = [str(r[1]).lower() for r in c.execute('PRAGMA table_info(%s)' % name)]
print(json.dumps({'version': m.__version__, 'tables': out}))
'''


def downgrade_package_schema(path):
    """The tables and columns the package's version knows, read off its own
    upsmon.py (the package checked and signed first)."""
    work = Path(tempfile.mkdtemp(prefix='upsmon-down-', dir=str(UPGRADE_DIR)))
    try:
        with tarfile.open(str(path), 'r:gz') as tf:
            member = next((m for m in tf.getmembers()
                           if re.match(r'^upsmon-[0-9.]+/upsmon_admin\.py\Z', m.name) and m.isfile()), None)
            if member is None:
                raise ValueError('the package has no upsmon_admin.py')
            with tf.extractfile(member) as src, open(str(work / 'upsmon_admin.py'), 'wb') as dst:
                shutil.copyfileobj(src, dst)
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8',
               'UPSMON_STATE': str(work), 'UPSMON_CONFIG': str(work / 'none.json'),
               'UPSMON_LOGDIR': str(work), 'UPSMON_RUN': str(work)}
        try:
            r = subprocess.run([sys.executable, '-I', '-c', _DOWNGRADE_SCHEMA_PY, str(work)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
                               env=env, cwd=str(work))
        except subprocess.TimeoutExpired:
            raise ValueError('the tables of the package could not be read in 2 minutes')
        try:
            return json.loads(r.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise ValueError('the tables of the package could not be read: %s'
                             % r.stderr.decode('utf-8', 'replace').strip()[-300:])
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def downgrade_schema_why(store, path):
    """What in this database the package's version could not live with: []
    when nothing."""
    got = downgrade_package_schema(path)
    knows = got.get('tables') or {}
    why = []
    for t, cols in sorted(downgrade_live_strict(store.db).items()):
        if t not in knows:
            continue                    # a table it never writes
        lack = [c for c in cols if c not in knows[t]]
        if lack:
            why.append('the table %s has %s, which upsmon %s does not know and every row needs'
                       % (t, ', '.join(lack), got.get('version')))
    return why


def downgrade_list(store):
    """The older versions at upgrade_url, each with what stands in its way."""
    url = online_url()
    if not url:
        raise ValueError('no upgrade_url is set (Settings → Upgrades)')
    out = []
    for p in online_list(url):
        if _ver_tuple(p['version']) >= _ver_tuple(__version__):
            continue
        out.append(dict(p, why=downgrade_why_not(store, p['version'])))
    out.sort(key=lambda p: _ver_tuple(p['version']), reverse=True)
    floor, by = downgrade_db_floor(store)
    root = downgrade_root_floor()
    # A few words a version for the list (1.0.145) - the reasons in full once.
    lowest = max([floor] + ([root] if root else []), key=_ver_tuple)
    for p in out:
        if not p['why']:
            p['short'] = ''
        elif _ver_tuple(p['version']) < _ver_tuple(lowest):
            p['short'] = 'below %s' % lowest
        elif root is None:
            p['short'] = 'this machine cannot go back yet'
        else:
            p['short'] = p['why'][0][:80]
    return {'url': url, 'here': __version__, 'versions': out, 'floor': floor,
            'floor_by': by, 'root_floor': root, 'lowest': lowest}


def downgrade_take(store, path, info, by):
    """A checked package of an older version kept for going back: refused
    when anything stands in its way. Its meta."""
    why = downgrade_why_not(store, info['version'])
    if not why:
        why = downgrade_schema_why(store, path)
    if why:
        store.add_event('starting and stopping', 'going back to upsmon %s was refused: %s'
                        % (info['version'], '; '.join(why)), 'warn', who=by)
        raise ValueError('upsmon %s cannot be gone back to: %s' % (info['version'], '; '.join(why)))
    meta = upgrade_store_package(store, path, info, by)
    meta['downgrade'] = True
    store.set_meta('upgrade:pkg', json.dumps(meta))
    store.add_event('starting and stopping', '%s made upsmon %s ready to go back to (signed by %s; '
                    'the database checked for it)' % (by, meta['version'], meta.get('signed_by')),
                    'warn', who=by)
    return meta


def downgrade_fetch(store, version, by):
    """The older package from upgrade_url, checked, and kept for going back."""
    why = downgrade_why_not(store, version)
    if why:
        raise ValueError('upsmon %s cannot be gone back to: %s' % (version, '; '.join(why)))
    return online_fetch(store, version, by, older=True)


def downgrade_file(store, path, by):
    """An older package from a file (the command line), checked and kept."""
    info = upgrade_inspect(path)
    if not info.get('older'):
        raise ValueError('upsmon %s is not older than %s, which runs here - that is an upgrade'
                         % (info['version'], info.get('installed') or __version__))
    return downgrade_take(store, path, info, by)


def changelog_sections(text):
    """{version: its section of CHANGELOG.md, heading and all}."""
    out = {}
    for m in re.finditer(r'^## (\d+\.\d+\.\d+)\b.*?(?=^## |\Z)', text or '', re.M | re.S):
        out[m.group(1)] = m.group(0).strip()[:20000]
    return out


def downgrade_changelog(version):
    """What came in `version`, and what going back to it from here gives up -
    the sections of the versions after it, up to this one (1.0.144). From the
    CHANGELOG.md installed beside upsmon.py; where that does not have it, from
    the package at upgrade_url (read, not yet checked)."""
    version = str(version or '')
    if not re.match(r'^\d+\.\d+\.\d+\Z', version):
        raise ValueError('which version?')
    try:
        here = changelog_sections((Path(__file__).resolve().parent / 'CHANGELOG.md')
                                  .read_text(encoding='utf-8', errors='replace'))
    except OSError:
        here = {}
    lost = [{'version': v, 'text': here[v]} for v in sorted(
        here, key=_ver_tuple, reverse=True)
        if _ver_tuple(version) < _ver_tuple(v) <= _ver_tuple(__version__)]
    entry, src = here.get(version), 'here'
    if entry is None:
        src = 'package'
        pk = next((p for p in online_list(online_url()) if p['version'] == version), None)
        if not pk:
            raise ValueError('upsmon %s is not at %s' % (version, online_url()))
        data, _ct, _final = _online_get(pk['url'], limit=UPGRADE_MOST, timeout=120)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
            m = next((x for x in tf.getmembers() if x.isfile() and
                      x.name == 'upsmon-%s/CHANGELOG.md' % version), None)
            text = tf.extractfile(m).read(4 << 20).decode('utf-8', 'replace') if m else ''
        entry = changelog_sections(text).get(version) or ''
    return {'version': version, 'here': __version__, 'entry': entry, 'from': src,
            'lost': lost}




# ======== carried over from OTP 1.0.187 (lines 23359-24080): TLS ========
# ---------------------------------------------------------------------------
# The web side (1.0.47): TLS of each node and of the cluster's VIP address,
# and that address itself (VIP, active/standby, held by keepalived).
#
# Everything is kept in the database, so both nodes know all of it:
#   web:vip          the address, its name, the VRRP id, the node it is meant
#                    to be on, each node's interface
#   web:tls:NODE     a node's own certificate, chain, root and TLS settings
#   web:tls:vip      the same for the VIP address's own name
# Keys are sealed with the tokens' key. Each node then asks root for its own
# part of it (upsmon_web.py, through /var/lib/upsmon/web/request.json) and keeps
# /run/upsmon/vip-state up to date for keepalived: whether this node is healthy
# enough to hold the address - its own pages answering /healthz end to end
# (nginx, PHP, the daemon, the database), RADIUS listening, not in
# maintenance, not being upgraded or rebuilt - and whether it is the one the
# address is meant to be on.
# ---------------------------------------------------------------------------
WEB_DIR = STATE_DIR / 'web'
VIP_STATE = RUN_DIR / 'vip-state'
VIP_ROLE = RUN_DIR / 'vip-role'
VIP_HERE_BY_ROLE = bool(os.environ.get('UPSMON_VIP_HERE_BY_ROLE'))
WEB_HELPER = Path(__file__).parent / 'upsmon_web.py'
VIP_FAILS_BEFORE = 2
VIP_HEALTH_URL = os.environ.get('UPSMON_VIP_HEALTH_URL', 'https://127.0.0.1/healthz')                    # checks in a row before it is said unhealthy
TLS_PRESETS = {
    # The ciphers upsmon has always used: ECDHE only, AEAD only.
    'standard': {'protocols': ['TLSv1.2', 'TLSv1.3'], 'ciphers': (
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305')},
    # Mozilla's "intermediate": the same and the DHE ones (DH parameters).
    'intermediate': {'protocols': ['TLSv1.2', 'TLSv1.3'], 'ciphers': (
        'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
        'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305')},
    # Mozilla's "modern": TLS 1.3 alone - its ciphers are not chosen.
    'modern': {'protocols': ['TLSv1.3'], 'ciphers': ''},
}
DH_WORDS = {'none': 'none (ECDHE only needs none)',
            'ffdhe2048': 'RFC 7919 ffdhe2048', 'ffdhe3072': 'RFC 7919 ffdhe3072',
            'ffdhe4096': 'RFC 7919 ffdhe4096', 'gen2048': 'made here, 2048 bits',
            'gen3072': 'made here, 3072 bits (a minute or so)',
            'gen4096': 'made here, 4096 bits (several minutes)'}
WEB_LOCK = threading.Lock()
VIP_HEALTH = {'ok': None, 'why': '', 'fails': 0, 'at': 0.0}


def _json_meta(store, k):
    try:
        got = json.loads(store.get_meta(k) or 'null')
        return got if isinstance(got, dict) else None
    except ValueError:
        return None


def vip_conf(store):
    return _json_meta(store, 'web:vip') or {'on': False}


def tls_profile(store, target):
    return _json_meta(store, 'web:tls:' + target)


def vip_auth():
    """The VRRP password: the same on every node, from the tokens' key."""
    key = sealing_key() or b''
    raw = hmac.new(key, b'upsmon-vip-vrrp', hashlib.sha256).digest()
    abc = string.ascii_letters + string.digits
    return ''.join(abc[b % len(abc)] for b in raw[:8])


VIP_MOVE_S = 60          # a move asked for by hand, in 'stays' mode, is wanted this long


def vip_moving(conf):
    """The node a move by hand is going to, while it is still under way."""
    to = str(conf.get('move_to') or '')
    if to and time.time() - float(conf.get('move_at') or 0) < VIP_MOVE_S:
        return to
    return ''


def vip_prefer_me(store, conf=None):
    """Is this node the one the address should be on - asked every 3 s.

    'back' (the default): the chosen node, always; the address goes back to it
    as soon as it is healthy. 'stays' (1.0.52): no preference - the node that
    holds it keeps it (keepalived's own state says which: MASTER), until it is
    unhealthy or gone, or until it is moved by hand."""
    conf = conf or vip_conf(store)
    me = node_name()
    if conf.get('mode') != 'stays':
        return vip_prefer(store, conf) == me
    moving = vip_moving(conf)
    if moving:
        return moving == me
    try:
        role = VIP_ROLE.read_text().split()[0]
    except (OSError, IndexError):
        role = ''
    return role == 'MASTER' or (role == '' and vip_here(conf.get('address')))


def vip_prefer(store, conf=None):
    conf = conf or vip_conf(store)
    if conf.get('mode') == 'stays':
        # Whoever holds it now (or is getting it).
        moving = vip_moving(conf)
        if moving:
            return moving
        for n in ha_nodes(store):
            w = web_state(store) if n['me'] else (n.get('web') or {})
            if w.get('vip_here'):
                return n['name']
        return ''
    want = str(conf.get('prefer') or '')
    if want:
        return want
    # Nobody chosen: the first node of the cluster by name - the same answer
    # on both nodes (1.0.59); "this one if it is slot 1" let both pick
    # themselves where the other's name sorted first.
    names = sorted(n['name'] for n in ha_nodes(store))
    return names[0] if names else node_name()


# ---- certificates: read, taken apart, made -----------------------------------
def _openssl(args, data=None, env=None, what='openssl'):
    e = dict(os.environ)
    e.update(env or {})
    got = subprocess.run(['openssl'] + args, input=data, capture_output=True, env=e,
                         timeout=120)
    if got.returncode != 0:
        said = (got.stderr or got.stdout or b'').decode('utf-8', 'replace').strip()
        raise ValueError('%s: %s' % (what, (said.splitlines() or ['openssl said no'])[-1][:200]))
    return got.stdout


PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----')
PEM_KEY = re.compile(r'-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[A-Za-z0-9+/=\s:,-]+?'
                     r'-----END \1-----')


def cert_info(pem):
    """What a certificate says of itself, for the pages."""
    out = _openssl(['x509', '-noout', '-subject', '-issuer', '-startdate', '-enddate',
                    '-fingerprint', '-sha256', '-ext', 'subjectAltName', '-nameopt',
                    'RFC2253'], pem.encode(), what='the certificate').decode()
    info = {'san': []}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('subject='):
            info['subject'] = line[8:].strip()
        elif line.startswith('issuer='):
            info['issuer'] = line[7:].strip()
        elif line.startswith('notBefore='):
            info['not_before'] = _cert_time(line[10:])
        elif line.startswith('notAfter='):
            info['not_after'] = _cert_time(line[9:])
        elif 'Fingerprint=' in line:
            info['fingerprint'] = line.split('=', 1)[1].strip()
        elif 'Subject Alternative Name' in line and i + 1 < len(lines):
            info['san'] = [x.strip().split(':', 1)[-1] for x in lines[i + 1].split(',')
                           if x.strip()]
    info['self_signed'] = info.get('subject') == info.get('issuer')
    cn = re.search(r'(?:^|,)CN=([^,]+)', info.get('subject') or '')
    info['cn'] = cn.group(1) if cn else ''
    try:
        pub = _openssl(['x509', '-noout', '-pubkey'], pem.encode()).decode()
        txt = _openssl(['pkey', '-pubin', '-noout', '-text'], pub.encode()).decode()
        m = re.search(r'\((\d+) bit\)', txt)
        info['key'] = ('%s %s bit' % ('EC' if 'ASN1 OID' in txt or 'NIST' in txt else 'RSA',
                                      m.group(1))) if m else ''
    except ValueError:
        info['key'] = ''
    return info


def _cert_time(text):
    try:
        return datetime.strptime(text.strip().replace('  ', ' '),
                                 '%b %d %H:%M:%S %Y %Z').replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _pub_of_cert(pem):
    return _openssl(['x509', '-noout', '-pubkey'], pem.encode(), what='the certificate')


def _pub_of_key(pem):
    return _openssl(['pkey', '-pubout'], pem.encode(), what='the key')


def key_plain(pem, password=''):
    """A private key without its passphrase, as PEM."""
    return _openssl(['pkey', '-passin', 'env:UPSMON_PW'], pem.encode(),
                    {'UPSMON_PW': password or ''},
                    what='the key (a wrong or missing password?)').decode()


def cert_bundle(cert='', key='', chain='', root='', pfx=b'', password='', pending_key=''):
    """Whatever was sent - one PEM with everything in it, separate parts, or
    a PFX / PKCS#12 with or without a password - as the parts nginx needs:
    the certificate, its key, the chain up from it, the root. The key is the
    certificate's own or nothing is taken."""
    certs, keys = [], []
    if pfx:
        got = None
        for extra in ([], ['-legacy']):
            try:
                got = _openssl(['pkcs12', '-nodes', '-passin', 'env:UPSMON_PW'] + extra, pfx,
                               {'UPSMON_PW': password or ''}, what='the PFX / PKCS#12 file')
                break
            except ValueError as e:
                last = e
        if got is None:
            raise ValueError('%s - is the password right?' % last)
        text = got.decode('utf-8', 'replace')
        certs += [m.group(0) for m in PEM_CERT.finditer(text)]
        keys += [m.group(0) for m in PEM_KEY.finditer(text)]
    for part in (cert, chain, root, key):
        part = str(part or '')
        certs += [m.group(0) for m in PEM_CERT.finditer(part)]
        keys += [m.group(0) for m in PEM_KEY.finditer(part)]
    if not certs:
        raise ValueError('no certificate was found in what was sent (PEM, or a PFX / PKCS#12 '
                         'file)')
    if len(keys) > 1:
        raise ValueError('more than one private key was sent')
    if keys:
        key_pem = key_plain(keys[0], password)
    elif pending_key:
        key_pem = pending_key
    else:
        raise ValueError('no private key came with it: send the key too (or the PFX), or make '
                         'the request here first so the key is waiting')
    want = _pub_of_key(key_pem)
    leaf = next((c for c in certs if _pub_of_cert(c) == want), None)
    if not leaf:
        raise ValueError('none of the certificates is the one of this key')
    others = [c for c in certs if c != leaf]
    infos = {c: cert_info(c) for c in others}
    roots = [c for c in others if infos[c]['self_signed']]
    roots += [m.group(0) for m in PEM_CERT.finditer(str(root or '')) if m.group(0) not in roots]
    inter = [c for c in others if c not in roots]
    # The chain in order: each the issuer of the one before it.
    chain_out, at = [], cert_info(leaf)
    while inter:
        nxt = next((c for c in inter if infos[c].get('subject') == at.get('issuer')), None)
        if not nxt:
            chain_out += inter
            break
        chain_out.append(nxt)
        inter.remove(nxt)
        at = infos[nxt]
    info = cert_info(leaf)
    verify = ''
    if roots:
        with tempfile.TemporaryDirectory(prefix='upsmon-cert-') as t:
            def put(name, text):
                p = os.path.join(t, name)
                with open(p, 'w') as f:
                    f.write(text)
                return p
            args = ['verify', '-CAfile', put('root.pem', '\n'.join(roots) + '\n')]
            if chain_out:
                args += ['-untrusted', put('chain.pem', '\n'.join(chain_out) + '\n')]
            args.append(put('leaf.pem', leaf + '\n'))
            try:
                _openssl(args, what='the chain')
                verify = 'ok'
            except ValueError as e:
                verify = str(e)
    return {'cert': leaf + '\n', 'chain': ''.join(c + '\n' for c in chain_out),
            'root': ''.join(c + '\n' for c in roots), 'key': key_pem, 'info': info,
            'chain_info': [cert_info(c) for c in chain_out],
            'root_info': [cert_info(c) for c in roots], 'verify': verify}


def _san_ext(names):
    out = []
    for n in names:
        n = str(n).strip()
        if not n:
            continue
        try:
            plain_ip(n, 'address')
            out.append('IP:' + n)
        except ValueError:
            if not re.match(r'^(\*\.)?[A-Za-z0-9.-]{1,253}\Z', n):
                raise ValueError('%r is not a name or an address' % n)
            out.append('DNS:' + n)
    return ','.join(out)


def _subject(cn, org='', unit='', country='', city=''):
    def esc(v):
        return re.sub(r'([/\\=+,])', r'\\\1', str(v).strip())
    if not cn or not re.match(r'^[A-Za-z0-9*.-]{1,64}\Z', cn):
        raise ValueError('the common name is a host name')
    s = '/CN=' + esc(cn)
    if org:
        s += '/O=' + esc(org)
    if unit:
        s += '/OU=' + esc(unit)
    if city:
        s += '/L=' + esc(city)
    if country:
        if not re.match(r'^[A-Za-z]{2}\Z', country):
            raise ValueError('the country is two letters (CZ)')
        s += '/C=' + country.upper()
    return s


# The keys Let's Encrypt takes (4.1.6): RSA of 2048, 3072, 4096 bits, ECDSA
# on P-256 or P-384 - for the account and for a certificate alike.
KEY_WORDS = {'ec': 'ECDSA P-256', 'ec384': 'ECDSA P-384', 'rsa2048': 'RSA 2048',
             'rsa3072': 'RSA 3072', 'rsa4096': 'RSA 4096'}
# A certificate's choice: one key, or two certificates - RSA served by
# default, ECDSA to the clients that take it (what Let's Encrypt advises).
ACME_CERT_KEYS = {'dual': ('rsa2048', 'ec'), 'dual-strong': ('rsa4096', 'ec384'),
                  'ec': ('ec',), 'ec384': ('ec384',), 'rsa2048': ('rsa2048',),
                  'rsa3072': ('rsa3072',), 'rsa4096': ('rsa4096',)}


def new_key(kind):
    if kind in ('ec', 'ec256', 'ec384'):
        return _openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt',
                         'ec_paramgen_curve:%s' % ('P-384' if kind == 'ec384' else 'P-256')]).decode()
    bits = {'rsa2048': 2048, 'rsa3072': 3072, 'rsa4096': 4096}.get(kind)
    if not bits:
        raise ValueError('the key is ec, ec384, rsa2048, rsa3072 or rsa4096')
    return _openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt',
                     'rsa_keygen_bits:%d' % bits]).decode()


def make_csr(cn, names, kind='rsa2048', **subject):
    key = new_key(kind)
    with tempfile.TemporaryDirectory(prefix='upsmon-csr-') as t:
        kf = os.path.join(t, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        csr = _openssl(['req', '-new', '-key', kf, '-subj', _subject(cn, **subject),
                        '-addext', 'subjectAltName=' + _san_ext([cn] + list(names))],
                       what='the request').decode()
    return key, csr


def make_selfsigned(cn, names, days=825, kind='rsa2048', **subject):
    key = new_key(kind)
    with tempfile.TemporaryDirectory(prefix='upsmon-crt-') as t:
        kf = os.path.join(t, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        crt = _openssl(['req', '-new', '-x509', '-key', kf, '-days', str(int(days)), '-subj',
                        _subject(cn, **subject), '-addext',
                        'subjectAltName=' + _san_ext([cn] + list(names))],
                       what='the certificate').decode()
    return key, crt


# ---- the TLS of a target, kept ---------------------------------------------------------
def tls_targets(store):
    names = sorted(set([node_name()] + [n['name'] for n in ha_nodes(store)]))
    return names + ['vip']


def tls_save(store, target, prof, by):
    prof = dict(prof)
    prof['at'] = time.time()
    prof['by'] = by
    store.set_meta('web:tls:' + target, json.dumps(prof))


def tls_view(prof):
    """A profile as the pages may see it: no key."""
    if not prof:
        return None
    out = {k: v for k, v in prof.items() if k not in ('key', 'pending_key', 'alt')}
    alt = tls_alt(prof)
    if alt:
        out['alt'] = {'info': alt.get('info') or {}}
    out['has_key'] = bool(prof.get('key'))
    out['pending'] = bool(prof.get('pending_key'))
    return out


def tls_policy_checked(b):
    preset = str(b.get('preset') or 'standard')
    if preset not in list(TLS_PRESETS) + ['custom']:
        raise ValueError('the TLS settings are standard, intermediate, modern or custom')
    out = {'preset': preset}
    if preset == 'custom':
        prot = b.get('protocols') or []
        if not isinstance(prot, list) or not prot or \
                any(p not in ('TLSv1.2', 'TLSv1.3') for p in prot):
            raise ValueError('the protocols are TLSv1.2 and/or TLSv1.3')
        out['protocols'] = [p for p in ('TLSv1.2', 'TLSv1.3') if p in prot]
        ciphers = str(b.get('ciphers') or '').strip()
        if ciphers:
            if not re.match(r'^[A-Za-z0-9_+!@=:.-]{1,2000}\Z', ciphers):
                raise ValueError('the ciphers are an OpenSSL cipher list')
            _openssl(['ciphers', ciphers], what='OpenSSL does not know that cipher list')
        out['ciphers'] = ciphers
    dh = str(b.get('dh') or 'none')
    if dh not in DH_WORDS:
        raise ValueError('the DH parameters are one of %s' % ', '.join(DH_WORDS))
    out['dh'] = dh
    out['prefer'] = bool(b.get('prefer'))
    try:
        # Not said is the two years nginx is shipped with (1.0.94), not none:
        # the first TLS change on the pages dropped HSTS without a word.
        hv = b.get('hsts')
        out['hsts'] = max(0, min(63072000, int(hv) if hv not in (None, '') else 63072000))
    except (TypeError, ValueError):
        raise ValueError('HSTS is a number of seconds')
    hisec_tls(out)                          # 1.0.168
    return out


def tls_alt_for(cert):
    """What ties the ECDSA certificate to its RSA one (4.1.6): a certificate
    put in another way leaves the second one out."""
    return hashlib.sha256((_first_pem(cert) or str(cert or '')).strip().encode()).hexdigest()[:32]


def tls_alt(prof):
    a = (prof or {}).get('alt') or {}
    if a.get('cert') and a.get('key') and prof.get('cert') and \
            a.get('for') == tls_alt_for(prof['cert']):
        return a
    return None


def tls_resolved(prof):
    """What root is handed for a profile: the parts and the lines."""
    if not prof:
        return None
    preset = prof.get('preset') or 'standard'
    p = TLS_PRESETS.get(preset) or {'protocols': prof.get('protocols') or ['TLSv1.2', 'TLSv1.3'],
                                    'ciphers': prof.get('ciphers') or ''}
    out = {'protocols': p['protocols'], 'ciphers': p['ciphers'], 'prefer': bool(prof.get('prefer')),
           'dh': prof.get('dh') or 'none',
           'hsts': int(prof['hsts']) if prof.get('hsts') not in (None, '') else 63072000}
    if prof.get('cert') and prof.get('key'):
        out.update(cert=prof['cert'], chain=prof.get('chain') or '', root=prof.get('root') or '',
                   key=unseal_secret(prof['key'], 'web:tls'))
        alt = tls_alt(prof)
        if alt:
            out['alt'] = {'cert': alt['cert'], 'chain': alt.get('chain') or '',
                          'key': unseal_secret(alt['key'], 'web:tls')}
    return out


# ---- what this node asks of root, and how it went -------------------------------------
def web_desired(store):
    me = node_name()
    v = vip_conf(store)
    vip = {'on': False}
    many = bool(CONFIG.get('ha_mode'))
    if v.get('on') and many:
        vip = {'on': True, 'address': v.get('address'), 'fqdn': v.get('fqdn') or '',
               'address6': v.get('address6') or '',
               'vrid': int(v.get('vrid') or 51), 'auth': vip_auth(),
               'own': CONFIG.get('ha_address') or node_address(),
               'peer': CONFIG.get('ha_peer') or '',
               'iface': (v.get('ifaces') or {}).get(me, '')}
    tls = {'node': tls_resolved(tls_profile(store, me)),
           'vip': tls_resolved(tls_profile(store, 'vip')) if vip['on'] else None}
    out = {'node': me, 'vip': vip, 'tls': tls}
    # Asked only once set on the pages (1.0.52): a request from before had
    # neither, and its hash stays what it was.
    fw, access = fw_desired(store), access_desired(store)
    if fw is not None:
        out['fw'] = fw
    if access is not None:
        out['access'] = access
    # ACME (1.0.169): port 80 answers the CA for the names ordered - the web
    # address's on every node, wherever it is now.
    if CONFIG.get('acme'):
        out['acme'] = acme_http_names(store)
    return out


def web_hash(desired):
    return hashlib.sha256(json.dumps(desired, sort_keys=True).encode()).hexdigest()


def web_status():
    try:
        fd = os.open(str(WEB_DIR / 'status.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(1 << 20).decode('utf-8'))
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


WEB_RETRY_S = int(os.environ.get('UPSMON_WEB_RETRY_S') or 900)


def web_tick(store):
    """Asks root for this node's part when what is wanted has changed."""
    if HA_REBUILDING.is_set() or not WEB_DIR.is_dir():
        return
    desired = web_desired(store)
    # Nothing ever asked and nothing to ask: no request at all.
    st = web_status()
    if not st and not desired['vip']['on'] and not desired['tls']['node'] and \
            'fw' not in desired and 'access' not in desired and 'acme' not in desired:
        return
    h = web_hash(desired)
    if st.get('hash') == h:
        if st.get('state') == 'done':
            # Done, by root's last word - and nginx really has it (1.0.104):
            # a machine put back from its own backup, nginx set up again or
            # a file changed by hand is given what the database says again.
            drift = web_drift(desired)
            if not drift or time.time() - WEB_DRIFT['at'] < 1800:
                return
            WEB_DRIFT['at'] = time.time()
            log('the web certificate in place is not the one wanted (%s): asked again' % drift,
                'warn')
            store.add_event('settings', 'the certificate nginx has on %s is not the one saved '
                            '(%s): put in again' % (node_name(), drift), 'warn')
        # Failed with exactly this: asked again only when somebody says so.
        # Or once after a restart (1.0.120): it may have failed on what the
        # machine did not have yet - its new address, say.
        # And every 15 minutes (1.0.187): a failure on something passing - a
        # mirror that did not answer while keepalived was installed - left the
        # VIP address and the certificates as they were until somebody looked.
        if float(store.get_meta('web:retry:' + node_name()) or 0) <= float(st.get('at') or 0):
            if st.get('state') != 'failed':
                return
            rebooted = not WEB_DRIFT.get('boot_retried') and boot_time() > float(st.get('at') or 0)
            if not rebooted and time.time() - float(st.get('at') or 0) < WEB_RETRY_S:
                return
            if rebooted:
                WEB_DRIFT['boot_retried'] = True
            log_sparing('web-retry', 'the web part failed (%s): asked again' % '; '.join(
                st.get('said') or [])[:200], 'warn', every=3000)
    # Root at work on it (1.0.59): while it holds request.taken the status
    # still has the old hash, and the same request was written again - every
    # change applied twice.
    taken = WEB_DIR / 'request.taken'
    if (taken.exists() and time.time() - taken.stat().st_mtime < 600) or (
            WEB_ASKED.get('hash') == h and time.time() - float(WEB_ASKED.get('at') or 0) < 600
            and float(st.get('at') or 0) < float(WEB_ASKED.get('at') or 0)):
        return
    req = WEB_DIR / 'request.json'
    if req.exists() and time.time() - req.stat().st_mtime < 600:
        # Waiting for root: left as it is when it asks for this very thing,
        # replaced when what is wanted changed meanwhile.
        try:
            if json.loads(req.read_text()).get('hash') == h:
                return
        except (OSError, ValueError):
            return
    body = dict(desired, id=secrets.token_hex(8), hash=h)
    tmp = WEB_DIR / 'request.part'
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(body, f)
    os.replace(str(tmp), str(req))
    WEB_ASKED['hash'] = h
    WEB_ASKED['at'] = time.time()


WEB_ASKED = {'hash': '', 'at': 0.0}
WEB_DRIFT = {'at': 0.0}
NGINX_CERT_FILES = {'node': '/etc/nginx/certs/upsmon.pem', 'vip': '/etc/nginx/certs/upsmon-vip.pem'}


def _first_pem(text):
    m = PEM_CERT.search(text or '')
    return re.sub(r'\s+', '', m.group(0)) if m else ''


def web_drift(desired):
    """Why the certificates nginx has are not the ones wanted - '' when they
    are, or when that cannot be told (a file not readable here)."""
    for target in ('node', 'vip'):
        t = (desired.get('tls') or {}).get(target)
        if not t or not t.get('cert'):
            continue
        path = NGINX_CERT_FILES[target]
        try:
            with open(path) as f:
                have = _first_pem(f.read(200000))
        except FileNotFoundError:
            return '%s is not there' % path
        except OSError:
            continue
        if have and have != _first_pem(t['cert']):
            return '%s holds another certificate' % path
    return ''


def web_progress():
    """What root is doing now, if anything (1.0.50)."""
    try:
        fd = os.open(str(WEB_DIR / 'progress.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(65536).decode('utf-8'))
    except (OSError, ValueError):
        return None
    if not isinstance(got, dict) or time.time() - float(got.get('at') or 0) > 3 * 3600:
        return None
    got['now'] = time.time()
    return got


def web_state(store):
    """This node's web side, for its heartbeat: what root said last, whether
    that is what is wanted now, and the address."""
    st = web_status()
    desired_hash = ''
    try:
        desired_hash = web_hash(web_desired(store))
    except Exception:                                   # noqa: BLE001
        pass
    role = ''
    try:
        role = VIP_ROLE.read_text().split()[0]
    except (OSError, IndexError):
        pass
    v = vip_conf(store)
    return {'cert_now': cert_now('/etc/nginx/certs/upsmon.pem'),
            'vip_cert_now': cert_now('/etc/nginx/certs/upsmon-vip.pem'),
            'state': st.get('state') or '', 'said': (st.get('said') or [])[-6:],
            'at': st.get('at'), 'current': bool(st) and st.get('hash') == desired_hash,
            'waiting': (WEB_DIR / 'request.json').exists(),
            'progress': web_progress(),
            'iface': (st.get('applied') or {}).get('iface') or '',
            'vip_here': vip_here(v.get('address')) if v.get('on') else False,
            'role': role, 'health': dict(VIP_HEALTH),
            'fw': dict(st.get('fw') or {}, **fw_now_read()), 'access': st.get('access') or {},
            'ifaces': sorted(os.listdir('/sys/class/net')) if os.path.isdir('/sys/class/net')
            else []}


def fw_now_read():
    """The whole firewall as root last read it (1.0.67): {'full': {4, 6},
    'full_at'}."""
    try:
        fd = os.open(str(WEB_DIR / 'fwnow.json'), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            got = json.loads(f.read(4 << 20).decode('utf-8'))
        full = got.get('full') or {}
        return {'full': {str(k): [str(x)[:400] for x in (v or [])][:1500] for k, v in full.items()},
                'full_at': got.get('at'), 'full_backend': got.get('backend')}
    except (OSError, ValueError, AttributeError):
        return {}


def fw_now_ask(wait=6.0):
    """Root asked to read the firewall again, and waited for (1.0.67)."""
    if not WEB_DIR.is_dir():
        return False
    t0 = time.time()
    try:
        (WEB_DIR / 'fw.ask').write_text(json.dumps({'at': t0}))
    except OSError:
        return False
    while time.time() - t0 < wait:
        if float(fw_now_read().get('full_at') or 0) >= t0:
            return True
        time.sleep(0.3)
    return False


CERT_NOW = {}


def cert_now(path):
    """What the certificate nginx has in `path` says - read again only
    when the file changes."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    had = CERT_NOW.get(path)
    if had and had[0] == (st.st_mtime, st.st_size):
        return had[1]
    try:
        with open(path) as f:
            text = f.read(200000)
        m = PEM_CERT.search(text)
        info = cert_info(m.group(0)) if m else None
        if info:
            info['chain'] = max(0, len(PEM_CERT.findall(text)) - 1)
    except (OSError, ValueError):
        return None             # not kept: read again next time (1.0.57)
    CERT_NOW[path] = ((st.st_mtime, st.st_size), info)
    return info


def local_addresses():
    """Every address on this machine's interfaces, read from the kernel.

    Not by binding to it (1.0.55): with net.ipv4.ip_nonlocal_bind on - which
    the VIP address turns on since 1.0.51, so nginx can listen on it - a bind
    succeeds for an address the machine does not hold, and both nodes said
    they had the VIP address."""
    out = set()
    try:
        # IPv4: the local table of the FIB, "/32 host LOCAL" under each address.
        last = None
        with open('/proc/net/fib_trie') as f:
            for line in f:
                m = re.match(r'^\s*\|--\s+([0-9.]+)\s*\Z', line)
                if m:
                    last = m.group(1)
                elif last and '/32 host LOCAL' in line:
                    out.add(last)
    except OSError:
        pass
    try:
        with open('/proc/net/if_inet6') as f:
            for line in f:
                h = line.split()[0]
                if len(h) == 32:
                    out.add(str(ipaddress.IPv6Address(int(h, 16))))     # ::1 too (1.0.59)
    except (OSError, ValueError, IndexError):
        pass
    if not out and shutil.which('ip'):
        got = subprocess.run(['ip', '-o', 'addr', 'show'], capture_output=True, text=True)
        for m in re.finditer(r'\binet6?\s+([0-9a-fA-F:.]+)/', got.stdout or ''):
            out.add(str(ipaddress.ip_address(m.group(1))))
    return out


def vip_here(address):
    """Does this machine hold the address now? Its interfaces say so."""
    if VIP_HERE_BY_ROLE:
        # Tests (1.0.187): two nodes on one machine both see the address on lo;
        # keepalived's own word says which holds it.
        try:
            return VIP_ROLE.read_text().split()[0] == 'MASTER'
        except (OSError, IndexError):
            return False
    try:
        ip = ipaddress.ip_interface(str(address or '')).ip
    except ValueError:
        return False
    return str(ip) in local_addresses()




# ======== carried over from OTP 1.0.187 (lines 24762-25933): ACME ========
# ---- certificates by ACME: Let's Encrypt and the like (1.0.169) --------------------------
# Settings → Automatic certificates: the certificate of the VIP address (and,
# where asked, each node's own) ordered from an ACME CA - Let's Encrypt, its
# staging, or one of your own (step-ca, an internal CA) - by HTTP-01, and
# renewed when fewer than acme_days are left. The answer to the challenge is
# kept in the database, so whichever node the CA reaches on port 80 gives it
# (nginx sends /.well-known/acme-challenge/ to acme.php, which asks the
# daemon): in a cluster the VIP address may be on either node. The web
# address's certificate is ordered by the one node that does what one node
# does for both (alerts_lead); a node's own by that node. Signed with openssl;
# done in a thread of its own, never on the way of a sign-in.
ACME_CAS = {'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
            'letsencrypt-staging': 'https://acme-staging-v02.api.letsencrypt.org/directory'}
ACME_WORK = {'busy': False, 'at': 0.0, 'says': '', 'target': ''}
ACME_EVERY = float(os.environ.get('UPSMON_ACME_EVERY') or 3600)
ACME_RETRY = float(os.environ.get('UPSMON_ACME_RETRY') or 6 * 3600)


class AcmeError(Exception):
    pass


def _b64u(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def acme_directory_url():
    ca = CONFIG.get('acme_ca') or 'letsencrypt'
    if ca == 'custom':
        return str(CONFIG.get('acme_url') or '').strip()
    return ACME_CAS.get(ca, ACME_CAS['letsencrypt'])


def _acme_ctx():
    ctx = ssl.create_default_context()
    pem = str(CONFIG.get('acme_ca_pem') or '').strip()
    if pem and CONFIG.get('acme_ca') == 'custom':
        ctx.load_verify_locations(cadata=pem)
    return ctx


def _acme_account_gone(kind, said):
    """The CA's error says the account it was asked with is no more (RFC 8555
    accountDoesNotExist; Boulder's 'unauthorized' for one deactivated or not found)."""
    if kind.endswith(':accountDoesNotExist') or kind == 'accountDoesNotExist':
        return True
    low = str(said or '').lower()
    return kind.endswith('unauthorized') and 'account' in low and \
        any(w in low for w in ('deactivated', 'not valid', 'not found', 'does not exist', 'revoked'))


class Acme(object):
    """One conversation with the CA: the account, its key, the nonces."""
    def __init__(self, store):
        self.store = store
        self.dir_url = acme_directory_url()
        if not re.match(r'^https://[^\s]+\Z', self.dir_url):
            raise AcmeError('the ACME directory is an https:// address')
        self.work = tempfile.mkdtemp(prefix='upsmon-acme-', dir=str(STATE_DIR))
        os.chmod(self.work, 0o700)
        self.nonce = None
        self.kid = None
        self.dir = self._get(self.dir_url)[0]
        self._account()

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)

    # -- HTTP ------------------------------------------------------------------------
    def _req(self, url, data=None, method=None, accept='application/json'):
        if not str(url).startswith('https://'):
            raise AcmeError('the CA sent an address that is not https: %s' % url)
        req = urllib.request.Request(url, data=data, method=method or ('POST' if data else 'GET'),
                                     headers={'User-Agent': 'upsmon/%s (acme)' % __version__,
                                              'Accept': accept})
        if data is not None:
            req.add_header('Content-Type', 'application/jose+json')
        try:
            with url_open(req, timeout=30, context=_acme_ctx()) as r:
                body, headers, status = r.read(1 << 20), r.headers, r.status
        except urllib.error.HTTPError as e:
            body, headers, status = e.read(1 << 20), e.headers, e.code
        except (OSError, ssl.SSLError) as e:
            raise AcmeError('the CA did not answer (%s): %s' % (
                urllib.parse.urlsplit(url).hostname, getattr(e, 'reason', e)))
        if headers.get('Replay-Nonce'):
            self.nonce = headers['Replay-Nonce']
        return body, headers, status

    def _get(self, url):
        body, headers, status = self._req(url)
        if status >= 400:
            raise AcmeError('the CA said %d: %s' % (status, body[:200]))
        return json.loads(body.decode('utf-8')), headers

    # -- signing ---------------------------------------------------------------------
    def _key_file(self):
        p = os.path.join(self.work, 'account.pem')
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(self.key_pem)
        return p

    def _alg(self):
        """(JWS alg, digest, bytes of r and s) of the account key (4.1.6)."""
        kind = getattr(self, 'akind', 'ec')
        if kind == 'ec384':
            return 'ES384', '-sha384', 48
        if kind.startswith('rsa'):
            return 'RS256', '-sha256', 0
        return 'ES256', '-sha256', 32

    def _jwk(self):
        if getattr(self, '_jwk_done', None):
            return self._jwk_done
        alg, _, size = self._alg()
        if alg == 'RS256':
            txt = _openssl(['pkey', '-in', self._key_file(), '-noout', '-text_pub'],
                           what='the account key').decode()
            m = re.search(r'(?s)Modulus:\s*\n(.*?)\n\S', txt)
            e = re.search(r'Exponent:\s*(\d+)', txt)
            if not m or not e:
                raise AcmeError('the RSA account key does not read')
            n = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', m.group(1))).lstrip(b'\x00')
            ev = int(e.group(1))
            jwk = {'e': _b64u(ev.to_bytes((ev.bit_length() + 7) // 8, 'big')), 'kty': 'RSA',
                   'n': _b64u(n)}
        else:
            der = _openssl(['pkey', '-in', self._key_file(), '-pubout', '-outform', 'DER'],
                           what='the account key')
            point = der[-2 * size:]
            jwk = {'crv': 'P-384' if size == 48 else 'P-256', 'kty': 'EC',
                   'x': _b64u(point[:size]), 'y': _b64u(point[size:])}
        self._jwk_done = jwk
        return jwk

    def thumbprint(self):
        # RFC 7638: the required members only, sorted - the JWK holds just those.
        return _b64u(hashlib.sha256(json.dumps(
            self._jwk(), separators=(',', ':'), sort_keys=True).encode()).digest())

    def _sign(self, data):
        alg, digest, size = self._alg()
        der = _openssl(['dgst', digest, '-sign', self._key_file()], data=data,
                       what='signing for the CA')
        if alg == 'RS256':
            return der                       # PKCS#1 v1.5, as JWS wants it
        # DER SEQUENCE { INTEGER r, INTEGER s } -> r || s, `size` bytes each.
        i = 2 if der[1] < 0x80 else 3

        def integer(at):
            n = der[at + 1]
            v = der[at + 2:at + 2 + n].lstrip(b'\x00')
            return v.rjust(size, b'\x00'), at + 2 + n
        r, i = integer(i)
        s, _ = integer(i)
        return r + s

    def post(self, url, payload, use_jwk=False):
        anew = False
        for attempt in (1, 2, 3):
            if not self.nonce:
                self._req(self.dir['newNonce'], method='HEAD')
            protected = {'alg': self._alg()[0], 'nonce': self.nonce, 'url': url}
            if use_jwk or not self.kid:
                protected['jwk'] = self._jwk()
            else:
                protected['kid'] = self.kid
            p64 = _b64u(json.dumps(protected))
            b64 = '' if payload is None else _b64u(json.dumps(payload))
            sig = _b64u(self._sign(('%s.%s' % (p64, b64)).encode('ascii')))
            self.nonce = None
            body, headers, status = self._req(url, json.dumps(
                {'protected': p64, 'payload': b64, 'signature': sig}).encode('utf-8'),
                accept='application/json' if 'cert' not in url else
                'application/pem-certificate-chain')
            if status == 400 and b'badNonce' in body and attempt == 1:
                continue
            if status >= 400:
                try:
                    err = json.loads(body.decode('utf-8'))
                    said = err.get('detail') or err.get('type')
                    kind = str(err.get('type') or '')
                except (ValueError, AttributeError):
                    said, kind = body[:200].decode('utf-8', 'replace'), ''
                # The account kept here gone from the CA (1.0.187): deleted,
                # deactivated, a CA of the same address started anew. Each
                # renewal was refused for it until the certificates ran out;
                # now a new account is made, and the request asked again.
                if self.kid and not use_jwk and not anew and url != self.dir.get('newAccount') and \
                        _acme_account_gone(kind, said):
                    anew = True
                    log('ACME: the CA does not know the account any more (%s) - a new one is made'
                        % said, 'warn')
                    self._account(fresh=True)
                    continue
                raise AcmeError('the CA refused it: %s' % said)
            return body, headers

    def post_json(self, url, payload):
        body, headers = self.post(url, payload)
        return (json.loads(body.decode('utf-8')) if body else {}), headers

    # -- the account -----------------------------------------------------------------
    def _account(self, fresh=False):
        row = {} if fresh else (_meta_json(self.store, 'acme:account') or {})
        pem = unseal_secret(row.get('key') or '', 'acme') if row.get('key') else ''
        # The kind of key asked for (4.1.6): another one than the account has
        # makes a new account with a key of that kind.
        self.akind = str(CONFIG.get('acme_account_key') or 'ec')
        if self.akind not in KEY_WORDS:
            self.akind = 'ec'
        if row.get('directory') != self.dir_url or not pem or \
                (row.get('kind') or 'ec') != self.akind:
            pem = ''
        if fresh:
            self.kid = None
            try:
                os.unlink(os.path.join(self.work, 'account.pem'))
            except OSError:
                pass
        if not pem:
            pem = new_key(self.akind)
            row = {}
            self.kid = None
            self._jwk_done = None
            try:
                os.unlink(os.path.join(self.work, 'account.pem'))
            except OSError:
                pass
        self.key_pem = pem
        if row.get('kid'):
            self.kid = row['kid']
            return
        mail = str(CONFIG.get('acme_email') or '').strip()
        payload = {'termsOfServiceAgreed': True}
        if mail:
            payload['contact'] = ['mailto:' + mail]
        body, headers = self.post(self.dir['newAccount'], payload, use_jwk=True)
        self.kid = headers.get('Location')
        if not self.kid:
            raise AcmeError('the CA made no account')
        self.store.set_meta('acme:account', json.dumps({
            'key': seal_secret(pem, 'acme'), 'kid': self.kid, 'directory': self.dir_url,
            'email': mail, 'at': time.time(), 'kind': self.akind}))

    # -- an order --------------------------------------------------------------------
    def _poll(self, url, done, what, secs=90):
        end = time.time() + secs
        while True:
            got, _ = self.post_json(url, None)
            st = got.get('status')
            if st in done:
                return got
            if st == 'invalid':
                errs = [c.get('error', {}).get('detail') for c in got.get('challenges') or []
                        if c.get('error')] or [got.get('error', {}).get('detail')]
                raise AcmeError('%s: %s' % (what, '; '.join(e for e in errs if e) or 'invalid'))
            if time.time() > end:
                raise AcmeError('%s: the CA has not said in %d s (%s)' % (what, secs, st))
            time.sleep(2)

    def order(self, names, say, key_kind=None):
        say('ordered from the CA')
        got, headers = self.post_json(self.dir['newOrder'], {
            'identifiers': [{'type': 'dns', 'value': n} for n in names]})
        order_url = headers.get('Location')
        thumb = self.thumbprint()
        for az in got.get('authorizations') or []:
            a, _ = self.post_json(az, None)
            if a.get('status') == 'valid':
                continue
            name = a.get('identifier', {}).get('value')
            kind = 'dns-01' if (CONFIG.get('acme_challenge') or 'http-01') == 'dns-01' else 'http-01'
            ch = [c for c in a.get('challenges') or [] if c.get('type') == kind]
            if not ch:
                raise AcmeError('the CA offers no %s challenge for %s' % (kind.upper(), name))
            token = ch[0]['token']
            if not re.match(r'^[A-Za-z0-9_-]{8,256}\Z', token):
                raise AcmeError('the CA sent a token that is not one')
            auth = token + '.' + thumb
            if kind == 'dns-01':
                # A TXT record in DNS (1.0.169): for a server the CA cannot
                # reach - nothing has to be open to the internet.
                txt = _b64u(hashlib.sha256(auth.encode()).digest())
                undo = acme_dns_put(self.store, name, txt, say)
                try:
                    say('the CA looks up _acme-challenge.%s' % name)
                    self.post_json(ch[0]['url'], {})
                    self._poll(az, ('valid',), 'the CA did not take %s' % name, 180)
                finally:
                    try:
                        undo()
                    except Exception as e:              # noqa: BLE001
                        log('ACME: the TXT record of %s was not taken away: %s' % (name, e), 'warn')
                continue
            # Kept where every node finds it; the other node's copy of the
            # database has it within seconds.
            self.store.set_meta('acme:chal:' + token, json.dumps(
                {'auth': auth, 'at': time.time(), 'name': name}))
            time.sleep(float(os.environ.get('UPSMON_ACME_SETTLE') or 3))
            say('the CA looks at http://%s/.well-known/acme-challenge/' % name)
            try:
                self.post_json(ch[0]['url'], {})
                self._poll(az, ('valid',), 'the CA did not take %s' % name)
            finally:
                self.store.db.run('DELETE FROM meta WHERE k = ?', ('acme:chal:' + token,))
        key, csr = make_csr(names[0], names[1:], key_kind or 'ec')
        der = _openssl(['req', '-in', '/dev/stdin', '-outform', 'DER'], data=csr.encode(),
                       what='the request')
        say('the certificate is made')
        o, _ = self.post_json(got['finalize'], {'csr': _b64u(der)})
        if o.get('status') != 'valid':
            o = self._poll(order_url, ('valid',), 'the order', 120)
        body, _ = self.post(o['certificate'], None)
        return key, body.decode('utf-8')


# ---- what is ordered, and when ----------------------------------------------------------
def acme_name_of(store, target):
    """The DNS name a target's certificate is for."""
    if target == 'vip':
        return str(vip_conf(store).get('fqdn') or '').strip()
    k = 'acme_node_name@' + target
    saved = store.settings_saved()
    name = str(saved.get(k) or (CONFIG.get('acme_node_name') if target == node_name() else '')
               or '').strip()
    if not name and target == node_name():
        name = socket.getfqdn()
    if not name:
        # The name of the certificate it has now (1.0.170) - what Certificates
        # and TLS shows: otp2's card said "for -" beside otp2.example.cz.
        info = (tls_profile(store, target) or {}).get('info') or {}
        for n in [info.get('cn')] + list(info.get('san') or []):
            n = str(n or '').strip().lower()
            if re.match(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z', n):
                name = n
                break
    if not name and target == node_name():
        name = socket.getfqdn()
    elif not name and target != 'vip':
        # Another node's own name, as that node publishes it (1.0.170): its
        # card said "for -" and Try port 80 asked http://?/.
        name = str((_meta_json(store, 'acme:host:' + target) or {}).get('fqdn') or '').strip()
    return name


def acme_before(store, target):
    """The certificate a target had before ACME replaced it, as the page may
    see it (no key)."""
    got = _meta_json(store, 'acme:before:' + target) or {}
    if not got.get('cert'):
        return None
    info = got.get('info') or {}
    return {'how': got.get('how'), 'subject': info.get('subject'), 'issuer': info.get('issuer'),
            'not_after': info.get('not_after'), 'at': got.get('at'),
            'ran_out': float(info.get('not_after') or 0) < time.time()}


def acme_put_back(store, target, by):
    """The certificate from before ACME back in place, ACME no longer renewing
    it; its TLS settings (protocols, ciphers, DH, HSTS) stay as they are now."""
    got = _meta_json(store, 'acme:before:' + target) or {}
    if not got.get('cert'):
        raise ValueError('there is no certificate from before ACME for this one')
    info = got.get('info') or {}
    if float(info.get('not_after') or 0) < time.time():
        raise ValueError('the certificate from before ACME ran out on %s - put a new one in on '
                         'Certificates and TLS' % stamp(info.get('not_after')))
    prof = tls_profile(store, target) or {}
    prof.update({k: got.get(k) for k in ('cert', 'chain', 'root', 'key', 'info', 'chain_info',
                                         'root_info', 'verify', 'how')})
    prof.pop('pending_key', None)
    prof.pop('csr', None)
    tls_save(store, target, prof, by)
    store.set_meta('acme:care:' + target, json.dumps({'on': False, 'at': time.time(), 'by': by}))
    store.db.run('DELETE FROM meta WHERE k = ?', ('acme:before:' + target,))
    store.add_event('settings', '%s put the certificate of %s from before ACME back (%s, until %s); '
                    'ACME no longer renews it' % (by, 'the VIP address' if target == 'vip' else
                                                  target, info.get('issuer') or '?',
                                                  stamp(info.get('not_after'))), 'warn', who=by)


def acme_care(store, target):
    """Whether ACME looks after this certificate (1.0.170). Said on either page;
    unsaid: yes for one from the CA, a self-signed one and none at all - never
    for one uploaded or answered to a request (a CA of your own): switching ACME
    on does not replace those."""
    got = _meta_json(store, 'acme:care:' + target)
    if got and 'on' in got:
        return bool(got['on'])
    prof = tls_profile(store, target) or {}
    how = str(prof.get('how') or '')
    return not prof.get('cert') or how == 'ACME' or how.startswith('self-signed')


def acme_care_set(store, target, on, by, why=''):
    was = acme_care(store, target)
    store.set_meta('acme:care:' + target, json.dumps({'on': bool(on), 'at': time.time(),
                                                     'by': by}))
    if was != bool(on) and CONFIG.get('acme'):
        store.add_event('settings', '%s: ACME %s the certificate of %s%s' % (
            by, 'looks after' if on else 'no longer renews', 'the VIP address' if target == 'vip'
            else target, (' - ' + why) if why else ''), 'info' if on else 'warn', who=by)


ACME_HOST = {'at': 0.0, 'fqdn': None}


def acme_host_publish(store):
    """This node's full name, for the cards of the other nodes - once in ten
    minutes, written only when it changed."""
    if time.time() - ACME_HOST['at'] < 600:
        return
    ACME_HOST['at'] = time.time()
    fqdn = socket.getfqdn()
    if fqdn == ACME_HOST['fqdn']:
        return
    store.set_meta('acme:host:' + node_name(), json.dumps({'fqdn': fqdn, 'at': time.time()}))
    ACME_HOST['fqdn'] = fqdn


def acme_targets(store):
    """[(target, name)] this node orders: the VIP address's on the lead, and
    its own where asked."""
    if not CONFIG.get('acme'):
        return []
    want = CONFIG.get('acme_for') or 'vip'
    out = []
    if want in ('vip', 'both') and vip_conf(store).get('on') and alerts_lead(store):
        out.append(('vip', acme_name_of(store, 'vip')))
    if want in ('node', 'both') or (want == 'vip' and not vip_conf(store).get('on')):
        out.append((node_name(), acme_name_of(store, node_name())))
    return [(t, n) for t, n in out if n and acme_care(store, t)]


def acme_wanted(store):
    """The certificates asked for at all (For), whichever node renews them."""
    want = CONFIG.get('acme_for') or 'vip'
    out = []
    for t in tls_targets(store):
        if t == 'vip':
            if want in ('vip', 'both') and vip_conf(store).get('on'):
                out.append(t)
        elif want in ('node', 'both') or (want == 'vip' and not vip_conf(store).get('on')):
            out.append(t)
    return out


def acme_state(store, target):
    return _meta_json(store, 'acme:state:' + target) or {}


def acme_due(store, target, name):
    """Why this certificate is to be ordered now, or ''."""
    st = acme_state(store, target)
    if st.get('failed_at') and time.time() - float(st['failed_at']) < ACME_RETRY and \
            st.get('name') == name:
        return ''
    prof = tls_profile(store, target) or {}
    info = prof.get('info') or {}
    if prof.get('how') != 'ACME' or st.get('name') != name:
        return 'not ordered yet for %s' % name
    left = (float(info.get('not_after') or 0) - time.time()) / 86400
    days = float(CONFIG.get('acme_days') or 30)
    # A third of its life at most (1.0.187): a CA giving fewer days than
    # acme_days (short-lived certificates, a test CA) had every new one due
    # at once - ordered again every hour, until its limits refused them all.
    life = (float(info.get('not_after') or 0) - float(info.get('not_before') or 0)) / 86400
    if info.get('not_before') and life > 0:
        days = min(days, life / 3)
    if left < days:
        return '%d days left' % int(left)
    return ''


def acme_order(store, target, name, by, say=None):
    """One certificate ordered and put in; the state kept, an event written -
    and what was done on the way (1.0.175), for the card."""
    tell = say or (lambda t: None)
    steps = []

    def say(t):
        steps.append([round(time.time(), 1), str(t)[:300]])
        tell(t)
    if not re.match(r'^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                    r'[A-Za-z]{2,63}\Z', name):
        raise AcmeError('%s is not a name a CA gives a certificate for (a full DNS name)' % name)
    st = {'name': name, 'at': time.time(), 'by': by, 'ca': acme_directory_url(), 'steps': steps}
    a = None
    try:
        a = Acme(store)
        choice = str(CONFIG.get('acme_key') or 'dual')
        kinds = ACME_CERT_KEYS.get(choice) or ('ec',)
        say('the key%s: %s' % ('s' if len(kinds) > 1 else '', ' + '.join(KEY_WORDS[k] for k in kinds)))
        key, chain = a.order([name], say, kinds[0])
        got = cert_bundle(chain, key)
        info = got['info']
        alt = None
        if len(kinds) > 1:
            # The second certificate (4.1.6): the name is already proven, so
            # the CA only signs - nginx offers it to the clients that take it.
            say('a second certificate, with a %s key' % KEY_WORDS[kinds[1]])
            k2, c2 = a.order([name], say, kinds[1])
            g2 = cert_bundle(c2, k2)
            alt = {'cert': g2['cert'], 'chain': g2['chain'], 'key': seal_secret(g2['key'], 'web:tls'),
                   'info': g2['info'], 'for': tls_alt_for(got['cert'])}
        prof = tls_profile(store, target) or {}
        if prof.get('cert') and prof.get('how') != 'ACME':
            # The certificate it had - uploaded, from your own CA - kept to go
            # back to (1.0.172): ACME switched off or left alone, it is put
            # back with a click, its key as sealed as it was.
            store.set_meta('acme:before:' + target, json.dumps(
                {k: prof.get(k) for k in ('cert', 'chain', 'root', 'key', 'info', 'chain_info',
                                          'root_info', 'verify', 'how')}
                | {'at': time.time()}))
        prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                    key=seal_secret(got['key'], 'web:tls'), info=info,
                    chain_info=got['chain_info'], root_info=got['root_info'],
                    verify=got['verify'], how='ACME')
        if alt:
            prof['alt'] = alt
        else:
            prof.pop('alt', None)
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        prof.setdefault('preset', 'standard')
        prof.setdefault('dh', 'none')
        tls_save(store, target, prof, by)
        st.update(ok=True, not_after=info.get('not_after'), issuer=info.get('issuer'),
                  ordered_at=time.time(), keys=' + '.join(KEY_WORDS[k] for k in kinds))
        st['steps'] = steps[-25:]
        store.set_meta('acme:state:' + target, json.dumps(st))
        store.add_event('settings', 'a certificate for %s (%s) came from the CA, good until %s'
                        % (name, 'the VIP address' if target == 'vip' else target,
                           stamp(info.get('not_after')) if info.get('not_after') else '?'),
                        'info', who=by)
        return st
    except (AcmeError, ValueError, OSError) as e:
        if 'NXDOMAIN' in str(e) and (CONFIG.get('acme_challenge') or '') == 'dns-01':
            e = AcmeError('%s - the CA does not find the record: In your DNS → Check DNS, with '
                          'DNS servers for ACME set to public ones (1.1.1.1), shows where the way '
                          'to it stops (the CNAME, or the delegation of its zone)' % e)
        st.update(ok=False, failed_at=time.time(), said=str(e)[:600])
        old = acme_state(store, target)
        for k in ('not_after', 'issuer', 'ordered_at'):
            if old.get(k):
                st[k] = old[k]
        st['steps'] = steps[-25:]
        store.set_meta('acme:state:' + target, json.dumps(st))
        store.add_event('settings', 'no certificate for %s came from the CA: %s' % (name, e),
                        'bad', who=by)
        raise AcmeError(str(e))
    finally:
        if a:
            a.close()


def acme_tick(daemon):
    """Once an hour: what is due, ordered - in a thread of its own."""
    # In a thread (1.0.186): socket.getfqdn() waits on a DNS that does not
    # answer, and this is the main loop's.
    if time.time() - ACME_HOST['at'] >= 600:
        def pub():
            try:
                acme_host_publish(daemon.store)
            except Exception:                           # noqa: BLE001
                pass
        threading.Thread(target=pub, name='upsmon-acme-host', daemon=True).start()
    if not CONFIG.get('acme') or ACME_WORK['busy'] or \
            time.time() - ACME_WORK['at'] < ACME_EVERY:
        return
    ACME_WORK['at'] = time.time()
    store = daemon.store
    due = [(t, n) for t, n in acme_targets(store) if acme_due(store, t, n)]
    if not due:
        return
    acme_start(store, due, 'upsmon (renewal)')


def acme_start(store, which, by):
    if ACME_WORK['busy']:
        raise ValueError('a certificate is being ordered already')
    ACME_WORK.update(busy=True, says='starting')

    def go():
        _ACME_DNS.on = True
        try:
            for t, n in which:
                ACME_WORK['target'] = t
                try:
                    acme_order(store, t, n, by, lambda s: ACME_WORK.update(says=s))
                except AcmeError as e:
                    log('ACME: %s' % e, 'warn')
        finally:
            ACME_WORK.update(busy=False, says='', target='')
    threading.Thread(target=go, name='upsmon-acme', daemon=True).start()


def acme_challenge(store, token):
    """The answer for the CA, or None: what acme.php gives on port 80."""
    if not re.match(r'^[A-Za-z0-9_-]{8,256}\Z', str(token or '')):
        return None
    got = _meta_json(store, 'acme:chal:' + token) or {}
    if not got.get('auth') or time.time() - float(got.get('at') or 0) > 3600:
        return None
    return got['auth']


def acme_view(store):
    out = []
    for t in tls_targets(store):
        if t == 'vip' and not vip_conf(store).get('on'):
            continue
        prof = tls_profile(store, t) or {}
        info = prof.get('info') or {}
        out.append({'target': t, 'name': acme_name_of(store, t), 'state': acme_state(store, t),
                    'how': prof.get('how') or '', 'subject': info.get('subject'),
                    'issuer': info.get('issuer'), 'not_after': info.get('not_after'),
                    'keys': ' + '.join(x for x in [info.get('key') or '',
                                                   ((tls_alt(prof) or {}).get('info') or {}).get('key') or '']
                                       if x),
                    'care': acme_care(store, t), 'wanted': t in acme_wanted(store),
                    'before': acme_before(store, t),
                    'named': bool(str(store.settings_saved().get('acme_node_name@' + t) or '')
                                  .strip()) if t != 'vip' else bool(vip_conf(store).get('fqdn'))})
    mine = [t for t, _ in acme_targets(store)]
    acc = _meta_json(store, 'acme:account') or {}
    return {'on': bool(CONFIG.get('acme')), 'targets': out, 'mine': mine,
            'directory': acme_directory_url(), 'account': {
                'kid': acc.get('kid'), 'email': acc.get('email'), 'at': acc.get('at'),
                'key': KEY_WORDS.get(acc.get('kind') or 'ec', '') if acc.get('kid') else ''},
            'work': dict(ACME_WORK), 'node': node_name(),
            'challenge': CONFIG.get('acme_challenge') or 'http-01',
            'dns_guide': acme_dns_guide(store),
            'manual': {k: v for k, v in (_meta_json(store, 'acme:manual') or {}).items()
                       if k in ('rr', 'txt', 'at', 'done')} or None}


def acme_probe(store, target):
    """Whether http://NAME/.well-known/acme-challenge/ reaches an upsmon node that
    answers - asked from here, straight, as the CA will (from outside it may
    still be blocked: a firewall in front sees only what reaches it)."""
    name = acme_name_of(store, target) if target else ''
    if not name:
        raise ValueError('which certificate? its name is not known')
    token = 'upsmon-probe-' + secrets.token_urlsafe(16)
    want = token + '.' + secrets.token_urlsafe(8)
    store.set_meta('acme:chal:' + token, json.dumps({'auth': want, 'at': time.time(),
                                                    'name': name, 'probe': True}))
    url = 'http://%s/.well-known/acme-challenge/%s' % (name, token)
    began = time.time()
    out = {'name': name, 'url': url, 'ok': False}
    scope = acme_dns_scope()
    scope.__enter__()
    try:
        time.sleep(float(os.environ.get('UPSMON_ACME_SETTLE') or 3))
        req = urllib.request.Request(url, headers={'User-Agent': 'upsmon/%s (acme probe)' % __version__})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=10) as r:
            body = r.read(4096).decode('utf-8', 'replace').strip()
        out.update(ok=body == want, status=r.status,
                   said='answered as the CA wants it' if body == want else
                   'something answers on port 80, but not upsmon\'s answer: %r' % body[:80])
    except urllib.error.HTTPError as e:
        out['said'] = 'port 80 answers %d - nginx does not send /.well-known/acme-challenge/ to upsmon' % e.code
    except (OSError, ValueError) as e:
        out['said'] = 'port 80 of %s cannot be reached: %s' % (name, getattr(e, 'reason', e))
    finally:
        scope.__exit__()
        store.db.run('DELETE FROM meta WHERE k = ?', ('acme:chal:' + token,))
    out['ms'] = int((time.time() - began) * 1000)
    return out


def acme_http_names(store):
    """The names this node's port 80 answers the CA for."""
    want = CONFIG.get('acme_for') or 'vip'
    vip_on = bool(vip_conf(store).get('on'))
    out = []
    if want in ('vip', 'both') and vip_on:
        out.append(acme_name_of(store, 'vip'))
    if want in ('node', 'both') or (want == 'vip' and not vip_on):
        out.append(acme_name_of(store, node_name()))
    return [n for n in out if n and re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z', n)]


# ---- DNS-01: the TXT record put in DNS (1.0.169) -------------------------------------
# For a server the CA cannot reach: _acme-challenge.NAME TXT, put in by
#   rfc2136    - nsupdate with a TSIG key (BIND, PowerDNS, Knot...), the key in a
#                file only upsmon reads for the moment it runs, never on a command line;
#   cloudflare - its API, with a token that may edit the zone's DNS;
#   acmedns    - an acme-dns server (_acme-challenge.NAME a CNAME to its subdomain);
#   manual     - shown on the page; the order waits until it is said to be there.
# Then waited for (acme_dns_wait s) and taken away again once the CA has looked.
NSUPDATE = os.environ.get('UPSMON_NSUPDATE') or 'nsupdate'


def _dns_wait(say, least=0):
    w = max(int(CONFIG.get('acme_dns_wait') or 0),
            int(os.environ.get('UPSMON_ACME_DNS_LEAST', least)))
    if w:
        say('waiting %d s for DNS to carry it' % w)
        time.sleep(w)


def acme_dns_where(name):
    """(where the TXT record goes, the CNAME your DNS needs or None) - 1.0.170.
    The record goes to _acme-challenge.NAME itself, or - with a zone of its own
    for them (deSEC, acme_dns_alias) - to _acme-challenge.LABEL.ZONE, and
    _acme-challenge.NAME is a CNAME to it in your DNS, put in once: the CA
    follows it. So a domain whose DNS has no API gets certificates by itself."""
    name = str(name or '').rstrip('.').lower()
    own = '_acme-challenge.' + name
    how = CONFIG.get('acme_dns') or 'manual'
    if how == 'acmedns':
        url = str(CONFIG.get('acme_dns_url') or '').strip()
        host = urllib.parse.urlparse(url).hostname or ''
        sub = str(CONFIG.get('acme_dns_subdomain') or '').strip()
        return own, ('%s.%s' % (sub, host) if sub and host else '')
    zone = str(CONFIG.get('acme_dns_alias') or '').strip().rstrip('.').lower()
    if how == 'desec':
        dom = str(CONFIG.get('acme_desec_domain') or '').strip().rstrip('.').lower()
        if dom and (name == dom or name.endswith('.' + dom)):
            return own, None                            # its DNS is at deSEC itself
        if not zone or not (zone == dom or zone.endswith('.' + dom)):
            zone = dom
    if not zone or name == zone or name.endswith('.' + zone):
        return own, None
    there = '_acme-challenge.%s.%s' % (name.split('.')[0], zone)
    return there, there


def acme_dns_put(store, name, txt, say):
    """The TXT record put in; returns what takes it away again."""
    how = CONFIG.get('acme_dns') or 'manual'
    rr, cname = acme_dns_where(name)
    if cname and how != 'acmedns':
        say('the TXT record %s put in DNS (%s; _acme-challenge.%s is a CNAME to it)'
            % (rr, how, name))
    else:
        say('the TXT record %s put in DNS (%s)' % (rr, how))
    if how == 'rfc2136':
        undo = _dns_rfc2136(rr, txt)
    elif how == 'cloudflare':
        undo = _dns_cloudflare(rr, txt)
    elif how == 'acmedns':
        undo = _dns_acmedns(txt)
    elif how == 'desec':
        undo = _dns_desec(rr, txt)
    else:
        undo = _dns_manual(store, rr, txt, say)
    if how == 'desec':
        _desec_seen(rr, txt, say)
    else:
        _dns_wait(say)
        if how != 'manual':
            acme_txt_seen(name, txt, say)
    return undo


DESEC_NS = ('ns1.desec.io', 'ns2.desec.org')


def _desec_seen(rr, txt, say):
    """deSEC's own name servers asked until both have the record (1.0.175),
    then a while more: they are anycast, and the CA asks from several places
    of the world - "During secondary validation: NXDOMAIN" was a place deSEC
    had not reached yet. Asked straight, never through a resolver, so no
    resolver keeps "not there" for the CA."""
    _dns_wait(say)
    addrs = []
    for ns in DESEC_NS:
        try:
            addrs += [(ns, a) for t, a in dns_ask(ns, 1) if t == 'A'][:1]
        except OSError:
            pass
    if not addrs:
        say('deSEC\'s name servers not found - waited %d s instead' % 120)
        _dns_wait(say, 120)
        return
    began = time.time()
    end = began + float(os.environ.get('UPSMON_DESEC_PROPAGATION') or 300)
    while True:
        seen = []
        for ns, a in addrs:
            try:
                rc, got = _dns_parse(_dns_ask(a, rr, 16, 3.0))
                if txt in [v for t, v in got if t == 'TXT']:
                    seen.append(ns)
            except OSError:
                pass
        if len(seen) == len(addrs):
            break
        if time.time() > end:
            say('%s TXT not on every deSEC name server yet (%s) - the CA is asked anyway'
                % (rr, ', '.join(seen) or 'none'))
            return
        # What is waited for, said as it goes (1.0.176): the line said "waited
        # 5 s" for minutes while deSEC was being asked.
        ACME_WORK['says'] = 'waiting for deSEC\'s name servers to have the record - %s so far, %d s' % (
            ', '.join(seen) or 'none', int(time.time() - began))
        time.sleep(5)
    settle = float(os.environ.get('UPSMON_DESEC_SETTLE') or 60)
    say('%s TXT is on %s after %d s; %d s more for deSEC\'s other places' % (
        rr, ', '.join(seen), int(time.time() - began), settle))
    left = settle
    while left > 0:
        ACME_WORK['says'] = '%d s more for deSEC\'s other places of the world, then the CA is asked' % left
        time.sleep(min(5, left))
        left -= 5


def _dns_rfc2136(rr, txt):
    server = str(CONFIG.get('acme_dns_server') or '').strip()
    if not server:
        raise AcmeError('the DNS server for the updates is not set')
    keyname = str(CONFIG.get('acme_dns_tsig_name') or '').strip()
    secret = unseal_secret(CONFIG.get('acme_dns_tsig_secret') or '') or ''
    alg = CONFIG.get('acme_dns_tsig_alg') or 'hmac-sha256'
    host, _, port = server.partition(':')
    zone = str(CONFIG.get('acme_dns_zone') or '').strip()

    def run(op):
        work = tempfile.mkdtemp(prefix='upsmon-dns-', dir=str(STATE_DIR))
        os.chmod(work, 0o700)
        try:
            args = [NSUPDATE]
            if keyname:
                kf = os.path.join(work, 'tsig.key')
                fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write('key "%s" {\n  algorithm %s;\n  secret "%s";\n};\n' % (keyname, alg, secret))
                args += ['-k', kf]
            script = 'server %s %s\n' % (host, port or '53')
            if zone:
                script += 'zone %s\n' % zone
            script += 'update %s %s 60 TXT "%s"\nsend\n' % (op, rr, txt) if op == 'add' else \
                'update delete %s TXT "%s"\nsend\n' % (rr, txt)
            try:
                got = subprocess.run(args, input=script, capture_output=True, text=True, timeout=60)
            except FileNotFoundError:
                raise AcmeError('nsupdate is not on this machine (dnf install bind-utils)')
            if got.returncode != 0:
                raise AcmeError('the DNS server did not take the update: %s'
                                % (got.stderr or got.stdout).strip()[-300:])
        finally:
            shutil.rmtree(work, ignore_errors=True)
    run('add')
    return lambda: run('delete')


def _cf(method, path, body=None):
    tok = unseal_secret(CONFIG.get('acme_dns_token') or '') or ''
    if not tok:
        raise AcmeError('the Cloudflare API token is not set')
    base = str(os.environ.get('UPSMON_CF_API') or 'https://api.cloudflare.com/client/v4').rstrip('/')
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': 'Bearer ' + tok,
                                          'Content-Type': 'application/json',
                                          'User-Agent': 'upsmon/%s (acme)' % __version__})
    try:
        with url_open(req, timeout=30, context=ssl.create_default_context()
                      if base.startswith('https') else None) as r:
            got = json.loads(r.read(1 << 20).decode())
    except urllib.error.HTTPError as e:
        try:
            got = json.loads(e.read().decode())
        except ValueError:
            got = {}
        raise AcmeError('Cloudflare said %d: %s' % (e.code, '; '.join(
            x.get('message', '') for x in got.get('errors') or []) or e.reason))
    if not got.get('success'):
        raise AcmeError('Cloudflare said no: %s' % '; '.join(
            x.get('message', '') for x in got.get('errors') or []))
    return got.get('result')


def _dns_cloudflare(rr, txt):
    labels = rr.split('.')
    zone_id = None
    for i in range(1, len(labels) - 1):
        z = '.'.join(labels[i:])
        got = _cf('GET', '/zones?name=' + urllib.parse.quote(z))
        if got:
            zone_id = got[0]['id']
            break
    if not zone_id:
        raise AcmeError('Cloudflare has no zone for %s that the token may see' % rr)
    rec = _cf('POST', '/zones/%s/dns_records' % zone_id,
              {'type': 'TXT', 'name': rr, 'content': txt, 'ttl': 60})
    return lambda: _cf('DELETE', '/zones/%s/dns_records/%s' % (zone_id, rec['id']))


def _dns_acmedns(txt):
    url = str(CONFIG.get('acme_dns_url') or '').strip().rstrip('/')
    if not url:
        raise AcmeError('the acme-dns server is not set')
    req = urllib.request.Request(url + '/update', method='POST', data=json.dumps(
        {'subdomain': str(CONFIG.get('acme_dns_subdomain') or ''), 'txt': txt}).encode(),
        headers={'X-Api-User': str(CONFIG.get('acme_dns_user') or ''),
                 'X-Api-Key': unseal_secret(CONFIG.get('acme_dns_key') or '') or '',
                 'Content-Type': 'application/json'})
    try:
        with url_open(req, timeout=30, context=ssl.create_default_context()
                      if url.startswith('https') else None) as r:
            r.read(4096)
    except urllib.error.HTTPError as e:
        raise AcmeError('acme-dns said %d: %s' % (e.code, e.read(300).decode('utf-8', 'replace')))
    except OSError as e:
        raise AcmeError('acme-dns did not answer: %s' % getattr(e, 'reason', e))
    return lambda: None             # acme-dns keeps the last two; nothing to take away


def _desec(method, path, body=None):
    """deSEC's API (1.0.170): Authorization: Token; a 429 waited out (it says
    how long) up to twice."""
    tok = unseal_secret(CONFIG.get('acme_desec_token') or '') or ''
    if not tok:
        raise AcmeError('the deSEC API token is not set')
    base = str(os.environ.get('UPSMON_DESEC_API') or 'https://desec.io/api/v1').rstrip('/')
    for attempt in range(3):
        req = urllib.request.Request(base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Authorization': 'Token ' + tok,
                                              'Content-Type': 'application/json',
                                              'User-Agent': 'upsmon/%s (acme)' % __version__})
        try:
            with url_open(req, timeout=30, context=ssl.create_default_context()
                          if base.startswith('https') else None) as r:
                raw = r.read(1 << 20)
                return json.loads(raw.decode()) if raw.strip() else None
        except urllib.error.HTTPError as e:
            if e.code == 404 and method == 'GET':
                return None
            if e.code == 429 and attempt < 2:
                try:
                    pause = float(e.headers.get('Retry-After') or 5)
                except ValueError:
                    pause = 5
                time.sleep(min(max(pause, 1), 60))
                continue
            said = e.read(400).decode('utf-8', 'replace')
            raise AcmeError('deSEC said %d: %s' % (e.code, said.strip() or e.reason))
        except OSError as e:
            raise AcmeError('deSEC did not answer: %s' % getattr(e, 'reason', e))
    raise AcmeError('deSEC asked to wait too long (429)')


def _dns_desec(rr, txt):
    dom = str(CONFIG.get('acme_desec_domain') or '').strip().rstrip('.').lower()
    if not dom:
        raise AcmeError('the domain at deSEC is not set')
    if not rr.endswith('.' + dom):
        raise AcmeError('%s is not in %s' % (rr, dom))
    sub = rr[:-len(dom) - 1]
    path = '/domains/%s/rrsets/' % urllib.parse.quote(dom)
    info = _desec('GET', '/domains/%s/' % urllib.parse.quote(dom))
    if info is None:
        raise AcmeError('deSEC has no domain %s that the token may see' % dom)
    ttl = max(int(info.get('minimum_ttl') or 3600), 60)
    one = '"%s"' % txt

    def have():
        got = _desec('GET', '%s%s/TXT/' % (path, urllib.parse.quote(sub))) or {}
        return list(got.get('records') or [])

    recs = have()
    if one not in recs:
        recs.append(one)
    _desec('PATCH', path, [{'subname': sub, 'type': 'TXT', 'ttl': ttl, 'records': recs}])

    def undo():
        left = [x for x in have() if x != one]
        _desec('PATCH', path, [{'subname': sub, 'type': 'TXT', 'ttl': ttl, 'records': left}])
    return undo


ACME_MANUAL_WAIT = float(os.environ.get('UPSMON_ACME_MANUAL_WAIT') or 3600)


def _dns_manual(store, rr, txt, say):
    """Shown on the page; waited for until somebody says it is in DNS."""
    ident = secrets.token_hex(6)
    store.set_meta('acme:manual', json.dumps({'id': ident, 'rr': rr, 'txt': txt, 'at': time.time()}))
    say('waiting: put %s TXT "%s" in DNS, then say so on the page' % (rr, txt))
    end = time.time() + ACME_MANUAL_WAIT
    try:
        while time.time() < end:
            got = _meta_json(store, 'acme:manual') or {}
            if got.get('id') != ident:
                raise AcmeError('the manual DNS step was given up')
            if got.get('done'):
                return lambda: None
            time.sleep(2)
        raise AcmeError('nobody said the TXT record was in DNS within an hour')
    finally:
        got = _meta_json(store, 'acme:manual') or {}
        if got.get('id') == ident:
            store.db.run("DELETE FROM meta WHERE k = 'acme:manual'")


# ---- what goes into your DNS, and whether it is there (1.0.170) -------------------------
def acme_resolvers():
    """The DNS servers ACME asks (1.0.172): its own setting, else the
    machine's (/etc/resolv.conf) - never the mail's."""
    out = []
    for w in re.split(r'[\s,;]+', str(CONFIG.get('acme_resolvers') or '')):
        try:
            out.append(str(ipaddress.ip_address(w)))
        except ValueError:
            pass
    return out


def _os_resolvers():
    out = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                bits = line.split()
                if len(bits) >= 2 and bits[0] == 'nameserver':
                    out.append(bits[1])
    except OSError:
        pass
    return out or ['127.0.0.1']


def dns_ask(name, qtype):
    """One question to ACME's DNS servers (the mail's own DNS client):
    [(type, text)] of the answer - CNAME (5), TXT (16), A (1), AAAA (28), NS (2).
    [] for a name that is not there; OSError when no resolver answers."""
    return dns_ask_rc(name, qtype)[1]


def dns_ask_rc(name, qtype):
    """dns_ask, and whether the name is there at all: (rcode, records) - 3 is
    NXDOMAIN, which a CNAME to a name nobody serves ends in too."""
    last = None
    for srv in (acme_resolvers() or _os_resolvers())[:3]:
        try:
            data = _dns_ask(srv, str(name).rstrip('.'), qtype, 3.0)
        except OSError as e:
            last = e
            continue
        rcode, out = _dns_parse(data)
        if rcode in (0, 3):
            return rcode, out
        last = OSError(DNS_RCODES.get(rcode, 'rcode %d' % rcode))
    raise OSError('no DNS server answered (%s)' % (last or 'none'))


def _dns_parse(data):
    """(rcode, [(type, text)]) of one answer."""
    rcode, recs = _dns_records(data)
    if rcode:
        return rcode, []
    out = []
    for rtype, _n, at, size in recs:
        rd = data[at:at + size]
        if rtype == 5:
            out.append(('CNAME', _dns_name(data, at)[0].lower()))
        elif rtype == 16:
            j, parts = 0, []
            while j < len(rd):
                parts.append(rd[j + 1:j + 1 + rd[j]].decode('utf-8', 'replace'))
                j += 1 + rd[j]
            out.append(('TXT', ''.join(parts)))
        elif rtype == 1 and size == 4:
            out.append(('A', socket.inet_ntop(socket.AF_INET, rd)))
        elif rtype == 28 and size == 16:
            out.append(('AAAA', socket.inet_ntop(socket.AF_INET6, rd)))
        elif rtype == 2:
            out.append(('NS', _dns_name(data, at)[0].lower()))
    return 0, out


# Names looked up by ACME's DNS servers (1.0.172): in the threads of this page
# only - the CA, the DNS API, Try port 80 - every other lookup of the daemon
# as the machine's.
_ACME_DNS = threading.local()
_SYS_GETADDRINFO = socket.getaddrinfo


def _acme_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if getattr(_ACME_DNS, 'on', False) and host and acme_resolvers():
        h = host.decode() if isinstance(host, bytes) else str(host)
        try:
            ipaddress.ip_address(h.strip('[]'))
        except ValueError:
            if h not in ('localhost',):
                addrs = []
                for qtype, kind in ((1, 'A'), (28, 'AAAA')):
                    if family in (0, socket.AF_INET if kind == 'A' else socket.AF_INET6):
                        try:
                            addrs += [a for t, a in dns_ask(h, qtype) if t == kind]
                        except OSError:
                            pass
                if not addrs:
                    raise socket.gaierror(socket.EAI_NONAME, '%s is not known to %s' % (
                        h, ', '.join(acme_resolvers())))
                out = []
                for a in addrs:
                    out += _SYS_GETADDRINFO(a, port, family, type, proto,
                                            flags | socket.AI_NUMERICHOST)
                return out
    return _SYS_GETADDRINFO(host, port, family, type, proto, flags)


socket.getaddrinfo = _acme_getaddrinfo


class acme_dns_scope(object):
    """with acme_dns_scope(): names looked up by ACME's DNS servers."""
    def __enter__(self):
        self.was = getattr(_ACME_DNS, 'on', False)
        _ACME_DNS.on = True

    def __exit__(self, *a):
        _ACME_DNS.on = self.was


def acme_txt_seen(name, txt, say):
    """After the wait: whether ACME's DNS servers see the TXT record (through
    its CNAME) - asked again for up to two minutes; the CA asked either way."""
    rr = '_acme-challenge.' + name.rstrip('.')
    end = time.time() + float(os.environ.get('UPSMON_ACME_SEEN_WAIT') or 120)
    while True:
        try:
            got = [v for t, v in dns_ask(rr, 16) if t == 'TXT']
        except OSError as e:
            say('DNS could not be asked whether the record is there (%s): the CA is asked anyway'
                % str(e)[:80])
            return False
        if txt in got:
            say('%s TXT is seen by %s' % (rr, ', '.join(acme_resolvers()) or 'this machine\'s DNS'))
            return True
        if time.time() > end:
            say('%s TXT is not seen yet by %s - the CA is asked anyway' % (
                rr, ', '.join(acme_resolvers()) or 'this machine\'s DNS'))
            return False
        time.sleep(5)


def acme_dns_guide(store):
    """What each certificate asked for needs in your DNS, by how the CA
    checks it - for the card In your DNS."""
    rows = []
    http = (CONFIG.get('acme_challenge') or 'http-01') != 'dns-01'
    how = CONFIG.get('acme_dns') or 'manual'
    v = vip_conf(store)
    addr = {n['name']: n.get('address') for n in ha_nodes(store)}
    addr.setdefault(node_name(), node_address())
    for t in acme_wanted(store):
        name = acme_name_of(store, t)
        if not name:
            rows.append({'target': t, 'name': '', 'type': '', 'record': '', 'value': '',
                         'why': 'its name is not known yet'})
            continue
        if http:
            where = str(v.get('address') or '').split('/')[0] if t == 'vip' else addr.get(t) or ''
            rows.append({'target': t, 'name': name, 'type': 'A', 'record': name, 'value': where,
                         'why': 'the name points at an address that reaches port 80 of %s' % (
                             'the VIP address' if t == 'vip' else t), 'check': 'a'})
            continue
        rr, cname = acme_dns_where(name)
        if how == 'desec' and cname:
            dom = str(CONFIG.get('acme_desec_domain') or '').strip().rstrip('.').lower()
            if dom and not dom.endswith('.dedyn.io') and not any(
                    x.get('type') == 'NS' for x in rows):
                # A domain of your own at deSEC (1.0.174): the zone above it
                # must send the internet there - NS records, once.
                rows.append({'target': '', 'name': dom, 'type': 'NS', 'record': dom,
                             'value': 'ns1.desec.io. ns2.desec.org.',
                             'why': 'once, in the zone above it: %s at deSEC' % dom,
                             'check': 'ns'})
        own = '_acme-challenge.' + name
        if how == 'acmedns' or cname:
            rows.append({'target': t, 'name': name, 'type': 'CNAME', 'record': own,
                         'value': (cname or '?') + '.', 'why': 'once, by hand, in your DNS',
                         'check': 'cname'})
        elif how == 'manual':
            rows.append({'target': t, 'name': name, 'type': 'TXT', 'record': rr,
                         'value': 'shown here at every order', 'why': 'by hand, at every order'})
        else:
            rows.append({'target': t, 'name': name, 'type': 'TXT', 'record': rr, 'value': '',
                         'why': 'nothing to do: upsmon puts it in and takes it away'})
    return {'rows': rows, 'challenge': 'http-01' if http else 'dns-01', 'dns': how}


def acme_dns_check(store):
    """Each row of the guide looked up from this node, as the CA will."""
    g = acme_dns_guide(store)
    for r in g['rows']:
        if not r.get('check'):
            continue
        try:
            if r['check'] == 'cname':
                rc, recs = dns_ask_rc(r['record'], 5)
                got = [x[1] for x in recs if x[0] == 'CNAME']
                want = r['value'].rstrip('.').lower()
                r['found'] = got[0] + '.' if got else ''
                r['ok'] = bool(got) and got[0].rstrip('.') == want
                r['said'] = 'there' if r['ok'] else (
                    'it points elsewhere: %s' % r['found'] if got else 'not there yet')
            elif r['check'] == 'ns':
                rc, recs = dns_ask_rc(r['record'], 2)
                got = sorted(x[1] for x in recs if x[0] == 'NS')
                r['found'] = ' '.join(got)
                r['ok'] = any(x.rstrip('.').endswith(('desec.io', 'desec.org')) for x in got)
                r['said'] = 'there' if r['ok'] else (
                    ('it is served by %s, not deSEC' % r['found']) if got else
                    'not delegated: the internet does not know %s' % r['record'])
            else:
                with acme_dns_scope():
                    got = sorted({a[4][0] for a in socket.getaddrinfo(
                        r['record'], 80, proto=socket.IPPROTO_TCP)})
                r['found'] = ', '.join(got)
                r['ok'] = bool(got)
                r['said'] = 'it points at %s' % r['found'] if got else 'not there'
        except (OSError, socket.gaierror) as e:
            r.update(ok=False, said='could not be looked up: %s' % str(e)[:120])
    g['at'] = time.time()
    g['resolvers'] = acme_resolvers() or ['this machine\'s DNS']
    g['own_resolvers'] = bool(acme_resolvers())
    return g




# ======== carried over from OTP 1.0.187 (lines 26989-26994): the root helper asked: names ========
NET_ASK_NAME = 'net.ask'
NET_ANSWER_NAME = 'net.json'
NET_READ_S = 300                # how often each node says what its network is
NET_JOB_LIVE_S = 1800           # a job not moving for this long is over
NET_WORK = {'busy': False, 'read_at': 0.0}
NET_WORK_LOCK = threading.Lock()


# ======== carried over from OTP 1.0.187 (lines 27015-27045): the root helper asked, one at a time ========

NET_ROOT_LOCK = threading.Lock()


def net_root(data, wait=60):
    """One request to the root helper (upsmon_web.py) and its answer - one at a
    time (1.0.146): "Read it again" on the pages during a job wrote over the
    job's request, or took its answer, and the job waited for nothing."""
    with NET_ROOT_LOCK:
        ask_id = secrets.token_hex(8)
        data = dict(data, id=ask_id)
        tmp = WEB_DIR / ('.%s.%s' % (NET_ASK_NAME, secrets.token_hex(6)))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(data))
        os.replace(str(tmp), str(WEB_DIR / NET_ASK_NAME))
        end = time.time() + wait
        while time.time() < end:
            try:
                got = json.loads((WEB_DIR / NET_ANSWER_NAME).read_text())
            except (OSError, ValueError):
                got = None
            if isinstance(got, dict) and got.get('id') == ask_id:
                if not got.get('ok'):
                    raise ValueError(got.get('said') or 'the root helper said no')
                return got.get('data') or {}
            time.sleep(0.4)
    raise ValueError('the root helper of this node did not answer in %d s - is upsmon-web.path '
                     'running?  systemctl status upsmon-web.path' % wait)




# ======== carried over from OTP 1.0.187 (lines 27765-27932): restart and power off ========
# ---- restart and power off ------------------------------------------------------------
POWER_LIVE_S = 1800


def power_plan(store):
    return _meta_json(store, 'power:plan') or {}


def power_busy(store):
    p = power_plan(store)
    if not p or time.time() - float(p.get('at') or 0) > POWER_LIVE_S:
        return False
    for n in p.get('targets') or []:
        row = _meta_json(store, 'power:node:' + n) or {}
        if row.get('id') != p.get('id') or row.get('state') in ('asked', 'going'):
            if p.get('how') == 'poweroff' and row.get('state') == 'going':
                continue
            return True
    return False


def power_ask(store, how, targets, order, by, keep_service=False):
    """`keep_service` (1.0.165): a node goes down only while another one
    answers - asked of every restart one after the other, on a schedule and
    after an update; a node that does not come back stops the rest."""
    if how not in ('reboot', 'poweroff'):
        raise ValueError('reboot or poweroff')
    known = [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]
    targets = [t for t in known if t in (targets or [])]
    if not targets:
        raise ValueError('which node?')
    if order not in ('one', 'rolling', 'together'):
        order = 'one' if len(targets) == 1 else 'rolling'
    if how == 'poweroff' and order == 'rolling':
        order = 'together'
    if power_busy(store):
        raise ValueError('a restart or a power-off is under way already')
    for t in targets:
        if net_job_active(_meta_json(store, 'net:job:' + t)):
            raise ValueError('%s is changing its network' % t)
    if order == 'rolling':
        # The node this page is not on last: the page stays with the other
        # while the first restarts.
        targets.sort(key=lambda n: n == node_name())
    keep_service = bool(keep_service or (order == 'rolling' and len(targets) > 1))
    if keep_service and CONFIG.get('ha_mode') and how == 'reboot':
        alive = [n['name'] for n in ha_nodes(store) if n.get('alive') or n.get('me')]
        if len(alive) < 2:
            raise ValueError('only %s answers: restarting it would stop the service - bring the '
                             'other node back first' % (', '.join(alive) or 'this node'))
    plan = {'id': secrets.token_hex(6), 'how': how, 'targets': targets, 'order': order,
            'by': by, 'at': time.time(), 'from': node_name(), 'keep_service': keep_service}
    store.set_meta('power:plan', json.dumps(plan))
    store.add_event('starting and stopping', '%s asked for a %s of %s%s' % (
        by, 'restart' if how == 'reboot' else 'power-off', ', '.join(targets),
        ' one after the other' if order == 'rolling' and len(targets) > 1 else
        (' at once' if len(targets) > 1 else '')), 'warn', who=by)
    return plan


def _power_put(store, row, state, words=''):
    row.update(state=state, moved=time.time())
    if words:
        row['said'] = str(words)[:300]
    store.set_meta('power:node:' + node_name(), json.dumps(row))


def power_go(daemon, plan):
    store = daemon.store
    row = {'id': plan['id'], 'how': plan['how'], 'at': time.time(), 'boot': boot_time()}
    try:
        many = bool(CONFIG.get('ha_mode'))
        if many and plan.get('keep_service') and plan['how'] == 'reboot' and \
                not any(n.get('alive') and not n.get('me') for n in ha_nodes(store)):
            # Its turn come, nobody else answers (1.0.165): it stays up.
            raise ValueError('no other node answers now - not restarted, the service goes on here')
        if many and plan.get('order') != 'together' and not (maintenance_row(store) or {}).get('on'):
            maintenance_set(store, True, 'a %s asked by %s' % (
                'restart' if plan['how'] == 'reboot' else 'power-off', plan.get('by')),
                plan.get('by') or '')
            row['maint'] = True
            v = vip_conf(store)
            end = time.time() + 90
            while v.get('on') and vip_here(v.get('address')) and time.time() < end:
                time.sleep(1)
            if v.get('on') and vip_here(v.get('address')) and plan.get('keep_service'):
                # The VIP address did not move (1.0.165): not restarted under it.
                raise ValueError('the VIP address did not move to the other node in 90 s - not '
                                 'restarted')
        row['down_at'] = time.time() + 5
        _power_put(store, row, 'going', 'going down')
        net_root({'do': 'power', 'how': plan['how'], 'in': 5}, 30)
        log('starting and stopping: %s in 5 s, asked by %s' % (plan['how'], plan.get('by')),
            'warn')
    except Exception as e:                              # noqa: BLE001
        if row.get('maint'):
            try:
                maintenance_set(store, False, '', plan.get('by') or '')
            except Exception:                           # noqa: BLE001
                pass
        _power_put(store, row, 'failed', str(e))


def power_back(daemon, row):
    store = daemon.store
    if row.get('maint'):
        maintenance_set(store, False, '', 'after the restart')
    _power_put(store, row, 'back', 'up again')
    store.add_event('starting and stopping', '%s is up again after the restart' % node_name())


def power_tick(daemon):
    """This node's part of a restart or power-off: its turn, and after it."""
    store = daemon.store
    me = node_name()
    plan = power_plan(store)
    row = _meta_json(store, 'power:node:' + me) or {}
    if row.get('state') == 'going' and row.get('how') == 'reboot':
        if boot_time() > float(row.get('boot') or 0) + 1:
            _net_thread(power_back, daemon, row)
            return True
        if time.time() - float(row.get('moved') or 0) > 900:
            _power_put(store, row, 'failed', 'it did not restart in 15 minutes')
        return False
    if not plan or me not in (plan.get('targets') or []) or row.get('id') == plan.get('id'):
        return False
    if time.time() - float(plan.get('at') or 0) > POWER_LIVE_S:
        return False
    if plan.get('order') == 'rolling':
        for t in plan['targets']:
            if t == me:
                break
            other = _meta_json(store, 'power:node:' + t) or {}
            if other.get('id') != plan['id'] or other.get('state') not in ('back', 'failed'):
                return False                # not my turn yet
            if other.get('state') == 'failed' and plan.get('keep_service'):
                # One before did not come back (1.0.165): the rest stays up.
                _power_put(store, {'id': plan['id'], 'how': plan['how'], 'at': time.time(),
                                   'boot': boot_time()}, 'failed',
                           'not restarted: %s did not restart and come back' % t)
                store.add_event('starting and stopping', '%s was not restarted: %s did not come '
                                'back - the service goes on here' % (me, t), 'bad')
                return False
    _net_thread(power_go, daemon, plan)
    return True


def power_view(store):
    plan = power_plan(store)
    nodes = []
    hb = {n['name']: n for n in ha_nodes(store)}
    names = [node_name()] + [n for n in hb if n != node_name()]
    for n in names:
        b = hb.get(n) or {}
        row = _meta_json(store, 'power:node:' + n) or {}
        nodes.append({'name': n, 'me': n == node_name(), 'alive': bool(b.get('alive', True)
                                                                      if n == node_name() else
                                                                      b.get('alive')),
                      'started': b.get('started'), 'age': b.get('age'),
                      'address': b.get('address') or '', 'version': b.get('version') or '',
                      'row': row if row.get('id') == plan.get('id') else {}})
    # Hidden from the page by whoever pressed Hide this (1.0.123).
    seen = store.get_meta('power:seen') == str(plan.get('id') or '')
    return {'plan': plan if plan and not seen and time.time() - float(plan.get('at') or 0) < POWER_LIVE_S
            else {}, 'nodes': nodes, 'now': time.time(), 'cluster': len(nodes) > 1,
            'busy': power_busy(store)}




# ======== carried over from OTP 1.0.187 (lines 28228-28241): the time: chrony ========
# ---- the time: chrony on every node (1.0.120) ----------------------------------------
# Codes from the app are worked out from the clock: a node whose clock is off by
# more than half a period refuses codes that are right. Settings → Time shows
# each node's clock as chrony sees it (offset, stratum, its sources) and sets
# the time servers for the whole cluster: kept in meta 'ntp:conf', put in by
# each node's root helper when it changes ('ntp:applied:NODE'), and in a
# cluster each node also takes the other as one more source.
NTP_READ_S = 60
NTP_WORK = {'busy': False, 'read_at': 0.0, 'last': {}}
NTP_WORK_LOCK = threading.Lock()
NTP_DEFAULT = {'manage': False, 'servers': [], 'peers': True, 'allow': [],
               'makestep': [1.0, 3], 'minsources': 1, 'timezone': ''}




# ======== carried over from OTP 1.0.187 (lines 28265-28471): the time: chrony ========
def ntp_conf(store):
    c = dict(NTP_DEFAULT)
    c.update(_meta_json(store, 'ntp:conf') or {})
    return c


def ntp_desired(store):
    c = ntp_conf(store)
    peers = []
    if c.get('manage') and c.get('peers') and CONFIG.get('ha_mode') and CONFIG.get('ha_peer'):
        try:
            peers = [str(ipaddress.ip_address(str(CONFIG['ha_peer'])))]
        except ValueError:
            peers = []
    return {'manage': bool(c.get('manage')), 'servers': c.get('servers') or [],
            'peers': peers, 'allow': c.get('allow') or [],
            'makestep': c.get('makestep') or [1.0, 3], 'minsources': c.get('minsources') or 1,
            'timezone': c.get('timezone') or ''}


def ntp_checked(b):
    """The settings from the page, made whole - the root helper checks them
    again."""
    out = dict(NTP_DEFAULT)
    out['manage'] = bool(b.get('manage'))
    servers = []
    for x in (b.get('servers') or [])[:12]:
        if not isinstance(x, dict):
            continue
        host = str(x.get('host') or '').strip().lower().rstrip('.')
        if not host:
            continue
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not re.match(r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
                            r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', host):
                raise ValueError('%r is not a host name or an address' % host)
        servers.append({'host': host, 'pool': bool(x.get('pool')),
                        'iburst': bool(x.get('iburst', True)), 'prefer': bool(x.get('prefer')),
                        'nts': bool(x.get('nts'))})
    if out['manage'] and not servers:
        raise ValueError('at least one time server - or let the machines keep their own')
    out['servers'] = servers
    out['peers'] = bool(b.get('peers', True))
    allow = []
    for a in re.split(r'[\s,;]+', b.get('allow') if isinstance(b.get('allow'), str)
                      else ' '.join(b.get('allow') or [])):
        if not a:
            continue
        try:
            allow.append(str(ipaddress.ip_network(a, strict=False)))
        except ValueError:
            raise ValueError('%r is not a network (192.0.2.0/24)' % a)
    out['allow'] = allow[:20]
    try:
        th = float(b.get('step_s', 1.0))
        lim = int(b.get('step_n', 3))
    except (TypeError, ValueError):
        raise ValueError('the step: seconds, and how many updates')
    if not (0.001 <= th <= 3600) or not (-1 <= lim <= 1000):
        raise ValueError('the step: 0.001 to 3600 s; -1 (always) to 1000 updates')
    out['makestep'] = [th, lim]
    try:
        out['minsources'] = max(1, min(10, int(b.get('minsources') or 1)))
    except (TypeError, ValueError):
        raise ValueError('how many sources have to agree is a number')
    tz = str(b.get('timezone') or '').strip()
    if tz and not re.match(r'^[A-Za-z0-9_+-]{1,40}(/[A-Za-z0-9_+-]{1,40}){0,3}\Z', tz):
        raise ValueError('%r is not a time zone' % tz)
    out['timezone'] = tz
    return out


def ntp_save(store, b, by):
    c = ntp_checked(b)
    c.update(at=time.time(), by=by)
    store.set_meta('ntp:conf', json.dumps(c))
    what = ('the servers %s%s' % (', '.join(x['host'] for x in c['servers']),
                                  '; the nodes take each other too' if c['peers'] and
                                  CONFIG.get('ha_mode') else '')) if c['manage'] \
        else 'each machine keeps its own servers'
    if c['timezone']:
        what += '; time zone %s' % c['timezone']
    store.add_event('settings', '%s set the time: %s' % (by, what), 'warn', who=by)
    return c


def ntp_publish(store, zones=False):
    data = root_ask('ntp.ask', 'ntp.json', {'do': 'read', 'zones': zones}, 30)
    now = {'at': time.time(), 'data': {k: v for k, v in data.items() if k != 'zones'}}
    store.set_meta('ntp:now:' + node_name(), json.dumps(now))
    NTP_WORK['read_at'] = time.time()
    NTP_WORK['last'] = now
    if zones and data.get('zones'):
        store.set_meta('ntp:zones', json.dumps(data['zones']))
    return now


def ntp_apply(store):
    want = ntp_desired(store)
    h = hashlib.sha256(json.dumps(want, sort_keys=True).encode()).hexdigest()[:24]
    row = {'hash': h, 'at': time.time()}
    try:
        got = root_ask('ntp.ask', 'ntp.json', dict(want, do='apply'), 300)
        row.update(ok=True, said='; '.join(got.get('said') or []) or 'as it was')
        log('the time: %s' % row['said'])
    except ValueError as e:
        row.update(ok=False, said=str(e)[:300])
        log('the time servers could not be set: %s' % e, 'warn')
    store.set_meta('ntp:applied:' + node_name(), json.dumps(row))
    try:
        ntp_publish(store)
    except Exception:                                   # noqa: BLE001
        pass


def _ntp_thread(fn, *args):
    def go():
        try:
            fn(*args)
        except Exception as e:                          # noqa: BLE001
            log('the time: %s' % e, 'warn')
        finally:
            with NTP_WORK_LOCK:
                NTP_WORK['busy'] = False
    with NTP_WORK_LOCK:
        if NTP_WORK['busy']:
            return False
        NTP_WORK['busy'] = True
    threading.Thread(target=go, name='upsmon-ntp', daemon=True).start()
    return True


def ntp_sync(store):
    got = root_ask('ntp.ask', 'ntp.json', {'do': 'sync'}, 60)
    store.add_event('settings', '%s: the clock stepped to the time servers now (%s)' % (
        node_name(), '; '.join(got.get('said') or [])), 'warn')
    time.sleep(3)
    ntp_publish(store)


def ntp_tick(daemon):
    if HA_REBUILDING.is_set() or not WEB_DIR.is_dir():
        return
    store = daemon.store
    me = node_name()
    if NTP_WORK['busy']:
        return
    conf = _meta_json(store, 'ntp:conf')
    if conf:
        want = ntp_desired(store)
        h = hashlib.sha256(json.dumps(want, sort_keys=True).encode()).hexdigest()[:24]
        done = _meta_json(store, 'ntp:applied:' + me) or {}
        if done.get('hash') != h and time.time() - float(done.get('at') or 0) > 30:
            _ntp_thread(ntp_apply, store)
            return
    sync_at = float(store.get_meta('ntp:sync:' + me) or 0)
    if sync_at > float(NTP_WORK.get('synced') or 0) and time.time() - sync_at < 300:
        NTP_WORK['synced'] = sync_at
        _ntp_thread(ntp_sync, store)
        return
    wanted = float(store.get_meta('ntp:read:' + me) or 0)
    if time.time() - NTP_WORK['read_at'] > NTP_READ_S or wanted > NTP_WORK['read_at']:
        _ntp_thread(ntp_publish, store, wanted > NTP_WORK['read_at'] or
                    not store.get_meta('ntp:zones'))


def ntp_problem():
    """Words for the status when this node's clock is not to be trusted."""
    now = NTP_WORK.get('last') or {}
    d = now.get('data') or {}
    if not d or time.time() - float(now.get('at') or 0) > 600:
        return ''
    t = d.get('tracking') or {}
    if d.get('chrony') and t:
        if t.get('leap') == 'Not synchronised' or not t.get('stratum'):
            return ('the clock is not synchronised to a time server (chrony) - codes from the '
                    'app are worked out from it: Settings → Time')
        if abs(float(t.get('offset') or 0)) > 1.0:
            return ('the clock is %.1f s off the time servers - codes from the app are worked '
                    'out from it: Settings → Time' % abs(float(t['offset'])))
    elif d.get('ntpsynchronized') == 'no':
        return 'the clock is not synchronised (timedatectl): Settings → Time'
    return ''


def ntp_view(store):
    hb = {n['name']: n for n in ha_nodes(store)}
    names = [node_name()] + sorted(n for n in hb if n != node_name())
    nodes = []
    for n in names:
        nodes.append({'name': n, 'me': n == node_name(),
                      'alive': True if n == node_name() else bool((hb.get(n) or {}).get('alive')),
                      'now': _meta_json(store, 'ntp:now:' + n) or {},
                      'applied': _meta_json(store, 'ntp:applied:' + n) or {}})
    try:
        zones = json.loads(store.get_meta('ntp:zones') or '[]')
    except ValueError:
        zones = []
    conf = ntp_conf(store)
    want = ntp_desired(store)
    h = hashlib.sha256(json.dumps(want, sort_keys=True).encode()).hexdigest()[:24]
    return {'nodes': nodes, 'conf': conf, 'zones': zones, 'cluster': len(nodes) > 1,
            'hash': h if _meta_json(store, 'ntp:conf') else '', 'now': time.time()}




# ======== carried over from OTP 1.0.187 (lines 28582-28597): the machine: its nodes ========
HOST_WORK = {'ssh': False, 'ssh_seen': 0.0, 'ssh_since': 0.0, 'osup': False, 'osup_read': 0.0}


def host_nodes(store):
    return [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]


def host_alive(store):
    """{node: whether it is heard from}."""
    out = {node_name(): True}
    for n in ha_nodes(store):
        if n['name'] != node_name():
            out[n['name']] = bool(n.get('alive'))
    return out




# ======== carried over from OTP 1.0.187 (lines 28835-29192): the updates of the system ========
OSUP_STATES = ('waiting', 'draining', 'updating', 'rebooting', 'done', 'failed', 'skipped')


def osup_plan(store):
    return _meta_json(store, 'host:osup:plan') or {}


def osup_row(store, name):
    return _meta_json(store, 'host:osup:node:' + name) or {}


def osup_put(store, row, **kw):
    row.update(kw, at=time.time())
    store.set_meta('host:osup:node:' + node_name(), json.dumps(row))
    return row


def osup_view(store):
    plan = osup_plan(store)
    seen = store.get_meta('host:osup:seen')
    alive = host_alive(store)
    nodes = []
    for n in host_nodes(store):
        row = osup_row(store, n)
        chk = _meta_json(store, 'host:osup:check:' + n) or {}
        nodes.append({'name': n, 'me': n == node_name(), 'alive': alive.get(n, False),
                      'row': row if row.get('plan') == plan.get('id') else {},
                      'check': chk, 'reboot': bool(row.get('reboot') and not row.get('rebooted')) or
                      bool(chk.get('reboot_now') and chk.get('state') == 'done'),
                      'started': (_meta_json(store, 'node:' + n) or {}).get('started')})
    _osup_cleared(store, nodes)
    hidden = bool(plan) and seen == plan.get('id') and plan.get('state') != 'running'
    return {'plan': {} if hidden else plan, 'nodes': nodes, 'now': time.time(),
            'cluster': bool(CONFIG.get('ha_mode')), 'helper': WEB_DIR.is_dir(),
            'power': power_plan(store) if power_busy(store) else {}}


def _osup_mark(part):
    """Which run a part's lines are of: the same mark, the same run."""
    return '%s|%s' % (part.get('plan') or part.get('id') or '', part.get('began') or '')


def _osup_cleared(store, nodes):
    """The lines cleared from the window (1.0.159) left out: of the run they
    were cleared in, only what came after the last line then shown. Kept in
    the database, so for every page and after a reload."""
    cl = _meta_json(store, 'host:osup:cleared') or {}
    for n in nodes:
        for part in ('row', 'check'):
            p = n.get(part) or {}
            c = (cl.get(n['name']) or {}).get(part) or {}
            lines = p.get('lines') or []
            if not lines or not c or c.get('mark') != _osup_mark(p):
                continue
            last = c.get('last')
            at = max((i for i, ln in enumerate(lines) if ln == last), default=None)
            n[part] = dict(p, lines=lines[at + 1:] if at is not None else lines)


def osup_clear(store, by):
    """The window of every node emptied: the lines there now not shown again."""
    plan = osup_plan(store)
    cl = {}
    for n in host_nodes(store):
        row = osup_row(store, n)
        parts = {'row': row if row.get('plan') == plan.get('id') else {},
                 'check': _meta_json(store, 'host:osup:check:' + n) or {}}
        cl[n] = {k: {'mark': _osup_mark(p), 'last': (p.get('lines') or [''])[-1]}
                 for k, p in parts.items() if p.get('lines')}
    store.set_meta('host:osup:cleared', json.dumps(cl))


def osup_check_ask(store, nodes, by):
    nodes = [n for n in host_nodes(store) if n in (nodes or [])]
    if not nodes:
        raise ValueError('which node?')
    for n in nodes:
        store.set_meta(node_key('host:osup:checkwant', n),
                       json.dumps({'id': secrets.token_hex(6), 'by': by, 'at': time.time()}))
    return nodes


def osup_start(store, nodes, reboot, by, security=False):
    plan = osup_plan(store)
    if plan.get('state') == 'running':
        raise ValueError('an update is going on already')
    if upgrade_plan(store) and upgrade_plan(store).get('state') == 'running':
        raise ValueError('an upgrade of upsmon is going on - wait for it to end')
    if power_busy(store):
        raise ValueError('a restart or a power off is going on - wait for it to end')
    known = host_nodes(store)
    alive = host_alive(store)
    nodes = [n for n in known if n in (nodes or known)]
    if not nodes:
        raise ValueError('which node?')
    gone = [n for n in nodes if not alive.get(n)]
    if gone:
        raise ValueError('%s is not heard from: bring it back first' % ', '.join(gone))
    if reboot not in ('ask', 'auto'):
        reboot = 'ask'
    # The others first, this one last - the page the person looks at stays
    # up the longest, as in an upgrade of upsmon.
    me = node_name()
    order = sorted(n for n in nodes if n != me) + ([me] if me in nodes else [])
    plan = {'id': secrets.token_hex(6), 'order': order, 'reboot': reboot, 'by': by,
            'at': time.time(), 'state': 'running', 'from': me, 'security': bool(security)}
    store.set_meta('host:osup:plan', json.dumps(plan))
    store.add_event('settings', '%s started the update of the system%s: %s, one at a time%s'
                    % (by, ' (security updates only)' if security else '', ', '.join(order),
                       ', each restarted when it needs it' if reboot == 'auto' else ''),
                    'warn', who=by)
    return plan


def osup_cancel(store, by):
    plan = osup_plan(store)
    if plan.get('state') != 'running':
        raise ValueError('no update is going on')
    plan.update(state='cancelled', ended=time.time(), cancelled_by=by)
    store.set_meta('host:osup:plan', json.dumps(plan))
    store.add_event('settings', '%s stopped the update of the system - a node being updated '
                    'finishes' % by, 'warn', who=by)


def _osup_job(kind, security=False):
    """The helper asked to start the work; its id."""
    got = root_ask('osup.ask', 'osup.ans', {'do': 'run', 'kind': kind,
                                             'security': bool(security),
                                             # dnf and apt through Settings → Proxy (1.0.166)
                                             'proxy': proxy_full('os'),
                                             'proxy_no': ','.join(proxy_no_list())}, 60)
    return got


def _osup_read():
    try:
        return json.loads((WEB_DIR / 'osup.json').read_text())
    except (OSError, ValueError):
        return {}


def osup_tick(daemon):
    """Every few seconds: a look for updates asked of this node; its turn in an
    update; what the helper says while it works."""
    store = daemon.store
    me = node_name()
    if HOST_WORK['osup'] or HA_REBUILDING.is_set():
        return
    # Back up after a restart the update asked for: done, and back in service.
    row = osup_row(store, me)
    if row.get('reboot') and not row.get('rebooted') and \
            boot_time() > float(row.get('done_at') or row.get('at') or 0) + 1:
        row['rebooted'] = True
        store.set_meta(node_key('host:osup:checkwant', me),
                       json.dumps({'id': secrets.token_hex(6), 'by': 'upsmon (system update)',
                                   'at': time.time()}))
        if row.get('state') == 'rebooting':
            row['state'] = 'done'
            row['said'] = 'up again after the restart'
            plan = osup_plan(store)
            if plan.get('state') == 'running' and (plan.get('order') or [None])[-1] == me and \
                    row.get('plan') == plan.get('id'):
                plan.update(state='done', ended=time.time())
                store.set_meta('host:osup:plan', json.dumps(plan))
            if row.get('maint'):
                try:
                    maintenance_set(store, False, '', 'upsmon (system update)')
                except Exception:                       # noqa: BLE001
                    pass
                row['maint'] = False
        osup_put(store, row)
    # A look for updates, asked.
    chk = _meta_json(store, 'host:osup:check:' + me) or {}
    # It said a restart was waiting and the node has restarted since: looked
    # at again, not left saying so (1.0.159).
    if chk.get('reboot_now') and chk.get('state') == 'done' and not chk.get('relook') and \
            boot_time() > float(chk.get('checked') or 0) + 1:
        chk['relook'] = True
        store.set_meta('host:osup:check:' + me, json.dumps(chk))
        store.set_meta(node_key('host:osup:checkwant', me),
                       json.dumps({'id': secrets.token_hex(6), 'by': 'upsmon (system update)',
                                   'at': time.time()}))
    for r in node_key_rows(store, 'host:osup:checkwant', me):
        try:
            a = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if a.get('id') and a['id'] not in (chk.get('asked') or []) and \
                time.time() - float(a.get('at') or 0) < 900:
            _osup_go(daemon, 'check', a)
            return
    if chk.get('state') == 'running':
        _osup_follow_check(store, chk)
        return
    plan = osup_plan(store)
    if plan.get('state') != 'running' or me not in (plan.get('order') or []):
        return
    row = osup_row(store, me)
    if row.get('plan') != plan.get('id'):
        row = {'plan': plan.get('id'), 'state': 'waiting'}
    st = row.get('state') or 'waiting'
    if st == 'waiting':
        # My turn once every node before me is done.
        before = plan['order'][:plan['order'].index(me)]
        rows = {n: osup_row(store, n) for n in before}
        bad = [n for n in before if rows[n].get('plan') == plan['id'] and
               rows[n].get('state') == 'failed']
        if bad:
            return
        if all(rows[n].get('plan') == plan['id'] and rows[n].get('state') in ('done', 'skipped')
               for n in before):
            _osup_go(daemon, 'upgrade', {'plan': plan, 'row': row})
        return
    if st == 'draining':
        if time.time() - float(row.get('drain_at') or 0) >= 15:
            _osup_go(daemon, 'upgrade-now', {'plan': plan, 'row': row})
        return
    if st == 'updating':
        _osup_follow(daemon, plan, row)


def _osup_go(daemon, what, ctx):
    HOST_WORK['osup'] = True

    def go():
        store = daemon.store
        me = node_name()
        by = 'upsmon (system update)'
        try:
            if what == 'check':
                chk = _meta_json(store, 'host:osup:check:' + me) or {}
                asked = (list(chk.get('asked') or []) + [ctx['id']])[-20:]
                try:
                    _osup_job('check')
                    store.set_meta('host:osup:check:' + me, json.dumps(
                        dict(chk, state='running', asked=asked, began=time.time(), at=time.time(),
                             error='', lines=[])))
                except ValueError as e:
                    store.set_meta('host:osup:check:' + me, json.dumps(
                        dict(chk, state='failed', asked=asked, at=time.time(), error=str(e)[:300])))
                return
            plan, row = ctx['plan'], ctx['row']
            if what == 'upgrade':
                # Out of service first where another node answers meanwhile:
                # the VIP address moves to it, RADIUS is answered there.
                many = any(n.get('alive') and not n.get('me') for n in ha_nodes(store))
                if many:
                    maintenance_set(store, True, 'the system is being updated', by)
                    osup_put(store, row, state='draining', drain_at=time.time(), maint=True,
                             said='out of service - the other node answers', pct=0, lines=[])
                    return
                row['maint'] = False
            try:
                _osup_job('upgrade', bool(plan.get('security')))
                osup_put(store, row, state='updating', began=time.time(), pct=1, lines=[],
                         said='the packages are being updated')
            except ValueError as e:
                _osup_end(store, plan, row, False, str(e))
        except Exception as e:                          # noqa: BLE001
            log('the update of the system: %s' % e, 'warn')
        finally:
            HOST_WORK['osup'] = False
    threading.Thread(target=go, name='upsmon-osup', daemon=True).start()


def _osup_follow_check(store, chk):
    me = node_name()
    got = _osup_read()
    if not got or got.get('kind') != 'check' or float(got.get('began') or 0) < \
            float(chk.get('began') or 0) - 5:
        if time.time() - float(chk.get('began') or 0) > 1800:
            store.set_meta('host:osup:check:' + me, json.dumps(
                dict(chk, state='failed', error='the helper did not say anything', at=time.time())))
        return
    if got.get('state') == 'running':
        if time.time() - float(chk.get('at') or 0) > 3:
            store.set_meta('host:osup:check:' + me, json.dumps(
                dict(chk, at=time.time(), lines=(got.get('lines') or [])[-40:])))
        return
    store.set_meta('host:osup:check:' + me, json.dumps(dict(
        chk, state=got.get('state'), at=time.time(), checked=time.time(), relook=False,
        packages=(got.get('packages') or [])[:1000], count=int(got.get('count') or 0),
        security=got.get('security'), pm=got.get('pm'), error=got.get('said') or '',
        reboot_after=bool(got.get('reboot_after')), reboot_why=(got.get('reboot_why') or [])[:20],
        reboot_now=bool(got.get('reboot_now')),
        lines=(got.get('lines') or [])[-40:])))


def _osup_follow(daemon, plan, row):
    store = daemon.store
    got = _osup_read()
    if not got or got.get('kind') != 'upgrade' or \
            float(got.get('began') or 0) < float(row.get('began') or 0) - 5:
        if time.time() - float(row.get('began') or 0) > 600:
            _osup_end(store, plan, row, False, 'the helper did not start the update')
        return
    if got.get('state') == 'running':
        if time.time() - HOST_WORK['osup_read'] > 2:
            HOST_WORK['osup_read'] = time.time()
            osup_put(store, row, pct=int(got.get('pct') or 0), phase=got.get('phase') or '',
                     lines=(got.get('lines') or [])[-300:])
        return
    row['lines'] = (got.get('lines') or [])[-300:]
    row['pct'] = 100
    _osup_end(store, plan, row, got.get('state') == 'done', got.get('said') or '',
              reboot=bool(got.get('reboot')))


def _osup_end(store, plan, row, ok, said='', reboot=False):
    me = node_name()
    by = 'upsmon (system update)'
    row.update(done_at=time.time(), reboot=reboot, rebooted=False)
    if not ok:
        osup_put(store, row, state='failed', said=said or 'it failed')
        if row.get('maint'):
            maintenance_set(store, False, '', by)
            row['maint'] = False
            osup_put(store, row)
        plan.update(state='failed', ended=time.time(), failed_on=me)
        store.set_meta('host:osup:plan', json.dumps(plan))
        store.add_event('settings', 'the update of the system failed on %s: %s' % (me, said),
                        'bad', who=by)
        return
    if reboot and plan.get('reboot') == 'auto':
        osup_put(store, row, state='rebooting', said='updated - restarting, as it needs')
        try:
            power_ask(store, 'reboot', [me], 'one', by, keep_service=True)
        except ValueError as e:
            osup_put(store, row, state='done', said='updated; the restart was not started: %s' % e)
        return
    osup_put(store, row, state='done', said='updated' + (' - it needs a restart' if reboot else ''))
    # What is waiting looked at again, not left at what was there before.
    store.set_meta(node_key('host:osup:checkwant', me),
                   json.dumps({'id': secrets.token_hex(6), 'by': by, 'at': time.time()}))
    if row.get('maint'):
        maintenance_set(store, False, '', by)
        row['maint'] = False
        osup_put(store, row)
    store.add_event('settings', 'the system of %s is updated%s' % (
        me, ' - it needs a restart' if reboot else ''), 'warn' if reboot else 'info', who=by)
    order = plan.get('order') or []
    if order and order[-1] == me:
        plan.update(state='done', ended=time.time())
        store.set_meta('host:osup:plan', json.dumps(plan))


# -- the SSH server and the notices at sign-in (1.0.163) --------------------------------------
# One wish for the whole cluster ('host:sshd:conf', with its hash); each node
# puts it in through its root helper and says what it has in a row of its own
# ('host:sshd:now:NODE'). A change is on trial on each node - its helper's
# own timer puts the one before back - until Keep it ('host:sshd:keep').
SSHD_DEFAULT = {'manage': False, 'permit_root': 'prohibit-password', 'password': True,
                'port': 22, 'allow_users': [], 'tries': 4, 'notice': '', 'notice_ssh': False,
                'notice_console': False, 'notice_motd': False, 'trial_min': 5,
                # A code from upsmon at SSH sign-in (1.0.178): pam_radius asking
                # this node's own RADIUS.
                'radius': False, 'radius_users': [], 'radius_root': False,
                'radius_fallback': True, 'radius_with_key': False}


# ======== carried over from OTP 1.0.187 (lines 29444-29522): on a schedule ========
def _due(every, day, at, now=None):
    """(due now, the id of this window) for a schedule of HH:MM on a day."""
    n = datetime.fromtimestamp(now or time.time())
    try:
        hh, mm = (int(x) for x in str(at or '04:45').split(':', 1))
    except ValueError:
        hh, mm = 4, 45
    if every == 'weekly' and n.isoweekday() != int(day or 7):
        return False, ''
    if every == 'monthly' and n.day != 1:
        return False, ''
    return (n.hour, n.minute) >= (hh, mm), n.strftime('%Y-%m-%d')


def osup_settling(store):
    """An update going on, or a node still looking (again) for updates - what
    says which node needs a restart is not known yet (1.0.168)."""
    if osup_plan(store).get('state') == 'running':
        return True
    for n in host_nodes(store):
        chk = _meta_json(store, 'host:osup:check:' + n) or {}
        if chk.get('state') == 'running':
            return True
        for r in node_key_rows(store, 'host:osup:checkwant', n):
            try:
                a = json.loads(r['v'] or '{}')
            except ValueError:
                continue
            if a.get('id') and a['id'] not in (chk.get('asked') or []) and \
                    time.time() - float(a.get('at') or 0) < 900:
                return True
    return False


def osup_sched_tick(daemon):
    store = daemon.store
    if not alerts_lead(store):
        return
    by = 'upsmon (on a schedule)'
    if CONFIG.get('osup_check'):
        due, day = _due('daily', '', CONFIG.get('osup_check_at'))
        if due and store.get_meta('osup:check:day') != day and \
                claim_once(store, 'osup:check:day', day):
            alive = [n for n, a in host_alive(store).items() if a]
            try:
                osup_check_ask(store, alive, by)
            except ValueError as e:
                log('the daily look for updates: %s' % e, 'warn')
    if CONFIG.get('osup_auto'):
        due, day = _due(CONFIG.get('osup_auto_every') or 'weekly', CONFIG.get('osup_auto_day'),
                        CONFIG.get('osup_auto_at'))
        if due and store.get_meta('osup:auto:day') != day and \
                claim_once(store, 'osup:auto:day', day):
            try:
                osup_start(store, None, CONFIG.get('osup_auto_reboot') or 'auto', by,
                           security=(CONFIG.get('osup_auto_what') or 'security') == 'security')
            except ValueError as e:
                store.add_event('settings', 'the update of the system on a schedule did not '
                                'start: %s' % e, 'bad')
    if CONFIG.get('power_auto'):
        due, day = _due(CONFIG.get('power_auto_every') or 'weekly', CONFIG.get('power_auto_day'),
                        CONFIG.get('power_auto_at'))
        # Not while an update or a look for updates is still going on: the
        # nodes that need a restart are known only after it (1.0.168).
        if due and store.get_meta('power:auto:day') != day and not osup_settling(store) and \
                claim_once(store, 'power:auto:day', day):
            nodes = host_nodes(store)
            if CONFIG.get('power_auto_needed', 1):
                nodes = [n['name'] for n in osup_view(store)['nodes'] if n.get('reboot')]
            if not nodes:
                store.add_event('settings', 'the restart on a schedule: no node needs one', 'info')
                return
            try:
                power_ask(store, 'reboot', nodes, 'rolling', by, keep_service=True)
                store.add_event('settings', 'the restart on a schedule: %s, one after the other'
                                % ', '.join(nodes), 'warn')
            except ValueError as e:
                store.add_event('settings', 'the restart on a schedule did not start: %s' % e,
                                'bad')


# ======== carried over from OTP 1.0.187 (lines 18277-20090): backups to another machine ========
# ---------------------------------------------------------------------------
# Backups to another machine (1.0.109)
# ---------------------------------------------------------------------------
# One file that brings any loss back - one server or a cluster, onto a
# machine installed from nothing: the whole database (an engine-independent
# copy: tokens, settings, accounts, certificates, the VIP address, the
# firewall, the texts, the logs), the key that opens the tokens, the machine's
# config.json and the files it names, a manifest with the checksum of each,
# and RESTORE.md - the exact steps. Locked with a password kept in the
# settings (openssl enc, AES-256-CBC, PBKDF2-SHA256: opened with upsmon, or with
# openssl alone on any machine). RESTORE.md and a .sha256 also go beside it,
# not locked, so the steps can be read before anything is opened.
#
# Where they go: a folder (an NFS or other mount), FTP, FTPS (explicit or
# implicit), SFTP, SCP or SMB, each with its name and password, SSH keys made
# here or brought, the server's host key or certificate checked, a client
# certificate for FTPS. Each node makes and sends its own (its config.json is
# its own); old ones are taken away as kept-count and age say.
RB_KINDS = ('folder', 'ftp', 'ftps', 'sftp', 'scp', 'smb')
RB_KIND_WORDS = {'folder': 'a folder', 'ftp': 'FTP', 'ftps': 'FTPS', 'sftp': 'SFTP',
                 'scp': 'SCP (ssh)', 'smb': 'SMB (Windows share, Samba)'}
RB_PORTS = {'ftp': 21, 'ftps': 21, 'sftp': 22, 'scp': 22, 'smb': 445}
RB_SEALED = ('password', 'key', 'client_key', 'key_pass')
RB_BIND = 'rbackup'
RB_LOCK = threading.Lock()
RB_JOB = {'running': False, 'what': '', 'says': '', 'done': 0, 'whole': 0, 'error': '',
          'began': 0, 'ended': 0, 'result': None, 'by': ''}
RB_ITER = 600000
RB_NAME_RE = re.compile(r'^upsmon-backup-(?P<site>[A-Za-z0-9_.-]+?)-(?P<node>[A-Za-z0-9_.-]+)-'
                        r'(?P<stamp>\d{8}-\d{6})\.tar\.gz(?P<enc>\.enc)?\Z')
RB_TIMEOUT = 60


class RbError(Exception):
    pass


def rb_clean(text, what, most=200, pattern=None, empty=True):
    t = str(text if text is not None else '').strip()
    if not t and empty:
        return ''
    if len(t) > most or re.search(r'[\x00-\x1f\x7f]', t):
        raise ValueError('%s: at most %d characters, one line' % (what, most))
    if pattern and t and not re.match(pattern, t):
        raise ValueError('%s: %r is not one' % (what, t[:60]))
    return t


def rb_slug(text):
    return re.sub(r'[^A-Za-z0-9_.]+', '_', str(text or 'upsmon')).strip('_.')[:40] or 'upsmon'


# ---- the destinations ---------------------------------------------------------------
def rb_targets(store):
    try:
        got = json.loads(store.get_meta('rbackup:targets') or '[]')
    except ValueError:
        got = []
    return [t for t in got if isinstance(t, dict) and t.get('id')]


def rb_put_targets(store, targets):
    store.set_meta('rbackup:targets', json.dumps(targets))


def rb_target(store, tid):
    return next((t for t in rb_targets(store) if t['id'] == str(tid)), None)


def rb_secret(t, k):
    v = t.get(k) or ''
    return (unseal_secret(v, bind=RB_BIND) or '') if v else ''


def ssh_fingerprints(lines):
    """The SHA256 fingerprints of known_hosts lines, as ssh-keygen says them."""
    if not lines.strip() or not shutil.which('ssh-keygen'):
        return []
    got = subprocess.run(['ssh-keygen', '-lf', '-'], input=lines, capture_output=True,
                         text=True, timeout=20)
    return [x.strip() for x in got.stdout.splitlines() if x.strip()]


def rb_view(t):
    """A destination as the pages see it: nothing secret, what it has said."""
    out = {k: v for k, v in t.items() if k not in RB_SEALED}
    for k in RB_SEALED:
        out['has_' + k] = bool(t.get(k))
    out['kind_words'] = RB_KIND_WORDS.get(t.get('kind'), t.get('kind'))
    if t.get('password'):
        out['password'] = secret_shown(rb_secret(t, 'password'), last=True)
    if t.get('hostkey'):
        out['hostkey_fp'] = ssh_fingerprints(t['hostkey'])
    if t.get('client_cert'):
        try:
            out['client_cert_info'] = cert_info(t['client_cert'])
        except Exception:                               # noqa: BLE001
            out['client_cert_info'] = None
    if t.get('ca'):
        try:
            out['ca_info'] = cert_info(t['ca'])
        except Exception:                               # noqa: BLE001
            out['ca_info'] = None
    return out


def rb_checked(data, old=None):
    """A destination as typed on the pages, checked; secrets left out or as
    dots keep what was there."""
    old = dict(old or {})
    if not isinstance(data, dict):
        raise ValueError('a destination is an object')
    kind = str(data.get('kind') or old.get('kind') or '')
    if kind not in RB_KINDS:
        raise ValueError('the kind is one of %s' % ', '.join(RB_KINDS))
    t = {'id': old.get('id') or secrets.token_hex(6), 'kind': kind}
    t['name'] = rb_clean(data.get('name'), 'the name', 60) or \
        ('%s %s' % (RB_KIND_WORDS[kind], data.get('host') or data.get('path') or '')).strip()
    t['enabled'] = 1 if data.get('enabled', old.get('enabled', 1)) else 0
    t['path'] = rb_clean(data.get('path'), 'the folder', 400)
    if kind == 'folder':
        if not t['path'].startswith('/'):
            raise ValueError('the folder is a whole path on this machine (/mnt/backup/upsmon)')
        if re.search(r'(^|/)\.\.(/|$)', t['path']):
            raise ValueError('the folder has no .. in it')
    else:
        t['host'] = rb_clean(data.get('host'), 'the server', 253,
                             r'^[A-Za-z0-9][A-Za-z0-9.:_-]*\Z', empty=False)
        try:
            port = int(data.get('port') or RB_PORTS.get(kind) or 0)
        except (TypeError, ValueError):
            raise ValueError('the port is a number')
        if kind == 'ftps' and data.get('implicit') and not data.get('port'):
            port = 990
        if not 1 <= port <= 65535:
            raise ValueError('the port is 1 to 65535')
        t['port'] = port
        t['user'] = rb_clean(data.get('user'), 'the account', 128, r'^[^\s:@/\\]+\Z') or ''
        # Nothing a tool on the way reads as more (1.0.136): smbclient takes
        # ; as the next command whatever the quotes, ssh a leading - as an
        # option of its own.
        if t['user'].startswith('-'):
            raise ValueError('the account does not begin with -')
        if re.search(r'[;"]', t['path']) or t['path'].lstrip().startswith('-'):
            raise ValueError('the folder has no ; or " in it, and does not begin with -')
        if kind != 'smb' and re.search(r'(^|/)\.\.(/|$)', t['path']):
            raise ValueError('the folder has no .. in it')
        if kind == 'scp' and re.search(r'[^A-Za-z0-9._/~+@%=,-]', t['path']):
            # scp before OpenSSH 9 hands the far path to the shell there
            # (1.0.139): $( ), `, |, & and spaces ran or broke.
            raise ValueError('the folder (SCP) is letters, digits and . _ / ~ + @ % = , - '
                             'only - use SFTP for any other')
    pw = data.get('password')
    # The saved password goes only to the server it was saved for (1.0.149):
    # with another server typed in, Try it sent it there - to whoever the
    # administrator chose. Typed again for a new one.
    moved = bool(old) and (old.get('kind') != kind or
                           str(old.get('host') or '').lower() != str(t.get('host') or '').lower() or
                           int(old.get('port') or 0) != int(t.get('port') or 0))
    if (pw is None or is_masked(pw)) and moved and old.get('password'):
        raise ValueError('the server changed: type the password again')
    if pw is None or is_masked(pw):
        t['password'] = old.get('password') or ''
    else:
        pw = str(pw)
        if len(pw) > 512 or '\n' in pw or '\x00' in pw:
            raise ValueError('the password is one line, at most 512 characters')
        t['password'] = seal_secret(pw, bind=RB_BIND) if pw else ''
    if kind in ('sftp', 'scp'):
        for k in ('key', 'pub', 'ssh_cert', 'hostkey', 'key_pass'):
            if k in old:
                t[k] = old[k]
        if data.get('ssh_cert') is not None:
            c = str(data.get('ssh_cert') or '').strip()
            if c and not re.match(r'^[a-z0-9@.-]+-cert-v01@openssh\.com AAAA[A-Za-z0-9+/=]+( .*)?\Z',
                                  c):
                raise ValueError('the SSH certificate is the one line of a ...-cert.pub file')
            t['ssh_cert'] = c
    if kind in ('ftp', 'ftps'):
        t['passive'] = 0 if data.get('passive', old.get('passive', 1)) in (0, '0', False) else 1
    if kind == 'ftps':
        t['implicit'] = 1 if data.get('implicit', old.get('implicit')) else 0
        check = str(data.get('tls_check') or old.get('tls_check') or 'system')
        if check not in ('system', 'ca', 'pin', 'none'):
            raise ValueError('the server certificate is checked against system, ca, pin or none')
        t['tls_check'] = check
        for k in ('ca', 'pin', 'client_cert', 'client_key'):
            if k in old:
                t[k] = old[k]
        if data.get('ca') is not None:
            ca = str(data.get('ca') or '').strip()
            if ca and not PEM_CERT.search(ca):
                raise ValueError('the authority is a PEM certificate (-----BEGIN CERTIFICATE-----)')
            t['ca'] = '\n'.join(m.group(0) for m in PEM_CERT.finditer(ca)) + '\n' if ca else ''
        if data.get('pin') is not None:
            pin = re.sub(r'[^0-9A-Fa-f]', '', str(data.get('pin') or '')).lower()
            if pin and len(pin) != 64:
                raise ValueError('the pinned fingerprint is SHA-256: 64 hex digits')
            t['pin'] = pin
        if check == 'ca' and not t.get('ca'):
            raise ValueError('checked against an authority: give its certificate')
        if check == 'pin' and not t.get('pin'):
            raise ValueError('pinned: the fingerprint is needed - Try it shows the server\'s')
    if kind == 'smb':
        t['share'] = rb_clean(data.get('share'), 'the share', 80, r'^[^\\/:*?"<>|;-][^\\/:*?"<>|;]*\Z',
                              empty=False)
        t['domain'] = rb_clean(data.get('domain'), 'the domain', 64, r'^[A-Za-z0-9._-]+\Z')
        t['smb_encrypt'] = 1 if data.get('smb_encrypt', old.get('smb_encrypt', 1)) else 0
        if re.search(r'(^|[\\/])\.\.([\\/]|$)', t['path']):
            raise ValueError('the folder has no .. in it')
    for k in ('last', 'made'):
        if k in old:
            t[k] = old[k]
    return t


def rb_save(store, data, by):
    with RB_LOCK:
        targets = rb_targets(store)
        old = next((x for x in targets if x['id'] == str(data.get('id') or '')), None)
        if data.get('id') and not old:
            raise ValueError('no such destination')
        t = rb_checked(data, old)
        hisec_backup_target(t)              # 1.0.168
        if old:
            targets = [t if x['id'] == t['id'] else x for x in targets]
        else:
            t['made'] = time.time()
            if len(targets) >= 20:
                raise ValueError('20 destinations at most')
            targets.append(t)
        rb_put_targets(store, targets)
    store.add_event('settings', '%s %s the backup destination %s (%s)' % (
        by, 'changed' if old else 'added', t['name'], RB_KIND_WORDS[t['kind']]), who=by)
    return t


def rb_set_fields(store, tid, by, said, **fields):
    with RB_LOCK:
        targets = rb_targets(store)
        t = next((x for x in targets if x['id'] == str(tid)), None)
        if not t:
            raise ValueError('no such destination')
        for k, v in fields.items():
            if v is None:
                t.pop(k, None)
            else:
                t[k] = v
        rb_put_targets(store, targets)
    if said:
        store.add_event('settings', '%s: the backup destination %s - %s' % (by, t['name'], said),
                        who=by)
    return t


def rb_delete(store, tid, by):
    with RB_LOCK:
        targets = rb_targets(store)
        t = next((x for x in targets if x['id'] == str(tid)), None)
        if not t:
            raise ValueError('no such destination')
        rb_put_targets(store, [x for x in targets if x['id'] != t['id']])
    store.add_event('settings', '%s took away the backup destination %s' % (by, t['name']),
                    'warn', who=by)


# ---- keys and certificates ----------------------------------------------------------
def ssh_keygen(comment):
    if not shutil.which('ssh-keygen'):
        raise ValueError('ssh-keygen is not on this machine (dnf install openssh-clients)')
    with tempfile.TemporaryDirectory(prefix='upsmon-key-') as d:
        path = os.path.join(d, 'k')
        got = subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', comment,
                              '-f', path], capture_output=True, text=True, timeout=30)
        if got.returncode != 0:
            raise ValueError('ssh-keygen: %s' % (got.stderr or got.stdout).strip()[:200])
        with open(path) as f:
            private = f.read()
        with open(path + '.pub') as f:
            public = f.read().strip()
    return private, public


def ssh_public_of(private, passphrase=''):
    """The public half of a private key given - and that it is one."""
    if not shutil.which('ssh-keygen'):
        raise ValueError('ssh-keygen is not on this machine (dnf install openssh-clients)')
    private = str(private or '').replace('\r\n', '\n').strip() + '\n'
    if 'PRIVATE KEY-----' not in private:
        raise ValueError('that is not a private key (-----BEGIN OPENSSH PRIVATE KEY----- or '
                         'another PEM private key)')
    with tempfile.TemporaryDirectory(prefix='upsmon-key-') as d:
        path = os.path.join(d, 'k')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(private)
        # The passphrase through SSH_ASKPASS, not on the command line where
        # `ps` shows it (1.0.136).
        env = dict(os.environ, DISPLAY=':0', SSH_ASKPASS_REQUIRE='force')
        if passphrase:
            ask = os.path.join(d, 'ask')
            with open(ask, 'w') as f:
                f.write('#!/bin/sh\nprintf "%s\\n" "$UPSMON_RB_SECRET"\n')
            os.chmod(ask, 0o700)
            env.update(SSH_ASKPASS=ask, UPSMON_RB_SECRET=passphrase)
            argv = ['ssh-keygen', '-y', '-f', path]
        else:
            argv = ['ssh-keygen', '-y', '-P', '', '-f', path]
        got = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=env,
                             stdin=subprocess.DEVNULL)
    if got.returncode != 0:
        said = (got.stderr or got.stdout).strip()
        if 'passphrase' in said.lower() or 'incorrect' in said.lower():
            raise ValueError('the key is locked with a passphrase: give it too')
        raise ValueError('ssh-keygen does not read it: %s' % said[:200])
    return private, got.stdout.strip()


def rb_client_cert_make(cn, days=1825):
    """A key and a self-signed client certificate for FTPS."""
    key = new_key('ec')
    with tempfile.TemporaryDirectory(prefix='upsmon-crt-') as d:
        kf = os.path.join(d, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        os.chmod(kf, 0o600)
        cn = re.sub(r'[^A-Za-z0-9.@_-]', '', str(cn or 'upsmon-backup'))[:64] or 'upsmon-backup'
        crt = _openssl(['req', '-new', '-x509', '-key', kf, '-days', str(int(days)), '-subj',
                        '/CN=' + cn, '-addext', 'extendedKeyUsage=clientAuth',
                        '-addext', 'keyUsage=critical,digitalSignature'],
                       what='the certificate').decode()
    return key, crt


def rb_client_cert_given(text, password=''):
    """A client certificate brought: PEM (certificate and key, in any order)
    or PFX (base64 of it, with its password)."""
    text = str(text or '').strip()
    if 'BEGIN' in text:
        certs = [m.group(0) for m in PEM_CERT.finditer(text)]
        m = re.search(r'-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]*)'
                      r'PRIVATE KEY-----', text)
        if not certs or not m:
            raise ValueError('a client certificate needs its certificate and its private key')
        key = m.group(0) + '\n'
        if 'ENCRYPTED' in key:
            key = _openssl(['pkey', '-passin', 'env:UPSMON_PW'], key.encode(),
                           env={'UPSMON_PW': password}, what='the key (its password)').decode()
        if _pub_of_key(key).strip() != _pub_of_cert(certs[0]).strip():
            raise ValueError('the key is not the one of this certificate')
        return key, '\n'.join(certs) + '\n'
    try:
        pfx = base64.b64decode(text, validate=False)
    except (binascii.Error, ValueError):
        raise ValueError('neither PEM nor PFX')
    with tempfile.TemporaryDirectory(prefix='upsmon-pfx-') as d:
        pf = os.path.join(d, 'c.pfx')
        with open(pf, 'wb') as f:
            f.write(pfx)
        both = ''
        for extra in ([], ['-legacy']):
            try:
                both = _openssl(['pkcs12', '-in', pf, '-nodes', '-passin', 'env:UPSMON_PW'] + extra,
                                env={'UPSMON_PW': password}, what='the PFX (its password?)').decode()
                break
            except ValueError:
                if extra:
                    raise
    return rb_client_cert_given(both)


# ---- the transports ------------------------------------------------------------------
class RbFolder(object):
    def __init__(self, t):
        self.t = t
        self.dir = t['path']

    def open(self):
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as e:
            raise RbError('the folder %s cannot be made: %s' % (self.dir, e))
        if not os.access(self.dir, os.W_OK):
            raise RbError('the upsmon account may not write into %s' % self.dir)

    def put(self, local, name):
        part = os.path.join(self.dir, '.%s.part' % name)
        shutil.copyfile(local, part)
        os.chmod(part, 0o640)
        os.replace(part, os.path.join(self.dir, name))

    def get(self, name, local):
        shutil.copyfile(os.path.join(self.dir, rb_safe_name(name)), local)

    def list(self):
        out = []
        for e in os.scandir(self.dir):
            if e.is_file() and not e.name.startswith('.'):
                st = e.stat()
                out.append({'name': e.name, 'size': st.st_size, 'mtime': st.st_mtime})
        return out

    def delete(self, name):
        os.unlink(os.path.join(self.dir, rb_safe_name(name)))

    def close(self):
        pass


def rb_safe_name(name):
    name = str(name or '')
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\Z', name):
        raise RbError('not a file name of a backup: %r' % name[:80])
    return name


class _ImplicitFTP_TLS(ftplib.FTP_TLS):
    """FTPS on its own port (990): TLS from the first byte."""
    def connect(self, host='', port=0, timeout=-999, source_address=None):
        if host:
            self.host = host
        if port > 0:
            self.port = port
        if timeout != -999:
            self.timeout = timeout
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.af = self.sock.family
        self.sock = self.context.wrap_socket(self.sock, server_hostname=self.host)
        self.file = self.sock.makefile('r', encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome


class _ReuseMixin(object):
    """The data connection resumes the control connection's TLS session:
    vsftpd, ProFTPD and FileZilla Server refuse one that does not (522)."""
    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host,
                                            session=self.sock.session)
        return conn, size


class RbFtpTls(_ReuseMixin, ftplib.FTP_TLS):
    pass


class RbFtpTlsImplicit(_ReuseMixin, _ImplicitFTP_TLS):
    pass


class RbFtp(object):
    def __init__(self, t):
        self.t = t
        self.ftp = None
        self.tmp = None
        self.seen = {}

    def _context(self):
        t = self.t
        check = t.get('tls_check') or 'system'
        if check == 'ca':
            ctx = ssl.create_default_context(cadata=t.get('ca') or '')
        elif check == 'system':
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if t.get('client_cert') and t.get('client_key'):
            self.tmp = tempfile.mkdtemp(prefix='upsmon-ftps-')
            cf, kf = os.path.join(self.tmp, 'c.pem'), os.path.join(self.tmp, 'k.pem')
            with open(cf, 'w') as f:
                f.write(t['client_cert'])
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(rb_secret(t, 'client_key'))
            ctx.load_cert_chain(cf, kf)
        return ctx

    def open(self):
        t = self.t
        try:
            if t['kind'] == 'ftps':
                cls = RbFtpTlsImplicit if t.get('implicit') else RbFtpTls
                self.ftp = cls(context=self._context(), timeout=RB_TIMEOUT)
                self.ftp.connect(t['host'], int(t['port']))
                if not t.get('implicit'):
                    self.ftp.auth()
                der = self.ftp.sock.getpeercert(True)
                fp = hashlib.sha256(der).hexdigest() if der else ''
                self.seen = {'fingerprint': fp}
                try:
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    self.seen['cert'] = cert_info(pem)
                except Exception:                       # noqa: BLE001
                    pass
                if (t.get('tls_check') == 'pin') and fp != (t.get('pin') or ''):
                    raise RbError('the server answers with another certificate than the one '
                                  'pinned (SHA-256 %s)' % fp)
            else:
                self.ftp = ftplib.FTP(timeout=RB_TIMEOUT)
                self.ftp.connect(t['host'], int(t['port']))
            self.ftp.login(t.get('user') or 'anonymous', rb_secret(t, 'password'))
            if t['kind'] == 'ftps':
                self.ftp.prot_p()
            self.ftp.set_pasv(bool(t.get('passive', 1)))
            self._cd(t.get('path') or '')
        except ssl.SSLCertVerificationError as e:
            raise RbError('the server\'s certificate is not trusted: %s - check it against '
                          'its authority, or pin it' % e.verify_message)
        except ftplib.error_perm as e:
            raise RbError('the FTP server said: %s' % str(e)[:200])
        except (OSError, EOFError, ftplib.Error) as e:
            raise RbError(str(e)[:200] or e.__class__.__name__)

    def _cd(self, path):
        if not path:
            return
        if path.startswith('/'):
            self.ftp.cwd('/')
        for part in [p for p in path.split('/') if p]:
            try:
                self.ftp.cwd(part)
            except ftplib.error_perm:
                self.ftp.mkd(part)
                self.ftp.cwd(part)

    def put(self, local, name):
        with open(local, 'rb') as f:
            self.ftp.storbinary('STOR .%s.part' % name, f, blocksize=262144)
        try:
            self.ftp.delete(name)
        except ftplib.error_perm:
            pass
        self.ftp.rename('.%s.part' % name, name)

    def get(self, name, local):
        with open(local, 'wb') as f:
            self.ftp.retrbinary('RETR %s' % rb_safe_name(name), f.write, blocksize=262144)

    def list(self):
        out = []
        try:
            for name, facts in self.ftp.mlsd(facts=['type', 'size', 'modify']):
                if facts.get('type') == 'file':
                    m = facts.get('modify') or ''
                    try:
                        mt = datetime.strptime(m[:14], '%Y%m%d%H%M%S').replace(
                            tzinfo=timezone.utc).timestamp()
                    except ValueError:
                        mt = 0
                    out.append({'name': name, 'size': int(facts.get('size') or 0), 'mtime': mt})
            return out
        except ftplib.error_perm:
            pass
        for name in self.ftp.nlst():
            name = name.rsplit('/', 1)[-1]
            if name in ('.', '..'):
                continue
            try:
                size = self.ftp.size(name) or 0
            except ftplib.error_perm:
                continue            # a folder
            out.append({'name': name, 'size': size, 'mtime': 0})
        return out

    def delete(self, name):
        self.ftp.delete(rb_safe_name(name))

    def close(self):
        try:
            if self.ftp:
                self.ftp.quit()
        except Exception:                               # noqa: BLE001
            try:
                self.ftp.close()
            except Exception:                           # noqa: BLE001
                pass
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


def ssh_keyscan(host, port):
    """The server's host keys, as known_hosts lines - and their fingerprints."""
    if not shutil.which('ssh-keyscan'):
        raise ValueError('ssh-keyscan is not on this machine (dnf install openssh-clients)')
    got = subprocess.run(['ssh-keyscan', '-T', '10', '-p', str(int(port)), host],
                         capture_output=True, text=True, timeout=30)
    lines = [x for x in got.stdout.splitlines() if x.strip() and not x.startswith('#')]
    if not lines:
        raise ValueError('%s:%s did not show a host key: %s' % (
            host, port, (got.stderr or '').strip().splitlines()[-1:] or 'no answer'))
    return '\n'.join(lines) + '\n', ssh_fingerprints('\n'.join(lines) + '\n')


class RbSsh(object):
    """SFTP (the sftp program) or SCP (scp, and ssh for the list and the
    deleting) - OpenSSH itself, the server's host key checked against the one
    trusted on the pages, a key of its own or a password."""
    def __init__(self, t):
        self.t = t
        self.d = None

    def open(self):
        t = self.t
        tools = ['ssh'] + (['sftp'] if t['kind'] == 'sftp' else ['scp'])
        for tool in tools:
            if not shutil.which(tool):
                raise RbError('%s is not on this machine (dnf install openssh-clients)' % tool)
        if not t.get('hostkey'):
            raise RbError('the server\'s host key is not trusted yet: Try it, then trust the '
                          'fingerprint it shows')
        self.d = tempfile.mkdtemp(prefix='upsmon-ssh-')
        kh = os.path.join(self.d, 'known_hosts')
        with open(kh, 'w') as f:
            f.write(t['hostkey'])
        self.opts = ['-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + kh,
                     '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=20',
                     '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4',
                     '-o', 'LogLevel=ERROR', '-o', 'IdentitiesOnly=yes', '-F', '/dev/null']
        key = rb_secret(t, 'key')
        if key:
            kf = os.path.join(self.d, 'id')
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(key if key.endswith('\n') else key + '\n')
            self.opts += ['-i', kf]
            if t.get('ssh_cert'):
                cf = os.path.join(self.d, 'id-cert.pub')
                with open(cf, 'w') as f:
                    f.write(t['ssh_cert'] + '\n')
                self.opts += ['-o', 'CertificateFile=' + cf]
        else:
            self.opts += ['-o', 'IdentityFile=/dev/null']
        # A password (or the key's passphrase) through SSH_ASKPASS: never on
        # a command line, never in a file of the upsmon account's.
        self.env = dict(os.environ, DISPLAY=':0', SSH_ASKPASS_REQUIRE='force')
        # Each prompt its own answer (1.0.139): with a password and a key that
        # has a passphrase, the password went to the key, and the key failed.
        pw = rb_secret(t, 'password') or rb_secret(t, 'key_pass')
        kp = rb_secret(t, 'key_pass') or rb_secret(t, 'password')
        ask = os.path.join(self.d, 'ask')
        with open(ask, 'w') as f:
            f.write('#!/bin/sh\ncase "$1" in\n  *assphrase*) printf "%s\\n" "$UPSMON_RB_KEYPASS";;\n'
                    '  *) printf "%s\\n" "$UPSMON_RB_SECRET";;\nesac\n')
        os.chmod(ask, 0o700)
        self.env.update(SSH_ASKPASS=ask, UPSMON_RB_SECRET=pw, UPSMON_RB_KEYPASS=kp)
        auths = ['publickey'] if key else []
        if rb_secret(t, 'password'):
            auths += ['password', 'keyboard-interactive']
        if not auths:
            raise RbError('neither a key nor a password is set')
        self.opts += ['-o', 'PreferredAuthentications=' + ','.join(auths),
                      '-o', 'NumberOfPasswordPrompts=1']
        if rb_secret(t, 'password') or rb_secret(t, 'key_pass'):
            # sftp -b asks ssh for batch mode, which takes no password; the
            # first value given wins, and this comes first.
            self.opts += ['-o', 'BatchMode=no']
        host = str(t['host']).strip('[]')
        self.dest = '%s@%s' % (t.get('user') or 'root', host)
        # scp and sftp read user@host:path - an IPv6 address in brackets
        # there (1.0.146), ssh takes it bare.
        self.rdest = '%s@[%s]' % (t.get('user') or 'root', host) if ':' in host else self.dest
        self.dir = (t.get('path') or '').rstrip('/') or '.'
        # Signed in and the folder made, at once - the errors said here.
        if t['kind'] == 'sftp':
            parts = [p for p in self.dir.split('/') if p and p != '.']
            cmds = []
            acc = '/' if self.dir.startswith('/') else ''
            for p in parts:
                acc = (acc + '/' + p) if acc not in ('', '/') else (acc + p)
                cmds.append('-mkdir "%s"' % acc)
            cmds.append('cd "%s"' % self.dir)
            self._sftp(cmds)
        else:
            self._ssh('mkdir -p -- %s && test -w %s' % (shlex_quote(self.dir),
                                                        shlex_quote(self.dir)))

    def _run(self, args, what, stdin=None, timeout=3600):
        got = subprocess.run(args, input=stdin, capture_output=True, text=True,
                             timeout=timeout, env=self.env, start_new_session=True)
        if got.returncode != 0:
            said = (got.stderr or got.stdout or '').strip().splitlines()
            said = [x for x in said if x.strip() and not x.startswith('Warning: Permanently')]
            tail = ' / '.join(said[-3:])[:300] or 'it said nothing (exit %d)' % got.returncode
            if 'Host key verification failed' in tail or 'REMOTE HOST IDENTIFICATION' in tail:
                tail = ('the server shows another host key than the one trusted - if it was '
                        'reinstalled on purpose, Try it and trust the new one')
            elif 'Permission denied' in tail:
                tail = 'the server did not let the account in (%s)' % tail
            raise RbError('%s: %s' % (what, tail))
        return got.stdout

    def _ssh(self, command):
        return self._run(['ssh'] + self.opts + ['-p', str(int(self.t['port'])), self.dest,
                                                command], 'ssh')

    def _sftp(self, cmds, timeout=3600):
        batch = os.path.join(self.d, 'batch')
        with open(batch, 'w') as f:
            f.write('\n'.join(cmds) + '\n')
        return self._run(['sftp'] + self.opts + ['-P', str(int(self.t['port'])), '-b', batch,
                                                 self.rdest], 'sftp', timeout=timeout)

    def put(self, local, name):
        name = rb_safe_name(name)
        if self.t['kind'] == 'sftp':
            self._sftp(['cd "%s"' % self.dir, 'put "%s" ".%s.part"' % (local, name),
                        '-rm "%s"' % name, 'rename ".%s.part" "%s"' % (name, name)])
        else:
            self._run(['scp'] + self.opts + ['-P', str(int(self.t['port'])), '-q', local,
                                             '%s:%s/.%s.part' % (self.rdest, self.dir, name)],
                      'scp')
            self._ssh('mv -f -- %s %s' % (shlex_quote('%s/.%s.part' % (self.dir, name)),
                                          shlex_quote('%s/%s' % (self.dir, name))))

    def get(self, name, local):
        name = rb_safe_name(name)
        if self.t['kind'] == 'sftp':
            self._sftp(['cd "%s"' % self.dir, 'get "%s" "%s"' % (name, local)])
        else:
            self._run(['scp'] + self.opts + ['-P', str(int(self.t['port'])), '-q',
                                             '%s:%s/%s' % (self.rdest, self.dir, name), local],
                      'scp')

    def list(self):
        if self.t['kind'] == 'sftp':
            text = self._sftp(['cd "%s"' % self.dir, 'ls -ln'])
        else:
            text = self._ssh('LC_ALL=C ls -ln -- %s' % shlex_quote(self.dir))
        out = []
        for line in text.splitlines():
            f = line.split(None, 8)
            if len(f) == 9 and f[0].startswith('-'):
                name = f[8].rsplit('/', 1)[-1]
                try:
                    out.append({'name': name, 'size': int(f[4]), 'mtime': 0})
                except ValueError:
                    pass
        return out

    def delete(self, name):
        name = rb_safe_name(name)
        if self.t['kind'] == 'sftp':
            self._sftp(['cd "%s"' % self.dir, 'rm "%s"' % name])
        else:
            self._ssh('rm -f -- %s' % shlex_quote('%s/%s' % (self.dir, name)))

    def close(self):
        if self.d:
            shutil.rmtree(self.d, ignore_errors=True)


class RbSmb(object):
    """SMB through smbclient: an authentication file of its own (never the
    password on a command line), SMB2 at least, SMB3 encryption when asked."""
    def __init__(self, t):
        self.t = t
        self.d = None

    def open(self):
        t = self.t
        if not shutil.which('smbclient'):
            raise RbError('smbclient is not on this machine (dnf install samba-client)')
        self.d = tempfile.mkdtemp(prefix='upsmon-smb-')
        auth = os.path.join(self.d, 'auth')
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write('username = %s\npassword = %s\n' % (t.get('user') or 'guest',
                                                       rb_secret(t, 'password')))
            if t.get('domain'):
                f.write('domain = %s\n' % t['domain'])
        self.args = ['smbclient', '//%s/%s' % (t['host'], t['share']), '-A', auth,
                     '-p', str(int(t['port'])), '--option=client min protocol=SMB2',
                     '-t', str(RB_TIMEOUT)]
        if t.get('smb_encrypt'):
            self.args += ['--client-protection=encrypt']
        self.dir = (t.get('path') or '').replace('/', '\\').strip('\\')
        cmds = []
        acc = ''
        for p in [x for x in self.dir.split('\\') if x]:
            acc = (acc + '\\' + p) if acc else p
            cmds.append('mkdir "%s"' % acc)
        self._run(cmds + ['cd "\\%s"' % self.dir, 'ls'], ignore=('NT_STATUS_OBJECT_NAME_COLLISION',))

    def _run(self, cmds, ignore=(), timeout=3600):
        got = subprocess.run(self.args + ['-c', '; '.join(cmds)], capture_output=True, text=True,
                             timeout=timeout, cwd=self.d, start_new_session=True)
        text = (got.stdout or '') + (got.stderr or '')
        bad = [x for x in text.splitlines() if 'NT_STATUS_' in x and
               not any(i in x for i in ignore)]
        if got.returncode != 0 or bad:
            said = ' / '.join((bad or text.strip().splitlines() or ['no answer'])[-2:])[:300]
            if 'NT_STATUS_LOGON_FAILURE' in said:
                said = 'the server did not take the account and password (%s)' % said
            elif 'NT_STATUS_BAD_NETWORK_NAME' in said:
                said = 'there is no share %s on %s' % (self.t['share'], self.t['host'])
            elif 'protection' in said.lower() and 'unknown' in said.lower():
                said = ('this smbclient does not know --client-protection: switch "SMB3 '
                        'encryption required" off or install a newer samba-client')
            raise RbError('smbclient: %s' % said)
        return got.stdout or ''

    def _cd(self):
        return 'cd "\\%s"' % self.dir

    def put(self, local, name):
        name = rb_safe_name(name)
        self._run([self._cd(), 'put "%s" ".%s.part"' % (local, name), 'del "%s"' % name,
                   'rename ".%s.part" "%s"' % (name, name)], ignore=('NT_STATUS_NO_SUCH_FILE',
                                                                   'NT_STATUS_OBJECT_NAME_NOT_FOUND'))

    def get(self, name, local):
        self._run([self._cd(), 'get "%s" "%s"' % (rb_safe_name(name), local)])

    def list(self):
        out = []
        for line in self._run([self._cd(), 'ls']).splitlines():
            m = re.match(r'^\s\s(.+?)\s+([ADHNRS]*)\s+(\d+)\s+(\w{3} \w{3}\s+\d+ [\d:]+ \d{4})\s*$',
                         line)
            if m and 'D' not in m.group(2) and m.group(1) not in ('.', '..'):
                try:
                    mt = datetime.strptime(re.sub(r'\s+', ' ', m.group(4)),
                                           '%a %b %d %H:%M:%S %Y').timestamp()
                except ValueError:
                    mt = 0
                out.append({'name': m.group(1), 'size': int(m.group(3)), 'mtime': mt})
        return out

    def delete(self, name):
        self._run([self._cd(), 'del "%s"' % rb_safe_name(name)])

    def close(self):
        if self.d:
            shutil.rmtree(self.d, ignore_errors=True)


def rb_said(e):
    """An error in words, whatever library raised it."""
    if isinstance(e, EOFError):
        return 'the server closed the connection'
    if isinstance(e, socket.timeout):
        return 'the server did not answer in time'
    if isinstance(e, ssl.SSLCertVerificationError):
        return ('the server\'s certificate is not trusted: %s - check it against its authority, '
                'or pin it' % e.verify_message)
    if isinstance(e, ftplib.Error):
        return 'the FTP server said: %s' % str(e)[:300]
    return scrub_secret(str(e) or e.__class__.__name__)[:400]


def rb_transport(t):
    return {'folder': RbFolder, 'ftp': RbFtp, 'ftps': RbFtp, 'sftp': RbSsh, 'scp': RbSsh,
            'smb': RbSmb}[t['kind']](t)


def rb_try(t):
    """Signed in, a small file written, seen in the list, taken away again."""
    out = {'ok': False, 'steps': []}
    began = time.time()
    tr = rb_transport(t)
    try:
        tr.open()
        out['steps'].append('signed in, the folder is there')
        if getattr(tr, 'seen', None):
            out['server_cert'] = tr.seen
        name = 'upsmon-try-%s-%s.txt' % (rb_slug(node_name()), secrets.token_hex(4))
        with tempfile.NamedTemporaryFile('w', prefix='upsmon-try-', delete=False) as f:
            f.write('upsmon %s on %s tried this destination at %s - this file is taken away again\n'
                    % (__version__, node_name(), datetime.now().isoformat(timespec='seconds')))
            local = f.name
        try:
            tr.put(local, name)
        finally:
            os.unlink(local)
        out['steps'].append('a file written')
        names = [x['name'] for x in tr.list()]
        if name not in names:
            raise RbError('the file written is not in the list the server gives')
        out['steps'].append('it is in the list (%d file(s) there)' % len(names))
        tr.delete(name)
        out['steps'].append('taken away again')
        out['ok'] = True
    except Exception as e:                              # noqa: BLE001
        out['error'] = rb_said(e)
        if getattr(tr, 'seen', None):
            out['server_cert'] = tr.seen
    finally:
        tr.close()
    out['secs'] = round(time.time() - began, 1)
    return out


# ---- the backup itself -----------------------------------------------------------------
def rb_password():
    # Sealed in config.json like the other passwords: until 1.0.139 the sealed
    # text itself locked the backups - not the password typed, so a new
    # machine could not open them.
    pw = str(CONFIG.get('rbackup_password') or '')
    return (unseal_secret(pw) or '') if pw else ''


def rb_password_old():
    """What locked the backups made here before 1.0.139: the sealed text."""
    pw = str(CONFIG.get('rbackup_password') or '')
    return pw if pw.startswith((SEALED, SEALED2)) else ''


def rb_files_named():
    """Files config.json names that live outside the database: the
    authority of a database on another machine."""
    out = []
    for k in ('db_tls_ca',):
        p = str(CONFIG.get(k) or '')
        if p and os.path.isfile(p):
            out.append(p)
    return out


def rb_restore_md(m):
    """RESTORE.md: the exact steps, filled in with what this backup is."""
    enc = m.get('encrypted')
    name = m['file']
    tar = name[:-4] if enc else name
    site, node, ver = m.get('site') or 'upsmon', m.get('node') or '?', m.get('upsmon') or '?'
    lines = [
        '# Restoring upsmon from %s' % name, '',
        '| | |', '|---|---|',
        '| Made | %s |' % m.get('made_words'),
        '| Installation | %s |' % site,
        '| Server | %s (%s) |' % (node, m.get('host') or ''),
        '| upsmon | %s |' % ver,
        '| Locked | %s |' % ('yes - AES-256-CBC, PBKDF2-SHA256, %d rounds (openssl enc)'
                             % RB_ITER if enc else '**no** - anybody with the file has the accounts '
                             'and the secrets: keep it as you would the server'),
        '', 'Everything is in it: both databases - `history.db` (the UPS, the plug and the sensors:',
        'samples, events, power failures, tests) and `upsmon.db` (the accounts of Settings, the',
        'settings of the pages, the certificates and their keys, the events) - the key that opens',
        'the sealed secrets (`secrets.key`) and `/etc/upsmon/config.json`.', '',
        'Keep the password of the backups apart from the backups (a password vault): without it',
        'the file cannot be opened - by anybody.', '',
        '## 0. Check the file', '', '```bash',
        'sha256sum -c %s.sha256          # "%s: OK"' % (name, name), '```', '',
    ]
    if enc:
        lines += ['## 1. Open it', '',
                  'upsmon opens it by itself (step 3). With openssl alone, on any machine:', '',
                  '```bash',
                  'openssl enc -d -aes-256-cbc -pbkdf2 -iter %d -md sha256 -in %s -out %s'
                  % (RB_ITER, name, tar),
                  '# it asks for the password of the backups',
                  'tar tzf %s                    # what is inside' % tar, '```', '']
    else:
        lines += ['## 1. It is not locked', '', '```bash', 'tar tzf %s' % tar, '```', '']
    lines += [
        'Inside: `upsmon-copy.tar.gz` (both databases, `config.json` and what made it),',
        '`secrets.key`, `config.json`, `manifest.json` (a checksum of each file) and this file.', '',
        '## 2. A machine to put it on', '',
        'AlmaLinux / Rocky / RHEL 9 (or the machine it came from). Install upsmon **%s or newer**' % ver,
        'from its package - the same way as the first time:', '', '```bash',
        'tar xzf upsmon-%s.tar.gz && cd upsmon-%s' % (ver, ver),
        './install.sh --nut-host <the NAS>',
        '```', '',
        '## 3. Put it back', '',
        'On the pages: *Settings → Backups → Put a backup back*, the file and the password. Or by',
        'hand, as root:', '', '```bash',
        'mkdir /root/r && cd /root/r',
        'openssl enc -d -aes-256-cbc -pbkdf2 -iter %d -md sha256 -in %s -out b.tar.gz' % (RB_ITER, name)
        if enc else 'cp %s b.tar.gz' % name,
        'tar xzf b.tar.gz && cd */ && tar xzf upsmon-copy.tar.gz',
        'systemctl stop upsmon',
        'install -o upsmon -g upsmon -m 640 upsmon.db history.db /var/lib/upsmon/',
        'install -o upsmon -g upsmon -m 600 secrets.key /var/lib/upsmon/',
        'rm -f /var/lib/upsmon/*.db-wal /var/lib/upsmon/*.db-shm',
        'install -o root -g upsmon -m 640 config.json /etc/upsmon/   # if this machine has none',
        'systemctl start upsmon', '```', '',
        'The certificate of the pages comes back with `upsmon.db`: the service gives it to nginx',
        'within seconds of its start.', '']
    return '\n'.join(lines)


def rb_manifest(store, base, tokens='?'):
    """What a backup made now is: the head of its manifest and of RESTORE.md."""
    pw = rb_password()
    m = {'upsmon': __version__, 'made': time.time(),
         'made_words': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z').strip(),
         'site': CONFIG.get('site_name') or 'upsmon', 'node': node_name(),
         'host': socket.getfqdn(), 'engine': store.db.engine,
         'engine_words': ENGINE_WORDS.get(store.db.engine, store.db.engine),
         'ha_mode': CONFIG.get('ha_mode') or '', 'ha_slot': CONFIG.get('ha_slot'),
         'ha_peer': CONFIG.get('ha_peer') or '', 'tokens': tokens,
         'encrypted': bool(pw), 'iter': RB_ITER if pw else 0,
         'file': base + ('.tar.gz.enc' if pw else '.tar.gz'), 'files': {}}
    return m


def rb_restore_guide(store):
    """RESTORE.md as a backup made now would carry it (1.0.110) - for reading
    on the pages before anything is lost. No secret is in it."""
    site = rb_slug(CONFIG.get('site_name') or 'upsmon')
    node = rb_slug(node_name())
    try:
        tokens = int(store.db.value('SELECT COUNT(*) FROM tokens') or 0)
    except Exception:                                   # noqa: BLE001
        tokens = '?'
    base = 'upsmon-backup-%s-%s-%s' % (site, node, datetime.now().strftime('%Y%m%d-%H%M%S'))
    m = rb_manifest(store, base, tokens)
    return {'md': rb_restore_md(m), 'name': 'RESTORE-%s-%s.md' % (site, node),
            'file': m['file']}


def rb_build(store, work, progress=None):
    """The backup, built in `work`: (path of the file to send, its name,
    manifest, RESTORE.md text)."""
    def say(n, t):
        if progress:
            progress(n, 6, t)
    stamp_ = datetime.now().strftime('%Y%m%d-%H%M%S')
    site = rb_slug(CONFIG.get('site_name') or 'upsmon')
    node = rb_slug(node_name())
    base = 'upsmon-backup-%s-%s-%s' % (site, node, stamp_)
    inner = os.path.join(work, 'in')
    os.makedirs(inner, mode=0o700)
    say(1, 'both databases are copied')
    os.replace(str(make_copy(store, 'backup', folder=work)), os.path.join(inner, 'upsmon-copy.tar.gz'))
    key = sealing_key()
    if not key:
        raise RbError('this machine has no key that opens the tokens - nothing worth sending')
    with open(os.path.join(inner, 'secrets.key'), 'w') as f:
        f.write(key.hex() + '\n')
    try:
        shutil.copyfile(str(CONFIG_FILE), os.path.join(inner, 'config.json'))
    except OSError as e:
        raise RbError('%s cannot be read: %s' % (CONFIG_FILE, e))
    extra = rb_files_named()
    if extra:
        os.makedirs(os.path.join(inner, 'files'))
        for p in extra:
            shutil.copyfile(p, os.path.join(inner, 'files', os.path.basename(p)))
    say(2, 'what is in it is counted')
    try:
        tokens = int(store.db.value('SELECT COUNT(*) FROM tokens') or 0)
    except Exception:                                   # noqa: BLE001
        tokens = '?'
    pw = rb_password()
    m = rb_manifest(store, base, tokens)
    for root, _dirs, files in os.walk(inner):
        for n in sorted(files):
            p = os.path.join(root, n)
            h = hashlib.sha256()
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            m['files'][os.path.relpath(p, inner)] = {'sha256': h.hexdigest(),
                                                    'bytes': os.path.getsize(p)}
    md = rb_restore_md(m)
    with open(os.path.join(inner, 'RESTORE.md'), 'w') as f:
        f.write(md)
    with open(os.path.join(inner, 'manifest.json'), 'w') as f:
        json.dump(m, f, indent=2, default=str)
    say(3, 'packed')
    tar = os.path.join(work, base + '.tar.gz')
    with tarfile.open(tar, 'w:gz', compresslevel=6) as tf:
        for n in sorted(os.listdir(inner)):
            tf.add(os.path.join(inner, n), arcname='%s/%s' % (base, n))
    shutil.rmtree(inner, ignore_errors=True)
    out = tar
    if pw:
        say(4, 'locked with the password of the backups')
        out = tar + '.enc'
        _openssl(['enc', '-aes-256-cbc', '-pbkdf2', '-iter', str(RB_ITER), '-md', 'sha256',
                  '-salt', '-in', tar, '-out', out, '-pass', 'env:UPSMON_RB_PASS'],
                 env={'UPSMON_RB_PASS': pw}, what='locking it')
        os.unlink(tar)
    h = hashlib.sha256()
    with open(out, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    m['sha256'] = h.hexdigest()
    m['bytes'] = os.path.getsize(out)
    with open(os.path.join(work, m['file'] + '.sha256'), 'w') as f:
        f.write('%s  %s\n' % (m['sha256'], m['file']))
    with open(os.path.join(work, base + '-RESTORE.md'), 'w') as f:
        f.write(md)
    return out, m, md


def rb_companions(name):
    m = RB_NAME_RE.match(name)
    if not m:
        return []
    base = name.split('.tar.gz')[0]
    return [name + '.sha256', base + '-RESTORE.md']


def rb_retain(tr, keep, days, now=None):
    """This node's backups at a destination beyond what is kept, taken away -
    never the newest."""
    now = now or time.time()
    mine = rb_slug(node_name())
    files = tr.list()
    names = set(x['name'] for x in files)
    ours = []
    for x in files:
        m = RB_NAME_RE.match(x['name'])
        if m and m.group('node') == mine and m.group('site') == rb_slug(
                CONFIG.get('site_name') or 'upsmon'):
            try:
                when = datetime.strptime(m.group('stamp'), '%Y%m%d-%H%M%S').timestamp()
            except ValueError:
                continue
            ours.append((when, x['name']))
    ours.sort(reverse=True)
    gone = []
    for i, (when, name) in enumerate(ours):
        if i == 0:
            continue
        if (keep and i >= keep) or (days and now - when > days * 86400):
            for n in [name] + [c for c in rb_companions(name) if c in names]:
                try:
                    tr.delete(n)
                except Exception:                       # noqa: BLE001
                    pass
            gone.append(name)
    return gone


def rb_run(store, by, only=None, progress=None):
    """Made once, sent to every destination switched on (or the ones asked):
    the result of each, kept in the history."""
    targets = [t for t in rb_targets(store)
               if (only and t['id'] in only) or (not only and t.get('enabled'))]
    if not targets:
        raise RbError('no destination is switched on')
    # Never sent unlocked (1.0.136): it holds the key every token is sealed
    # with, the whole database and config.json - whoever reads the share
    # could unseal every token.
    if not rb_password():
        raise RbError('the backups have no password: set one (Settings - Backups - '
                      'Backups to other machines) - unlocked, a copy would hand the key of '
                      'every token to whoever can read the destination')
    work = tempfile.mkdtemp(prefix='upsmon-rbackup-', dir=str(STATE_DIR))
    os.chmod(work, 0o700)
    began = time.time()
    run = {'at': began, 'by': by, 'node': node_name(), 'targets': [], 'ok': False}
    try:
        path, m, _md = rb_build(store, work, progress)
        run.update(file=m['file'], bytes=m['bytes'], encrypted=m['encrypted'],
                   tokens=m['tokens'])
        sha = os.path.join(work, m['file'] + '.sha256')
        md = os.path.join(work, m['file'].split('.tar.gz')[0] + '-RESTORE.md')
        for i, t in enumerate(targets):
            if progress:
                progress(5, 6, 'sent to %s (%d of %d)' % (t['name'], i + 1, len(targets)))
            one = {'id': t['id'], 'name': t['name'], 'kind': t['kind'], 'ok': False}
            t0 = time.time()
            tr = rb_transport(t)
            try:
                tr.open()
                tr.put(path, m['file'])
                tr.put(sha, os.path.basename(sha))
                tr.put(md, os.path.basename(md))
                got = {x['name']: x['size'] for x in tr.list()}
                if got.get(m['file']) not in (None, m['bytes']):
                    raise RbError('the server holds %s bytes of it, not %s' % (
                        got.get(m['file']), m['bytes']))
                one['ok'] = True
                try:
                    one['taken_away'] = rb_retain(tr, int(CONFIG.get('rbackup_keep') or 0),
                                                  int(CONFIG.get('rbackup_keep_days') or 0))
                except Exception as e:                  # noqa: BLE001
                    one['retain_error'] = str(e)[:200]
            except Exception as e:                      # noqa: BLE001
                one['error'] = rb_said(e)
            finally:
                tr.close()
            one['secs'] = round(time.time() - t0, 1)
            run['targets'].append(one)
            rb_set_fields(store, t['id'], '', '', last={
                'at': time.time(), 'ok': one['ok'], 'error': one.get('error') or '',
                'file': m['file'], 'bytes': m['bytes']})
        run['ok'] = all(x['ok'] for x in run['targets'])
    except (RbError, OSError, ValueError, subprocess.SubprocessError) as e:
        run['error'] = scrub_secret(str(e))[:400]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    run['secs'] = round(time.time() - began, 1)
    rb_history_add(store, run)
    good = [x['name'] for x in run['targets'] if x['ok']]
    bad = ['%s (%s)' % (x['name'], x.get('error')) for x in run['targets'] if not x['ok']]
    store.add_event('backups', 'a backup of %s (%s) %s%s%s' % (
        node_name(), human_bytes(run.get('bytes') or 0), ('went to ' + ', '.join(good))
        if good else 'went nowhere', ('; not to ' + '; '.join(bad)) if bad else '',
        ('; ' + run['error']) if run.get('error') else ''),
        'info' if run['ok'] else 'bad', who=by)
    log('remote backup: %s' % ('sent to ' + ', '.join(good) if good else 'not sent')
        + (' - failed: ' + '; '.join(bad) if bad else '')
        + (' - ' + run['error'] if run.get('error') else ''), 'info' if run['ok'] else 'warn')
    return run


def human_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'kB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.1f %s' % (n, unit))
        n /= 1024.0
    return '%d B' % n


def rb_history(store):
    try:
        got = json.loads(store.get_meta('rbackup:runs') or '[]')
    except ValueError:
        got = []
    return [x for x in got if isinstance(x, dict)]


def rb_history_forget(store, at=None, file=None):
    """One line off the list (at and file), or all of it (1.0.110). The
    backups themselves stay where they went."""
    with RB_LOCK:
        runs = rb_history(store)
        if at is None:
            left = []
        else:
            left = [r for r in runs if not (abs(float(r.get('at') or 0) - float(at)) < 0.001 and
                                           str(r.get('file') or '') == str(file or ''))]
        store.set_meta('rbackup:runs', json.dumps(left, default=str))
        return len(runs) - len(left)


def rb_history_add(store, run):
    with RB_LOCK:
        runs = [run] + rb_history(store)
        store.set_meta('rbackup:runs', json.dumps(runs[:60], default=str))


def rb_job_start(store, by, only=None):
    """In a thread of its own; the page follows RB_JOB."""
    with RB_LOCK:
        if RB_JOB['running']:
            raise ValueError('a backup is being made already')
        RB_JOB.update(running=True, what='backup', says='starting', done=0, whole=6, error='',
                      began=time.time(), ended=0, result=None, by=by)

    def progress(done, whole, says):
        RB_JOB.update(done=done, whole=whole, says=says)

    def work():
        try:
            RB_JOB['result'] = rb_run(store, by, only, progress)
            if RB_JOB['result'].get('error'):
                RB_JOB['error'] = RB_JOB['result']['error']
            elif RB_JOB['result'].get('ok') and CONFIG.get('rbackup_verify') == 'after':
                # Tried at once, at the first destination it went to (1.0.169).
                RB_JOB.update(what='verify', says='the backup just sent is tried', done=0, whole=4)
                sent = RB_JOB['result']
                v = rb_verify(store, by, sent['targets'][0]['id'], sent.get('file'), progress)
                sent['verified'] = v
                if not v['ok']:
                    RB_JOB['error'] = 'sent, but it is not good: ' + '; '.join(
                        c['what'] for c in v['checks'] if not c['ok'])
        except Exception as e:                          # noqa: BLE001
            RB_JOB['error'] = scrub_secret(str(e))[:400]
            log('remote backup failed: %s' % e, 'error')
        finally:
            RB_JOB.update(running=False, ended=time.time())
    threading.Thread(target=work, name='rbackup', daemon=True).start()
    return dict(RB_JOB)


def rb_due(store, last_day):
    """Whether the scheduled backup is due now; the day it is for."""
    if not CONFIG.get('rbackup'):
        return None
    try:
        hh, mm = (int(x) for x in str(CONFIG.get('rbackup_at') or '04:00').split(':', 1))
    except ValueError:
        hh, mm = 4, 0
    now = datetime.now()
    if (now.hour, now.minute) < (hh, mm):
        return None
    if str(CONFIG.get('rbackup_every') or 'daily') == 'weekly' and \
            now.isoweekday() != int(CONFIG.get('rbackup_day') or 7):
        return None
    today = now.strftime('%Y-%m-%d')
    return today if today != last_day else None


RB_NOW_LIVE_S = 900


def rb_now_ask_others(store, by):
    """Back up now on the other nodes too (1.0.149), as the schedule does: each
    node makes its own. Asked in a row of the asking node's own per node
    asked - 'rbackup:now:NODE@@ASKER' - so only one node ever writes it."""
    if not CONFIG.get('ha_mode'):
        return []
    asked = []
    ident = secrets.token_hex(6)
    for n in ha_nodes(store):
        if n.get('me') or not n.get('alive'):
            continue
        store.set_meta(node_key('rbackup:now', n['name']),
                       json.dumps({'id': ident, 'at': time.time(), 'by': by,
                                   'from': node_name()}))
        asked.append(n['name'])
    return asked


def rb_now_asked(daemon):
    """A Back up now asked of this node by another; started once each."""
    store = daemon.store
    done_k = 'rbackup:nowdone:' + node_name()
    try:
        done = set(json.loads(store.get_meta(done_k) or '[]'))
    except ValueError:
        done = set()
    for r in node_key_rows(store, 'rbackup:now', node_name()):
        try:
            ask = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        ident = str(ask.get('id') or '')
        if not ident or ident in done or time.time() - float(ask.get('at') or 0) > RB_NOW_LIVE_S:
            continue
        if RB_JOB['running']:
            return                      # asked again at the next tick
        store.set_meta(done_k, json.dumps(sorted(done | {ident})[-20:]))
        rb_job_start(store, '%s (Back up now on %s)' % (ask.get('by') or 'upsmon',
                                                        ask.get('from') or '?'))
        return


def rb_tick(daemon):
    """Once a minute from the daemon's loop: the scheduled backup, this node's."""
    store = daemon.store
    if CONFIG.get('ha_mode'):
        try:
            rb_now_asked(daemon)
        except Exception as e:                          # noqa: BLE001
            log_sparing('rb-now:' + str(e)[:60], 'Back up now asked by the other node: %s'
                        % e, 'warn', 600)
    if not RB_JOB['running'] and rb_verify_due(store) and \
            time.time() - float(getattr(daemon, '_rb_verify_at', 0)) > 3600:
        daemon._rb_verify_at = time.time()          # once an hour at most, if it fails to start
        try:
            rb_verify_start(store, 'upsmon (weekly)')
        except ValueError:
            pass
    day = rb_due(store, getattr(daemon, '_rb_day', ''))
    if not day or RB_JOB['running']:
        return
    # Marked done only once the database said whether it is this run's
    # (1.0.146): the database away just then left the day without a backup.
    claimed = claim_once(store, 'rbackup_day:' + node_name(), day)
    daemon._rb_day = day
    if not claimed:
        return
    if not any(t.get('enabled') for t in rb_targets(store)):
        return
    rb_job_start(store, 'upsmon (scheduled)')


# ---- putting one back -----------------------------------------------------------------
def rb_open(path, password, work):
    """A backup file opened into `work`: its folder and its manifest - every
    file checked against the checksum the manifest has."""
    src = path
    with open(path, 'rb') as f:
        head = f.read(8)
    if head.startswith(b'Salted__'):
        if not password:
            raise RbError('the backup is locked: its password is needed')
        src = os.path.join(work, 'b.tar.gz')
        tries = [password]
        if password == rb_password() and rb_password_old():
            tries.append(rb_password_old())             # made here before 1.0.139
        for n, pw in enumerate(tries):
            try:
                _openssl(['enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', str(RB_ITER), '-md',
                          'sha256', '-in', path, '-out', src, '-pass', 'env:UPSMON_RB_PASS'],
                         env={'UPSMON_RB_PASS': pw}, what='opening it')
                break
            except ValueError:
                if n == len(tries) - 1:
                    raise RbError('the password does not open it (or the file is damaged)')
    elif not head.startswith(b'\x1f\x8b'):
        raise RbError('that is not a backup of upsmon (neither locked nor a .tar.gz)')
    elif password:
        # Backups are always locked: an unlocked one where a password is in
        # play was put there by somebody else - its database, its accounts,
        # its key (1.0.139).
        raise RbError('the backup is not locked, and backups of upsmon always are - it was not '
                      'made by upsmon; not put in')
    out = os.path.join(work, 'x')
    os.makedirs(out, mode=0o700)
    with tarfile.open(src, 'r:gz') as tf:
        members = tf.getmembers()
        tops = set()
        for mb in members:
            parts = mb.name.split('/')
            if mb.name.startswith('/') or '..' in parts or not (mb.isfile() or mb.isdir()):
                raise RbError('the archive has a file it may not have: %r' % mb.name[:100])
            tops.add(parts[0])
        if len(tops) != 1:
            raise RbError('the archive is not one backup')
        # Unpacked only when it fits (1.0.136): a small file that unpacks to
        # more than the disk has would fill /var/lib/upsmon, the database's too.
        total = sum(mb.size for mb in members if mb.isfile())
        try:
            free = shutil.disk_usage(work).free
        except OSError:
            free = None
        if free is not None and total > free - 512 * 1024 * 1024:
            raise RbError('unpacked it is %s, more than there is room for here (%s free)'
                          % (human_bytes(total), human_bytes(max(0, free))))
        for mb in members:
            if mb.isfile():
                dst = os.path.join(out, *mb.name.split('/'))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with tf.extractfile(mb) as s, open(dst, 'wb') as d:
                    shutil.copyfileobj(s, d)
    top = os.path.join(out, tops.pop())
    try:
        with open(os.path.join(top, 'manifest.json')) as f:
            m = json.load(f)
    except (OSError, ValueError):
        raise RbError('there is no manifest in it')
    for rel, want in (m.get('files') or {}).items():
        p = os.path.join(top, *rel.split('/'))
        h = hashlib.sha256()
        try:
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
        except OSError:
            raise RbError('%s is missing from it' % rel)
        if h.hexdigest() != want.get('sha256'):
            raise RbError('%s is damaged (its checksum is not the one in the manifest)' % rel)
    return top, m


def rb_restore(store, path, password, by, keep_node_name=False, need_admin=True):
    """Everything in a backup put back on this machine: the database, the key
    of the tokens, the node's name. The connection to the database in
    config.json stays this machine's."""
    work = tempfile.mkdtemp(prefix='upsmon-putback-', dir=str(STATE_DIR))
    os.chmod(work, 0o700)
    try:
        top, m = rb_open(path, password, work)
        got = db_file_restore(store, os.path.join(top, 'upsmon-copy.tar.gz'), by,
                              key_file=os.path.join(top, 'secrets.key'),
                              from_name=os.path.basename(str(path)), need_admin=need_admin)
        said = [got.get('key') or '']
        old_name = node_name()
        if False:
            write_file_settings({'node_name': m['node']})
            CONFIG['node_name'] = m['node']
            try:
                node_carry(store, old_name, m['node'], by=by)
            except Exception:                           # noqa: BLE001
                pass
            said.append('this machine is node %s again (it was %s)' % (m['node'], old_name))
        store.add_event('backups', '%s put back the backup %s (made %s on %s, upsmon %s)' % (
            by, os.path.basename(str(path)), m.get('made_words'), m.get('node'), m.get('upsmon')),
            'warn', who=by)
        return {'manifest': m, 'safety': got.get('safety'), 'said': [x for x in said if x]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def rb_fetch(store, tid, name, dst):
    t = rb_target(store, tid)
    if not t:
        raise ValueError('no such destination')
    if not RB_NAME_RE.match(str(name or '')):
        raise ValueError('not a backup of upsmon: %r' % str(name)[:80])
    tr = rb_transport(t)
    try:
        tr.open()
        tr.get(name, dst)
    finally:
        tr.close()


def rb_remote_list(store, tid):
    t = rb_target(store, tid)
    if not t:
        raise ValueError('no such destination')
    tr = rb_transport(t)
    try:
        tr.open()
        files = tr.list()
    finally:
        tr.close()
    names = set(x['name'] for x in files)
    out = []
    for x in files:
        m = RB_NAME_RE.match(x['name'])
        if not m:
            continue
        try:
            when = datetime.strptime(m.group('stamp'), '%Y%m%d-%H%M%S').timestamp()
        except ValueError:
            when = x.get('mtime') or 0
        out.append({'name': x['name'], 'bytes': x['size'], 'when': when,
                    'node': m.group('node'), 'site': m.group('site'),
                    'encrypted': bool(m.group('enc')),
                    'mine': m.group('node') == rb_slug(node_name()),
                    'sha256': (x['name'] + '.sha256') in names})
    out.sort(key=lambda x: -x['when'])
    return out



# ---- a backup tried, without putting it back (1.0.169) ---------------------------------
# Settings → Backups → Try a backup: the newest backup of this node at a
# destination fetched into a folder of its own, opened with the password of
# the backups, every file checked against its manifest, the copy of the
# database read to its last line and counted, the key in it checked against
# the tokens in it (each token's key must open with it), config.json read -
# what a restore needs, done without touching the database in use. The
# newest nightly copy on this machine is read through as well. By hand, after
# every backup, or weekly (rbackup_verify); in a thread of its own, the
# result kept per node ('rbackup:verified:NODE') and alerted when it failed.
RB_VERIFY_KEEP = 30


def _seal_tag_ok(key, value, bind):
    """Whether `key` is the one `value` was sealed with - its tag checked, the
    secret itself never opened."""
    if not isinstance(value, str) or not value:
        return None
    if value.startswith(SEALED2):
        v2, prefix = True, SEALED2
    elif value.startswith(SEALED):
        v2, prefix = False, SEALED
    else:
        return None
    try:
        raw = base64.urlsafe_b64decode(value[len(prefix):].encode('ascii'))
    except (ValueError, TypeError):
        return False
    if len(raw) < 32:
        return False
    nonce, body, tag = raw[:16], raw[16:-16], raw[-16:]
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    signed = (b'2|' + str(bind).encode('utf-8') + b'|' if v2 else b'') + nonce + body
    return hmac.compare_digest(tag, hmac.new(sign, signed, hashlib.sha256).digest()[:16])


def copy_read_through(path, key=None, sample=50, child=False):
    """A copy of the database read to its last line: what it holds, and - with
    a key - how many tokens of a sample open with it. In the daemon by `upsmon
    --read-copy`, a process of its own (1.0.186): a big copy read line by line
    is minutes of Python, which held its one lock against RADIUS."""
    if not child and DAEMON_DB[0] is not None:
        r = subprocess.run([sys.executable, '-I', os.path.abspath(__file__), '--read-copy',
                            str(path)], input=(key.hex() if key else '') + '\n',
                           capture_output=True, text=True, timeout=6 * 3600)
        try:
            got = json.loads(r.stdout.strip().split('\n')[-1])
        except (ValueError, IndexError):
            raise RbError('the copy could not be read: %s' % (r.stderr or r.stdout).strip()[-300:])
        if got.get('error'):
            raise RbError(got['error'])
        return got
    import gzip
    counts, table, admins = {}, None, 0
    tried = opened = 0
    with gzip.open(str(path), 'rt', encoding='utf-8') as f:
        head = json.loads(f.readline() or '{}')
        if 'upsmon' not in head and 'opt' not in head:
            raise RbError('the copy of the database is not one made by upsmon')
        for line in f:
            got = json.loads(line)
            if set(got.keys()) == {'table'}:
                table = got['table']
                counts.setdefault(table, 0)
                continue
            if not table:
                continue
            counts[table] += 1
            if table == 'accounts' and got.get('role') == 'fulladmin' and not got.get('disabled'):
                admins += 1
            if table == 'tokens' and key and tried < sample and got.get('secret'):
                ok = _seal_tag_ok(key, got['secret'], token_bind(got.get('name')))
                if ok is not None:
                    tried += 1
                    opened += 1 if ok else 0
    return {'head': head, 'counts': counts, 'admins': admins, 'tried': tried, 'opened': opened}


def rb_verify_file(path, password, work, made_here=True):
    """The checks on one backup file: [(what, ok, said)] and its manifest."""
    checks = []

    def check(what, ok, said=''):
        checks.append({'what': what, 'ok': bool(ok), 'said': said})
        return ok
    try:
        top, m = rb_open(path, password, work)
    except RbError as e:
        check('opened with the password of the backups, every file as its manifest says',
              False, str(e))
        return checks, {}
    check('opened with the password of the backups, every file as its manifest says', True,
          '%d file(s)' % len(m.get('files') or {}))
    key = None
    try:
        key = bytes.fromhex(open(os.path.join(top, 'secrets.key')).read().strip())
        check('the key of the tokens is in it', len(key) >= 32)
    except (OSError, ValueError) as e:
        check('the key of the tokens is in it', False, str(e)[:200])
    try:
        got = copy_read_through(os.path.join(top, 'upsmon-copy.tar.gz'), key)
        c = got['counts']
        check('the copy of both databases reads to its last line', True, '%d tables, %d samples, '
              '%d accounts' % (len(c), c.get('samples', 0), c.get('accounts', 0)))
        want = m.get('tokens')
        if isinstance(want, int):
            pass
        check('a full administrator can sign in after it', got['admins'] > 0,
              '%d' % got['admins'])
        if got['tried']:
            check('the tokens open with the key in it', got['opened'] == got['tried'],
                  '%d of %d tried' % (got['opened'], got['tried']))
    except (OSError, ValueError, EOFError, RbError) as e:
        check('the copy of the database reads to its last line', False, str(e)[:200])
    try:
        with open(os.path.join(top, 'config.json')) as f:
            json.load(f)
        check('config.json is in it and reads', True)
    except (OSError, ValueError) as e:
        check('config.json is in it and reads', False, str(e)[:200])
    return checks, m


def rb_verify(store, by, tid=None, name=None, progress=None):
    """The newest backup of this node at a destination (or the one named),
    tried. The result is kept and returned."""
    def say(n, t):
        if progress:
            progress(n, 4, t)
    targets = [t for t in rb_targets(store) if t.get('enabled') and (not tid or t['id'] == tid)]
    if tid and not targets:
        raise RbError('no such destination')
    if not targets:
        raise RbError('no destination is switched on')
    t = targets[0]
    began = time.time()
    res = {'at': began, 'by': by, 'node': node_name(), 'target': t['id'], 'target_name': t['name'],
           'checks': [], 'ok': False}
    work = tempfile.mkdtemp(prefix='upsmon-verify-', dir=str(STATE_DIR))
    os.chmod(work, 0o700)
    try:
        say(1, 'the backups at %s listed' % t['name'])
        files = rb_remote_list(store, t['id'])
        pick = [f for f in files if f['name'] == name] if name else \
            ([f for f in files if f['mine']] or files)
        if not pick:
            raise RbError('there is no backup %s at %s' % (('called ' + name) if name else
                                                           'of this node', t['name']))
        f = pick[0]
        res.update(file=f['name'], made=f['when'], bytes=f['bytes'])
        say(2, 'fetched from %s' % t['name'])
        dst = os.path.join(work, 'b')
        rb_fetch(store, t['id'], f['name'], dst)
        say(3, 'opened and read through')
        res['checks'], m = rb_verify_file(dst, rb_password(), work)
        res['upsmon'] = m.get('upsmon')
    except (RbError, OSError, ValueError, subprocess.SubprocessError) as e:
        res['checks'].append({'what': 'fetched from the destination', 'ok': False,
                              'said': rb_said(e) if not isinstance(e, RbError) else str(e)})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    # The newest nightly copy here, read through too.
    say(4, 'the newest nightly copy read through')
    try:
        kept = kept_copies()
        if kept:
            got = copy_read_through(BACKUP_DIR / kept[0]['name'], sealing_key())
            res['checks'].append({'what': 'the newest nightly copy here reads to its last line',
                                  'ok': got['tried'] == got['opened'],
                                  'said': '%s, %d tokens' % (kept[0]['name'],
                                                             got['counts'].get('tokens', 0))})
    except Exception as e:                              # noqa: BLE001
        res['checks'].append({'what': 'the newest nightly copy here reads to its last line',
                              'ok': False, 'said': str(e)[:200]})
    res['ok'] = bool(res['checks']) and all(c['ok'] for c in res['checks'])
    res['secs'] = round(time.time() - began, 1)
    k = 'rbackup:verified:' + node_name()
    rows = _meta_json(store, k) or []
    if not isinstance(rows, list):
        rows = []
    store.set_meta(k, json.dumps(([res] + rows)[:RB_VERIFY_KEEP]))
    bad = [c['what'] + (': ' + c['said'] if c['said'] else '') for c in res['checks'] if not c['ok']]
    store.add_event('backups', 'the backup %s at %s was tried: %s' % (
        res.get('file') or '?', t['name'], 'it can be put back' if res['ok'] else
        'NOT GOOD - ' + '; '.join(bad)), 'info' if res['ok'] else 'bad', who=by)
    return res


def rb_verified(store):
    """Every node's tries, newest first."""
    out = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'rbackup:verified:%'"):
        try:
            rows = json.loads(r['v'] or '[]')
        except ValueError:
            continue
        out += [x for x in rows if isinstance(x, dict)]
    out.sort(key=lambda x: -float(x.get('at') or 0))
    return out


def rb_verified_forget(store, at=None):
    """Taken off the list - one try (by its time) or all; the backups stay."""
    n = 0
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'rbackup:verified:%'"):
        try:
            rows = json.loads(r['v'] or '[]')
        except ValueError:
            rows = []
        keep = [] if at is None else [x for x in rows if abs(float(x.get('at') or 0) - at) > 0.001]
        if len(keep) != len(rows):
            n += len(rows) - len(keep)
            store.set_meta(r['k'], json.dumps(keep))
    return n


def rb_verify_start(store, by, tid=None, name=None):
    """In a thread of its own, followed as a backup is (RB_JOB)."""
    with RB_LOCK:
        if RB_JOB['running']:
            raise ValueError('a backup is being made or tried already')
        RB_JOB.update(running=True, what='verify', says='starting', done=0, whole=4, error='',
                      began=time.time(), ended=0, result=None, by=by)

    def progress(done, whole, says):
        RB_JOB.update(done=done, whole=whole, says=says)

    def work():
        try:
            RB_JOB['result'] = rb_verify(store, by, tid, name, progress)
            if not RB_JOB['result'].get('ok'):
                RB_JOB['error'] = 'the backup is not good: ' + '; '.join(
                    c['what'] for c in RB_JOB['result']['checks'] if not c['ok'])
        except Exception as e:                          # noqa: BLE001
            RB_JOB['error'] = scrub_secret(str(e))[:400]
        finally:
            RB_JOB.update(running=False, ended=time.time())
    threading.Thread(target=work, name='rbackup-verify', daemon=True).start()
    return dict(RB_JOB)


def rb_verify_due(store):
    """Weekly: a week since this node last tried one."""
    if (CONFIG.get('rbackup_verify') or 'off') != 'weekly':
        return False
    rows = _meta_json(store, 'rbackup:verified:' + node_name()) or []
    last = float(rows[0].get('at') or 0) if isinstance(rows, list) and rows else 0
    return time.time() - last > 7 * 86400



# ======== carried over from OTP 1.0.187 (lines 14569-14570): the engines, in words ========
ENGINE_WORDS = {'sqlite': 'the file on this machine (SQLite)', 'mariadb': 'MariaDB',
                'postgres': 'PostgreSQL'}


# ======== carried over from OTP 1.0.187 (lines 14756-14798): one long job at a time ========
# ---- one long job at a time, which the page asks after ---------------------
DB_JOB = {'id': 0, 'what': '', 'running': False, 'done': 0, 'whole': 0, 'says': '',
          'error': '', 'result': None, 'began': 0, 'ended': 0}
DB_JOB_LOCK = threading.Lock()


def db_job(what, work):
    with DB_JOB_LOCK:
        if DB_JOB['running']:
            raise ValueError('%s is going on already' % DB_JOB['what'])
        DB_JOB.update({'id': DB_JOB['id'] + 1, 'what': what, 'running': True, 'done': 0,
                       'whole': 0, 'says': '', 'error': '', 'result': None,
                       'began': time.time(), 'ended': 0})

    def progress(done, whole, says):
        DB_JOB.update({'done': done, 'whole': whole, 'says': says})
        if time.time() - DB_JOB.get('_pub', 0) > 1:
            DB_JOB['_pub'] = time.time()
            job_publish({k: v for k, v in DB_JOB.items() if not k.startswith('_')})

    def run():
        try:
            DB_JOB['result'] = work(progress)
        except Exception as e:
            DB_JOB['error'] = scrub_secret(str(e).split('\n')[0][:400])
            log('%s failed: %s' % (what, scrub_secret(e)), 'error')
        finally:
            DB_JOB.update({'running': False, 'ended': time.time()})
            job_publish({k: v for k, v in DB_JOB.items() if not k.startswith('_')})

    def beat():
        # Said again every half minute, so the other node - or this one,
        # after a restart - can tell a job going on from one that died.
        while DB_JOB.get('running'):
            time.sleep(30)
            if DB_JOB.get('running'):
                job_publish({k: v for k, v in DB_JOB.items() if not k.startswith('_')})

    threading.Thread(target=run, name='db-job', daemon=True).start()
    threading.Thread(target=beat, name='db-job-beat', daemon=True).start()
    return dict(DB_JOB)




# ======== carried over from OTP 1.0.187 (lines 20325-20344): one node claims it ========
def claim_once(store, key, value):
    """True for exactly one node: the one whose conditional UPDATE changed the
    row. A key not there yet is made first; two nodes making it at the same
    moment cannot both insert it (it is the primary key).

    Two replicated databases are two tables, though: each node's INSERT went
    in, and replication then stopped on the other's for good; each UPDATE
    took the day too. A key of both nodes (not one of this node's own,
    'NAME:NODE') is claimed by one node alone since 1.0.147 - see ha_lead -
    so only that one ever writes its row."""
    if CONFIG.get('ha_mode') == 'replicated' and not key.endswith(':' + node_name()) and \
            not ha_lead(store):
        return False
    if store.get_meta(key) is None:
        try:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (key, ''))
        except Exception:                               # noqa: BLE001
            pass
    return bool(store.db.run('UPDATE meta SET v = ? WHERE k = ? AND (v IS NULL OR v <> ?)',
                             (str(value), key, str(value))))


# ======== carried over from OTP 1.0.187 (lines 20370-20412): the progress of a job ========
# ---- a job's progress, where both nodes can read it ------------------------------
def job_publish(job):
    store = HA_STORE.get('store')
    if store is None and ENGINE[0] is not None:
        store = ENGINE[0].store
    if not store or HA_REBUILDING.is_set():
        return
    try:
        store.set_meta('db_job:' + node_name(), json.dumps(dict(job, node=node_name(),
                                                                at=time.time()),
                                                           default=str))
    except Exception:                                   # noqa: BLE001
        pass


def job_read():
    """The job as the database has it - this node's, or the other's."""
    if DB_JOB.get('running') or DB_JOB.get('ended'):
        here = dict(DB_JOB, node=node_name())
    else:
        here = None
    store = HA_STORE.get('store')
    there = None
    if store:
        try:
            for r in store.db.rows("SELECT v FROM meta WHERE k LIKE 'db!_job:%' ESCAPE '!'"):
                one = json.loads(r['v'] or 'null')
                # Going on, by the word of a node that has not said so for
                # five minutes - or of this node, which is not running it:
                # it ended with the process that ran it (1.0.37).
                if one and one.get('running') and (
                        time.time() - float(one.get('at') or one.get('began') or 0) > 300 or
                        (one.get('node') == node_name() and not DB_JOB.get('running'))):
                    one = dict(one, running=False, ended=float(one.get('at') or 0),
                               error=one.get('error') or 'it stopped with the service that '
                               'ran it (restarted, or the database was changed)')
                if one and (not there or float(one.get('began') or 0) >
                            float(there.get('began') or 0)):
                    there = one
        except Exception:                               # noqa: BLE001
            there = None
    if here and (not there or float(here.get('began') or 0) >= float(there.get('began') or 0)):
        return here
    return there or dict(DB_JOB)



# ======== carried over from OTP 1.0.187 (lines 10145-10166): rows of one node ========
# by both at once (its first INSERT on each node) came over to the other as a
# second row with the same key, and replication stopped for good.
NODE_KEY_SEP = '@@'


def node_key(prefix, name):
    return '%s:%s%s%s' % (prefix, norm_name(name), NODE_KEY_SEP, node_name())


def node_key_rows(store, prefix, name):
    """Every node's row for `name` (and one written before 1.0.146)."""
    n = norm_name(name)
    return store.db.rows("SELECT k, v FROM meta WHERE k = ? OR k LIKE ? ESCAPE '!'",
                         ('%s:%s' % (prefix, n),
                          '%s:%s%s%%' % (prefix, n.replace('!', '!!').replace('%', '!%')
                                         .replace('_', '!_'), NODE_KEY_SEP)))


def node_key_name(prefix, k):
    """The name a key is counted for, its node taken off."""
    return str(k)[len(prefix) + 1:].split(NODE_KEY_SEP, 1)[0]



# ======== carried over from OTP 1.0.187 (lines 20607-20609): shell quoting ========
def shlex_quote(s):
    import shlex
    return shlex.quote(s)


# ======== carried over from OTP 1.0.187 (lines 27215-27218): a job of the network ========
def net_job_active(job):
    return bool(job) and job.get('state') in ('asked', 'running', 'rebooting') and \
        time.time() - float(job.get('moved') or job.get('at') or 0) < NET_JOB_LIVE_S



# ======== carried over from OTP 1.0.187 (lines 27652-27669): a thread of the network ========
def _net_thread(fn, *args):
    def go():
        try:
            fn(*args)
        except Exception as e:                          # noqa: BLE001
            log('network: %s' % e, 'warn')
        finally:
            with NET_WORK_LOCK:
                NET_WORK['busy'] = False
    with NET_WORK_LOCK:
        if NET_WORK['busy']:
            return False
        NET_WORK['busy'] = True
    threading.Thread(target=go, name='upsmon-net', daemon=True).start()
    return True


NET_REBOOT_GIVE_UP_S = 3600


# ======== carried over from OTP 1.0.187 (lines 32207-32700): the API ========
# ---------------------------------------------------------------------------
# The API the web pages ask
# ---------------------------------------------------------------------------
# On 127.0.0.1 only, and only for whoever holds the token in /run/upsmon - which
# is the web server's group and nobody else. The PHP pages relay to it and
# add nothing: the session travels as a header, and this decides what that
# session may have. Two kinds of session: an administrator's (`admin`) and a
# person enrolling their own token (`portal`), which can reach nothing but
# its own token.

ROLE_RANK = {'readonly': 1, 'tokenadmin': 2, 'fulladmin': 3}


class ApiError(Exception):
    def __init__(self, status, words, detail=''):
        Exception.__init__(self, words)
        self.status = status
        self.detail = detail


def api_token(make=False):
    if make:
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(32)
        write_replacing(TOKEN_FILE, token + '\n', 0o640)
        try:
            import grp
            gid = grp.getgrnam(WEB_GROUP).gr_gid
            os.chown(str(TOKEN_FILE), -1, gid)
            os.chmod(str(RUN_DIR), 0o750)
            os.chown(str(RUN_DIR), -1, gid)
        except (KeyError, OSError, ImportError):
            pass
        return token
    try:
        return TOKEN_FILE.read_text().strip()
    except OSError:
        return ''


def _int_id(v):
    """An id from a request: a whole number, or ValueError said plainly."""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        raise ValueError('an id is a number')


BODY_WORDS = ('name', 'to', 'mail_to', 'dest', 'note', 'code', 'password', 'passphrase', 'lang',
              'kind', 'action', 'mail_fmt', 'display', 'user', 'old', 'new', 'q',
              'state', 'via', 'mode', 'fingerprint', 'label')


def _no_constant(word):
    raise ValueError('%s is not a number' % word)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = 'upsmon'
    protocol_version = 'HTTP/1.1'
    # A connection that says nothing for a minute is closed (1.0.101): each
    # held a thread for ever, and any program on this machine could open
    # thousands without the key.
    timeout = 60

    def log_message(self, fmt, *args):
        if debugging('api'):
            log('api %s' % (fmt % args), 'debug')

    # ---- the plumbing ---------------------------------------------------------
    @property
    def d(self):
        return self.server.daemon

    @property
    def store(self):
        return self.server.daemon.store

    @property
    def reader(self):
        """The long lists' own connection (1.0.101)."""
        return self.server.daemon.reader()

    def client_ip(self):
        said = str(self.headers.get('X-Upsmon-Client') or '').strip()
        return said if re.match(r'^[0-9a-fA-F:.]{2,45}\Z', said) else self.client_address[0]

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        if hasattr(self, '_body'):
            return self._body
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            raise ApiError(400, 'the length of the body is not a number')
        if n < 0:
            raise ApiError(400, 'the length of the body is not a number')
        if n > 8 * 1024 * 1024:
            raise ApiError(413, 'that is more than this takes')
        raw = self.rfile.read(n) if n else b''
        try:
            # NaN and Infinity are not numbers anybody means (1.0.103).
            self._body = json.loads(raw.decode('utf-8'), parse_constant=_no_constant) \
                if raw else {}
        except (ValueError, RecursionError):            # [[[[... too (1.0.139)
            raise ApiError(400, 'the body is not JSON')
        if not isinstance(self._body, dict):
            raise ApiError(400, 'the body is not an object')
        # What is a word is a word (1.0.103): a list where a name belongs was
        # made into the text "['x']" - a token by that name, a mail to it.
        for k in BODY_WORDS:
            v = self._body.get(k)
            if isinstance(v, (list, dict, bool)):
                raise ApiError(400, '%s is a piece of text here' % k)
            if isinstance(v, float) and k != 'code':
                raise ApiError(400, '%s is a piece of text here' % k)
        return self._body

    def body_to_file(self, path, most):
        """A request body that is a file, written down a lump at a time."""
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0:
            raise ApiError(400, 'no file arrived')
        if n > most:
            raise ApiError(413, 'that file is bigger than this takes')
        left = n
        with open(str(path), 'wb') as out:
            while left > 0:
                lump = self.rfile.read(min(left, 1 << 20))
                if not lump:
                    raise ApiError(400, 'the file did not arrive whole')
                out.write(lump)
                left -= len(lump)
        self._body = {}
        return n

    def send_bytes(self, data, name, kind='application/octet-stream'):
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Disposition', 'attachment; filename="%s"' % name)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path, name):
        # Opened before a header is sent (1.0.61): a file it may not read -
        # a copy root made on the command line - went out as "200" and then
        # a 500 in the middle of the download.
        try:
            f = open(str(path), 'rb')
        except PermissionError:
            raise ApiError(403, '%s cannot be read by the service (made by root on the command '
                                'line?): chown upsmon:upsmon it, then again' % name)
        except FileNotFoundError:
            raise ApiError(404, 'there is no such file: %s' % name)
        with f:
            self._send_open_file(f, name)

    def _send_open_file(self, f, name):
        size = os.fstat(f.fileno()).st_size
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="%s"' % name)
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        shutil.copyfileobj(f, self.wfile, 1 << 18)

    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    def route(self, method):
        # A body of its own for each request (1.0.146): on a kept-alive
        # connection the handler is the same, and the last one's was read again.
        self.__dict__.pop('_body', None)
        url = urlparse(self.path)
        self.args = {k: v[-1] for k, v in parse_qs(url.query).items()}
        path = url.path.rstrip('/')
        self.route_path = path
        if path != '/api/health':
            want = api_token()
            given = str(self.headers.get('X-Upsmon-Token') or '')
            # As bytes (1.0.149): a token with a letter beyond ASCII raised
            # TypeError there, and the connection was dropped with a trace.
            if not want or not hmac.compare_digest(want.encode('utf-8'),
                                                   given.encode('utf-8', 'replace')):
                return self.send_json({'ok': False, 'error': 'not this API’s token'}, 403)
        fn = ROUTES.get((method, path))
        if not fn:
            return self.send_json({'ok': False, 'error': 'no such endpoint: %s %s'
                                   % (method, path)}, 404)
        self._held = None
        self._failed = False
        try:
            got = fn(self)
            if got is not None:
                self.send_json(got if 'ok' in got else dict(ok=True, **got))
        except ApiError as e:
            # What went wrong in detail - a domain controller's name, a bind
            # DN - only to somebody signed in (1.0.33); the rest is in the log.
            detail = e.detail if self._signed_in() else None
            if e.detail and not detail:
                log('%s %s: %s (%s)' % (method, path, e, e.detail), 'info')
            self.send_json({'ok': False, 'error': str(e), 'detail': detail}, e.status)
        except (ValueError, BadSetting) as e:
            said = str(e)
            if said.startswith(('invalid literal for int()', 'could not convert string to float',
                                'cannot convert float')):
                # Python's words for a field that is not a number (1.0.103).
                said = 'a field that is a number holds something else'
            self.send_json({'ok': False, 'error': said}, 400)
        except DbError as e:
            # Where the database is, only to somebody signed in (1.0.146).
            if self._signed_in():
                self.send_json({'ok': False, 'error': str(e)}, 503)
            else:
                log('%s %s: the database: %s' % (method, path, e), 'warn')
                self.send_json({'ok': False, 'error': 'the database cannot be reached just now '
                                                      '- try again in a moment'}, 503)
        except (TypeError, AttributeError, KeyError) as e:
            # A field of the wrong kind - null where a number goes, a list
            # where an object does (1.0.44): the request's fault, said so,
            # and the trace kept in case it was not.
            log('%s %s could not be read: %s\n%s' % (method, path, e, traceback.format_exc()),
                'warn')
            self.send_json({'ok': False, 'error': 'the request is not in the shape this '
                                                  'takes (a field of the wrong kind)'}, 400)
        except (BrokenPipeError, ConnectionResetError):
            # The page went away before its answer did (1.0.61): nothing broke.
            pass
        except Exception as e:
            # A value the database cannot keep - a number out of its range, a
            # text too long for its column (1.0.103): the request's fault.
            kind = type(e).__name__
            if kind in ('DataError', 'NumericValueOutOfRange', 'StringDataRightTruncation',
                        'InvalidTextRepresentation', 'OverflowError') or \
                    (kind == 'OperationalError' and 'out of range' in str(e).lower()):
                log('%s %s: a value the database cannot keep: %s' % (method, path, e), 'info')
                self.send_json({'ok': False, 'error': 'a value is too big or of the wrong kind '
                                                      'for the database'}, 400)
                return
            log('the API broke on %s %s: %s\n%s' % (method, path, e, traceback.format_exc()),
                'error')
            # The words of the exception stay in the log (1.0.33).
            self.send_json({'ok': False, 'error': 'it broke - the reason is in the log of the '
                                                  'service (/var/log/upsmon/upsmon.log)'}, 500)
        finally:
            self._release()

    def _signed_in(self):
        token = str(self.headers.get('X-Upsmon-Session') or '')
        if not token:
            return False
        try:
            # Only a look: an error must not keep a session alive. (1.0.36)
            # An administrator past the second step only (1.0.149): a portal
            # user, or a password without its code, was told the directory's
            # and the database's addresses with every error.
            s = self.store.session_get(
                token, 'admin', int(CONFIG.get('session_idle_min') or 120) * 60, touch=False)
            return bool(s) and not mfa_pending(s)
        except Exception:                               # noqa: BLE001
            return False

    def arg(self, name, default=''):
        return self.args.get(name, default)

    def num(self, name, default, lo=0, hi=10 ** 9):
        try:
            return max(lo, min(hi, int(float(self.args.get(name, default)))))
        except (TypeError, ValueError, OverflowError):
            return default

    # ---- who is asking ----------------------------------------------------------
    def session(self, kind):
        token = str(self.headers.get('X-Upsmon-Session') or '')
        if kind == 'admin':
            idle = int(CONFIG.get('session_idle_min') or 120) * 60
        else:
            idle = int(CONFIG.get('portal_session_min') or 15) * 60
        return self.store.session_get(token, kind, idle)

    def me(self, role='readonly'):
        s = self.session('admin')
        if not s:
            raise ApiError(401, 'not signed in, or the sign-in has run out')
        acc = self.store.account(s['name'])
        if not acc or acc.get('disabled'):
            self.store.session_end(self.headers.get('X-Upsmon-Session'))
            raise ApiError(401, 'that account may no longer sign in')
        s['role'] = acc['role']
        # The second step first (1.0.125): until it is given, the sign-in may
        # do that and nothing else.
        if mfa_pending(s) and getattr(self, 'route_path', '') not in MFA_ALLOWED:
            raise ApiError(401, 'the second step of signing in is not done yet')
        if acc.get('must_change') and getattr(self, 'route_path', '') not in MUST_CHANGE_ALLOWED:
            raise ApiError(403, 'change the password first')
        if ROLE_RANK.get(s['role'], 0) < ROLE_RANK[role]:
            raise ApiError(403, {'fulladmin': 'only a full administrator may do that',
                                 'tokenadmin': 'only a token administrator may do that'}
                           .get(role, 'that account may not do that'))
        s['account'] = acc
        return s

    def portal_link(self):
        """The enrolment pages' address, for a token's mail: from the name the
        pages were reached by, never from what the page sent (1.0.33)."""
        host = str(self.headers.get('X-Upsmon-Host') or '')
        if not re.fullmatch(r'([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?', host):
            return ''
        return 'https://%s/' % host

    def end_all(self, name, why):
        self.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                          ('admin', name.lower()))
        self.store.add_event('accounts', '%s: signed out everywhere' % why, 'warn')
        raise ApiError(401, 'that account may no longer sign in')

    THROTTLE_LOCK = threading.Lock()
    THROTTLE_TIDIED = [0.0]

    def throttle(self, kind, tries, wait_min, name='', ip_tries=None, name_tries=None,
                 what='wrong passwords'):
        """A sign-in attempt, counted before the password is asked (1.0.33):
        thirty at once from one address all slipped past a count made after
        the slow check. The attempt holds a place until it is known to have
        gone well, and gives it back then. Counted per address and, more
        loosely, per name, so many addresses cannot share out the guessing
        of one password."""
        ip = self.client_ip()
        try:
            a = ipaddress.ip_address(str(ip).split('%')[0])
            if a.version == 6 and not a.ipv4_mapped:
                # One /64 is one machine's to choose from (1.0.101): counted
                # per address, each guess came from a new one.
                ip = str(ipaddress.ip_network('%s/64' % a, strict=False))
        except ValueError:
            pass
        keys = [(kind, ip)]
        if name:
            # Counted per person, not per spelling (1.0.44): DOMAIN\\novak,
            # novak@anything and Novak are all novak here.
            who = str(name).strip().lower()
            # "admin>person" (a test of somebody's sign-in) keeps its admin
            # (1.0.146): CORP\\novak made it novak alone, one count for all.
            # Only for those tests (1.0.147): a name typed at a sign-in is
            # never split there - a>CORP\\novak, b>CORP\\novak... was a fresh
            # count each time for novak's password.
            pre = sep = ''
            if kind in ('code-test', 'radtest'):
                pre, sep, who = who.rpartition('>')
            who = who.split('\\', 1)[-1].rsplit('@', 1)[0].strip()
            keys.append((kind + '-name', (pre + sep + who)[:190]))
        t = time.time()
        span = wait_min * 60
        with self.THROTTLE_LOCK:
            for i, key in enumerate(keys):
                # Each limit its own where asked (1.0.103): a code typed on the
                # enrolment pages is one person's, and five typos of one
                # person locked the whole office behind its address out.
                limit = (ip_tries or tries) if i == 0 else (name_tries or tries * 4)
                fails = [x for x in self.d.login_fails[key] if t - x < span]
                self.d.login_fails[key] = fails
                info = self.d.login_info.setdefault(key, {'others': []})
                info.update(limit=limit, span=span, what=what, at=t)
                other = (str(name).strip()[:120] if i == 0 else str(ip)) if name or i else ''
                if other:
                    if other in info['others']:
                        info['others'].remove(other)
                    info['others'] = (info['others'] + [other])[-6:]
                if len(fails) >= limit:
                    raise ApiError(429, 'too many %s %s: try again in %s'
                                   % (what, 'from %s' % ip if i == 0 else 'for this name',
                                      human_span(span - (t - fails[0]))))
            for key in keys:
                self.d.login_fails[key].append(t)
            # Tidied at most every 30 s (1.0.59): past 20 000 names all still
            # waiting, every sign-in scanned the whole map under this lock.
            # Past 50 000 the oldest half goes - memory has an end.
            fl = self.d.login_fails
            if len(fl) > 20000 and t - self.THROTTLE_TIDIED[0] > 30:
                self.THROTTLE_TIDIED[0] = t
                # Kept for the longest wait of any kind (1.0.61), not this
                # kind's: a 5 min kind tidied away 15 min lockouts.
                keep_s = max(span, 6 * 3600)
                for k in [k for k, v in fl.items() if not v or t - v[-1] > keep_s]:
                    fl.pop(k, None)
                    self.d.login_info.pop(k, None)
                if len(fl) > 50000:
                    # Addresses go before names (1.0.61): many addresses must
                    # not flush the count of the one name being guessed.
                    order = sorted(fl, key=lambda k: (str(k[0]).endswith('-name'),
                                                      fl[k][-1] if fl[k] else 0))
                    for k in order[:len(fl) // 2]:
                        if k not in keys:
                            fl.pop(k, None)
                            self.d.login_info.pop(k, None)
        self._held = (keys, t)
        return keys

    def failed(self, key):
        """The attempt went wrong: the place it holds stays taken."""
        self._failed = True

    def _release(self):
        held = getattr(self, '_held', None)
        if not held or getattr(self, '_failed', False):
            return
        keys, t = held
        with self.THROTTLE_LOCK:
            for key in keys:
                got = self.d.login_fails.get(key)
                if got and t in got:
                    got.remove(t)
        self._held = None


ROUTES = {}
# What an administrator who still has to change their password may do.
MUST_CHANGE_ALLOWED = ('/api/auth/password', '/api/auth/logout', '/api/auth/whoami')


def route(method, path):
    def wrap(fn):
        ROUTES[(method, path)] = fn
        return fn
    return wrap


# ---- health and signing in -------------------------------------------------------
HEALTH_SEEN = {}


# ---- who is locked out (1.0.112) ---------------------------------------------------


# ======== carried over from OTP 1.0.187 (lines 32700-32986): lockouts ========
# ---- who is locked out (1.0.112) ---------------------------------------------------
# Each node counts the wrong passwords that reach it, in memory. Every node
# writes its list into meta when it changes, so the pages of either show both;
# a lockout is cleared by the node that holds it - asked through meta when it
# is the other one.
LOCKOUT_KINDS = {
    'admin': 'signing in to these pages',
    'portal': 'signing in to the enrolment pages',
    'portal-verify': 'a code typed on the enrolment pages',
    'portal-send': 'codes sent from the enrolment pages',
    'portal-confirm': 'confirming a token on the enrolment pages',
    'portal-reissue': 'a new token on the enrolment pages',
    'portal-codes': 'recovery codes shown on the enrolment pages',
    # Kept in the database for the whole cluster (1.0.116), not in a node's
    # memory: codes sent to a person, and a token locked by wrong codes.
    'codes-sent': 'codes sent by e-mail or SMS',
    'token-locked': 'the token, after wrong codes',
    'password': 'changing a password',
    'code-test': 'trying a code (Tokens)',
    'radtest': 'a RADIUS test (Test)',
    'texts-test': 'a test message (Message texts)',
    'radius-src': 'signing in to the VPN, from one place',
}
LOCKOUTS_SENT = {'sig': None, 'at': 0.0}
THROTTLE_GUARD = threading.Lock()


def lockouts_view(d):
    """What this node counts now: one line per address or name with a wrong
    attempt still counted, locked or not yet."""
    t = time.time()
    rows = []
    for key, fails in list(d.login_fails.items()):
        info = d.login_info.get(key) or {}
        span = float(info.get('span') or 0)
        if not span:
            continue
        fails = [x for x in fails if t - x < span]
        kind, who = key
        if info.get('guard'):
            # A place counted by the sign-in protection (1.0.137): blocked
            # for its own time, by its refusals or by its names.
            until = float(info.get('blocked_until') or 0)
            blocked = until > t
            if not fails and not blocked:
                # Forgotten once nothing of it counts (1.0.149): every new
                # place stayed for good - 50 000 /64s were 45 MB, and the
                # list published every few seconds 18 MB.
                if t - float(info.get('at') or 0) > span and t - until > span:
                    d.login_fails.pop(key, None)
                    d.login_info.pop(key, None)
                continue
            names = [n for n, ts in (info.get('names') or {}).items() if t - ts < span]
            last = max(fails[-1] if fails else 0, float(info.get('blocked_at') or 0))
            rows.append({
                'kind': kind, 'who': who, 'by': 'place', 'what': LOCKOUT_KINDS.get(kind, kind),
                'base': kind, 'words': info.get('what') or 'wrong sign-ins',
                'fails': len(fails), 'limit': int(info.get('limit') or 0),
                'names': len(names), 'names_limit': int(info.get('names_limit') or 0),
                'locked': blocked, 'until': until if blocked else None,
                'why': info.get('blocked_why') if blocked else '',
                'forgets': max(until, (fails[-1] + span) if fails else 0),
                'first': fails[0] if fails else last, 'last': last,
                'others': list(info.get('others') or [])})
            continue
        if not fails:
            continue
        by_name = kind.endswith('-name')
        base = kind[:-5] if by_name else kind
        limit = int(info.get('limit') or 0)
        locked = bool(limit) and len(fails) >= limit
        rows.append({
            'kind': kind, 'who': who, 'by': 'name' if by_name else 'address',
            'what': LOCKOUT_KINDS.get(base, base), 'base': base,
            'words': info.get('what') or 'wrong passwords',
            'fails': len(fails), 'limit': limit, 'locked': locked,
            'until': (fails[0] + span) if locked else None,
            'forgets': fails[-1] + span, 'first': fails[0], 'last': fails[-1],
            'others': list(info.get('others') or [])})
    rows.sort(key=lambda r: (not r['locked'], -r['last']))
    return rows


def lockouts_clear(d, which=None):
    """Forget counts: which is a list of (kind, who); None - every one."""
    n = 0
    with ApiHandler.THROTTLE_LOCK:
        keys = list(d.login_fails) if which is None else \
            [tuple(k) for k in which if tuple(k) in d.login_fails]
        for k in keys:
            if d.login_fails.pop(k, None):
                n += 1
            d.login_info.pop(k, None)
    LOCKOUTS_SENT['sig'] = None
    return n


LOCKOUTS_PUBLISHED_MOST = 500


def lockouts_publish(d, force=False):
    rows = lockouts_view(d)
    if len(rows) > LOCKOUTS_PUBLISHED_MOST:
        # The locked ones and the busiest (1.0.149), not every place.
        rows = sorted(rows, key=lambda r: (not r.get('locked'), -int(r.get('fails') or 0)))[
            :LOCKOUTS_PUBLISHED_MOST]
    sig = json.dumps([(r['kind'], r['who'], r['fails'], r['locked']) for r in rows])
    now = time.time()
    if not force and sig == LOCKOUTS_SENT['sig'] and now - LOCKOUTS_SENT['at'] < 60:
        return rows
    # On a server alone too (1.0.187): the command line reads it there
    # (upsmon --lockouts), the daemon's counts being in its memory only.
    d.store.set_meta('lockouts:' + node_name(), json.dumps({'at': now, 'rows': rows}))
    LOCKOUTS_SENT.update(sig=sig, at=now)
    return rows


def lockouts_tick(d):
    """Asked by the other node's pages to clear something here? Then the list."""
    key = 'lockouts:ask:' + node_name()
    raw = d.store.get_meta(key)
    if raw:
        d.store.db.run('DELETE FROM meta WHERE k = ?', (key,))
        try:
            asks = json.loads(raw)
        except ValueError:
            asks = []
        for a in asks if isinstance(asks, list) else []:
            if not isinstance(a, dict):
                continue
            n = lockouts_clear(d, None if a.get('all') else [a.get('key') or []])
            lockouts_said(d.store, a, n)
        lockouts_publish(d, force=True)
        return
    lockouts_publish(d)


def lockouts_said(store, a, n):
    by = str(a.get('by') or '?')
    if a.get('all'):
        words = '%s cleared every lockout and count of wrong attempts on %s (%d)' % (
            by, node_name(), n)
    else:
        k = a.get('key') or ['', '']
        base = str(k[0])[:-5] if str(k[0]).endswith('-name') else str(k[0])
        words = '%s cleared the count of wrong attempts of %s %s (%s) on %s' % (
            by, 'the name' if str(k[0]).endswith('-name') else 'the address', k[1],
            LOCKOUT_KINDS.get(base, base), node_name())
    store.add_event('sign-ins', words, 'warn', who=by)


def lockouts_shared(store):
    return []


def lockouts_shared_clear(store, kind, who, by):
    return 0


RADTEST_NAME_TRIES = 5


@route('GET', '/api/lockouts')
def _lockouts(h):
    h.me('fulladmin')
    me = node_name()
    out = [{'node': me, 'me': True, 'fresh': True, 'rows': lockouts_view(h.d)}]
    now = time.time()
    for n in h.d.cluster_nodes():
        if n == me:
            continue
        try:
            got = json.loads(h.store.get_meta('lockouts:' + n) or '{}')
        except ValueError:
            got = {}
        rows = [r for r in (got.get('rows') or []) if float(r.get('forgets') or 0) > now]
        for r in rows:
            if r.get('locked') and float(r.get('until') or 0) <= now:
                r['locked'] = False
        out.append({'node': n, 'me': False, 'fresh': now - float(got.get('at') or 0) < 120,
                    'at': got.get('at'), 'rows': rows})
    out.append({'node': '*', 'me': False, 'fresh': True, 'shared': True,
                'rows': lockouts_shared(h.store)})
    return {'nodes': out, 'now': now, 'cluster': len(out) > 2}


@route('POST', '/api/lockouts')
def _lockouts_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    nodes = [node_name()] + [n for n in h.d.cluster_nodes() if n != node_name()]
    if act == 'clear' and str(b.get('kind') or '') in ('codes-sent', 'token-locked'):
        n = lockouts_shared_clear(h.store, str(b.get('kind')), str(b.get('who') or '').strip(),
                                  s['name'])
        if not n:
            raise ApiError(404, 'that is not counted any more')
        return {'message': 'cleared', 'told': []}
    if act == 'clear_all':
        want = nodes
        ask = {'all': 1, 'by': s['name']}
        shared = lockouts_shared(h.store)
        for r in shared:
            lockouts_shared_clear(h.store, r['kind'], r['who'], s['name'])
    elif act == 'clear':
        kind, who = str(b.get('kind') or ''), str(b.get('who') or '')
        base = kind[:-5] if kind.endswith('-name') else kind
        if base not in LOCKOUT_KINDS or not who:
            raise ApiError(400, 'which lockout?')
        node = str(b.get('node') or node_name())
        if node not in nodes:
            raise ApiError(400, 'there is no node %s' % node)
        want = [node]
        ask = {'key': [kind, who], 'by': s['name']}
    else:
        raise ApiError(400, 'no such thing to do')
    told = []
    for n in want:
        if n == node_name():
            got = lockouts_clear(h.d, None if ask.get('all') else [ask['key']])
            lockouts_said(h.store, ask, got)
            lockouts_publish(h.d, force=True)
        else:
            # The other node clears it within five seconds.
            with THROTTLE_GUARD:
                try:
                    pending = json.loads(h.store.get_meta('lockouts:ask:' + n) or '[]')
                except ValueError:
                    pending = []
                pending = (pending if isinstance(pending, list) else [])[-50:] + [ask]
                h.store.set_meta('lockouts:ask:' + n, json.dumps(pending))
            told.append(n)
    return {'message': 'cleared', 'told': told}




# ======== carried over from OTP 1.0.187 (lines 32987-33480): health, signing in ========
@route('GET', '/api/health')
def _health(h):
    """Asked without the API token, so it says only what the pages need
    before anybody is signed in: that the database opens, whether any
    account exists at all (the sign-in page says how to make the first one
    otherwise), the language and this node's name. No version, no count."""
    # The database asked at most once a second (1.0.57): /healthz is public,
    # and every load balancer, monitor and the VIP address's own check ask it.
    got = HEALTH_SEEN.get('db')
    if got and time.time() - got[0] < 1.0:
        users, db_ok, maint = got[1]
    else:
        try:
            users = 1 if h.store.db.value('SELECT 1 FROM accounts LIMIT 1') else 0
            db_ok = True
        except Exception:
            users, db_ok = 0, False
        try:
            maint = bool(maintenance_now(h.store).get('on'))
        except Exception:                               # noqa: BLE001
            maint = False
        HEALTH_SEEN['db'] = (time.time(), (users, db_ok, maint))
    out = {'ok': True, 'users': users, 'database': {'ok': db_ok},
           'lang': CONFIG.get('ui_lang') or 'cs', 'node': node_name(),
           'maintenance': maint}
    return out


DUMMY_PW_HASH = password_hash(secrets.token_urlsafe(18))



@route('POST', '/api/auth/login')
def _login(h):
    b = h.body()
    # No account has a longer name (1.0.146): megabytes typed went into the log.
    name = str(b.get('name') or '').strip()[:190]
    password = str(b.get('password') or '')
    key = h.throttle('admin', int(CONFIG.get('login_tries') or 5),
                     int(CONFIG.get('login_wait_min') or 15), name=name)
    acc = h.store.account(name)
    ok = None
    if acc:
        ok = acc if (acc.get('pw') and password_ok(password, acc['pw'])) else None
    else:
        # As long as for a name that is there (1.0.33): how long the answer
        # took told which names exist.
        password_ok(password, DUMMY_PW_HASH)
    if not ok:
        h.failed(key)
        h.store.add_event('sign-ins', 'a wrong password for %s from %s'
                          % (name or '(nobody)', h.client_ip()), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    if ok.get('disabled'):
        # Said as a wrong password is, and counted as one (1.0.57): the
        # difference told that the password was right.
        h.failed(key)
        h.store.add_event('sign-ins', '%s, switched off, tried to sign in from %s'
                          % (ok['name'], h.client_ip()), 'warn')
        raise ApiError(401, 'the name or the password is not right')
    # The second step, when it is asked for (1.0.125): the sign-in is made,
    # and may do nothing but give it.
    stage = mfa_stage(h.store, ok['name']) if CONFIG.get('admin_2fa') else ''
    token = h.store.session_new('admin', ok['name'], ok['role'], h.client_ip(),
                                CONFIG.get('session_hours') or 12,
                                data={'mfa': stage} if stage else None)
    h.store.set_account(ok['name'], last_in=time.time(), last_from=h.client_ip())
    h.store.add_event('sign-ins', '%s signed in from %s%s' % (
        ok['name'], h.client_ip(), {'check': ' - the second step to give',
                                     'enrol': ' - the second step to set up'}.get(stage, '')),
                      who=ok['name'])
    return {'token': token, 'who': {'name': ok['name'], 'role': ok['role'] if not stage else ''},
            'must_change': bool(ok.get('must_change')), 'mfa': stage}


# ---- editing the columns, switched on for one sign-in --------------------------
# Held here in memory, as on isemon: signing out, a sign-in running out and a
# restart of the service all switch it off again. Off, a layout already kept
# is drawn just the same; nothing can be changed.
COLS_EDITING = {}
COLS_EDITING_LOCK = threading.Lock()


def _cols_key(token):
    return hashlib.sha256(str(token or '').encode('utf-8', 'replace')).hexdigest()


# Kept with the sign-in's own row since 1.0.13 - in memory it was this node's
# alone, and behind a load balancer the next request found it switched off.
def _session_row(token):
    store = HA_STORE.get('store')
    if not store or not token:
        return None, None
    row = store.db.row('SELECT id, data FROM sessions WHERE token_hash = ?',
                       (hashlib.sha256(str(token).encode()).hexdigest(),))
    if not row:
        return store, None
    try:
        row['data'] = json.loads(row.get('data') or '{}')
    except ValueError:
        row['data'] = {}
    return store, row


def cols_editing(token):
    _, row = _session_row(token)
    return bool(row and row['data'].get('cols_edit'))


def set_cols_editing(token, on):
    store, row = _session_row(token)
    if not row:
        return False
    data = row['data']
    if on:
        data['cols_edit'] = 1
    else:
        data.pop('cols_edit', None)
    store.session_set_data(row['id'], data)
    return bool(on)


SETTINGS_FILE_KIND = 'upsmon-user-settings'


@route('POST', '/api/auth/logout')
def _logout(h):
    token = h.headers.get('X-Upsmon-Session')
    h.store.session_end(token)
    set_cols_editing(token, False)
    return {}


@route('POST', '/api/auth/columns')
def _columns(h):
    """Anybody signed in, a read-only account as well: this is how the page
    looks to that one person and changes nothing anybody else sees."""
    s = h.me()
    b = h.body()
    token = h.headers.get('X-Upsmon-Session') or ''
    if 'edit' in b:
        set_cols_editing(token, bool(b.get('edit')))
        if 'cols' not in b:
            return {'edit': cols_editing(token)}
    reset = bool(b.get('reset'))
    # Putting them back is always allowed; changing them only with the switch
    # on, so a page that misbehaves cannot rearrange somebody's tables while
    # they are only reading them.
    if not reset and not cols_editing(token):
        raise ApiError(409, 'switch on "Edit the columns" under your name first: the columns '
                       'are not being edited from this sign-in')
    try:
        kept = h.store.put_user_cols(s['name'], {} if reset else (b.get('cols') or {}))
    except ValueError as e:
        raise ApiError(400, str(e))
    if reset:
        h.store.add_event('accounts', '%s put the columns of every table back as they come'
                          % s['name'], who=s['name'])
    return {'tables': len(kept), 'edit': cols_editing(token)}


@route('GET', '/api/auth/settings')
def _my_settings(h):
    """What a person has set for themselves on the page, as one object that
    can be saved to a file and read back - here or on another machine. Never
    the password, the role or anything else about the account."""
    s = h.me()
    return {'name': s['name'], 'version': __version__, 'kind': SETTINGS_FILE_KIND,
            'settings': {'columns': h.store.user_cols(s['name']),
                         'prefs': h.store.user_prefs(s['name'])}}


@route('POST', '/api/auth/settings')
def _my_settings_put(h):
    s = h.me()
    b = h.body()
    got = b.get('settings')
    if not isinstance(got, dict):
        raise ApiError(400, 'that is not a file of settings: there is no "settings" in it')
    known = ('columns', 'prefs')
    ignored = sorted(k for k in got if k not in known)
    # Every section checked before any of them is written.
    for section, check, words in (('columns', h.store.clean_cols, 'the columns'),
                                  ('prefs', h.store.clean_prefs, 'the choices')):
        if section in got:
            try:
                check(got[section] if got[section] is not None else {})
            except (ValueError, TypeError, AttributeError) as e:
                raise ApiError(400, '%s in that file: %s' % (words, e))
    took = {}
    if 'columns' in got:
        took['columns'] = len(h.store.put_user_cols(s['name'], got['columns'] or {}))
    if 'prefs' in got:
        took['prefs'] = len(h.store.put_user_prefs(s['name'], got['prefs'] or {}))
    if not took:
        raise ApiError(400, 'nothing in that file is a setting this version keeps'
                       + (' (it holds: %s)' % ', '.join(ignored) if ignored else ''))
    h.store.add_event('accounts', '%s read their own settings back from a file (%s)'
                      % (s['name'], ', '.join('%s: %d' % kv for kv in took.items())),
                      who=s['name'])
    return {'took': took, 'ignored': ignored}


@route('GET', '/api/auth/whoami')
def _whoami(h):
    s = h.session('admin')
    if not s:
        return {'who': None}
    acc = h.store.account(s['name'])
    if not acc or acc.get('disabled'):
        return {'who': None}
    if mfa_pending(s):
        # No role until the second step is given: the pages that ask who it
        # is (a database or a package sent) refuse it.
        return {'who': {'name': acc['name'], 'role': '', 'display': acc.get('display') or '',
                        'mfa': mfa_pending(s)}}
    try:
        prefs = json.loads(acc.get('prefs') or '{}')
    except ValueError:
        prefs = {}
    # The page is drawn with the person's own layout of the tables from the
    # first frame, rather than as it comes and then again.
    return {'idle_min': int(CONFIG.get('session_idle_min') or 120),
            'who': {'name': acc['name'], 'role': acc['role'], 'source': acc.get('source'),
                    'display': acc.get('display') or '', 'must_change': bool(
                        acc.get('must_change')), 'prefs': prefs,
                    'cols': h.store.user_cols(acc['name']),
                    'cols_edit': cols_editing(h.headers.get('X-Upsmon-Session') or '')}}


@route('POST', '/api/auth/password')
def _password(h):
    s = h.me()
    b = h.body()
    acc = s['account']
    if acc.get('source') == 'directory':
        raise ApiError(400, 'this account signs in with its directory password, which is '
                       'changed in the directory')
    # Counted as sign-ins are (1.0.57): a session left open was a way to
    # guess the password without end.
    key = h.throttle('password', int(CONFIG.get('login_tries') or 5), 5, name=acc['name'])
    if not password_ok(str(b.get('old') or ''), acc.get('pw')):
        h.failed(key)
        raise ApiError(400, 'the password you have now is not right')
    h.store.set_account(acc['name'], password=str(b.get('new') or ''), must_change=0)
    # Every other sign-in with the old password ends (1.0.33).
    h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ? AND token_hash <> ?',
                   ('admin', acc['name'].lower(), hashlib.sha256(
                       str(h.headers.get('X-Upsmon-Session') or '').encode()).hexdigest()))
    h.store.add_event('accounts', '%s changed their own password' % acc['name'],
                      who=acc['name'])
    # The first password, written down by the installer, is no use to anybody
    # now - and stays readable no longer (1.0.33).
    first = STATE_DIR / 'first-login.txt'
    try:
        if first.exists() and ('name: %s\n' % acc['name']) in first.read_text():
            first.unlink()
    except OSError:
        pass
    return {'message': 'the password is changed'}


@route('POST', '/api/auth/prefs')
def _prefs(h):
    s = h.me()
    acc = s['account']
    try:
        prefs = json.loads(acc.get('prefs') or '{}')
    except ValueError:
        prefs = {}
    b = h.body()
    if 'lang' in b:
        if str(b['lang']) not in ('cs', 'en'):
            raise ApiError(400, 'no such language here')
        prefs['lang'] = str(b['lang'])
    h.store.set_account(acc['name'], prefs=json.dumps(prefs))
    return {'prefs': prefs}


# ---- what it is doing --------------------------------------------------------------
@route('GET', '/api/status')
def _status(h):
    s = h.me()
    out = h.d.status()
    out['role'] = s['role']
    return out


@route('GET', '/api/software')
def _software(h):
    """What every node runs on (1.0.99): this one asked now, the others as
    their last heartbeat said."""
    h.me()
    me = node_name()
    out = [{'name': me, 'me': True, 'alive': True, 'software': software_info(h.store)}]
    try:
        for n in ha_nodes(h.store):
            if n['name'] != me:
                out.append({'name': n['name'], 'me': False, 'alive': bool(n.get('alive')),
                            'age': int(n.get('age') or 0), 'software': n.get('software') or {}})
    except Exception:                                   # noqa: BLE001
        pass
    return {'nodes': out}




# ======== carried over from OTP 1.0.187 (lines 35205-35255): settings ========
@route('GET', '/api/settings')
def _settings(h):
    s = h.me()
    full = s['role'] == 'fulladmin'
    return {'settings': h.d.settings_state(full), 'may_change': full, 'panes': PANES,
            'only_when': ONLY_WHEN, 'config_file': str(CONFIG_FILE),
            'database': h.store.db.where(), 'directories': [], 'realms': [], 'isemon': {},
            'node': node_name(), 'nodes': h.d.cluster_nodes(), 'cluster': False}


@route('POST', '/api/settings')
def _settings_do(h):
    s = h.me('fulladmin')
    b = h.body()
    asked = b.get('settings') or {}
    try:
        # The other sign-ins ended when the second step is switched on: in
        # save_settings, the one saving it kept.
        return h.d.save_settings(asked, by=s['name'], node=b.get('node'),
                                 drawn_by=b.get('drawn_by'), keep_session=s.get('id'))
    except NodeMoved as e:
        raise ApiError(409, str(e))
    except BadSetting as e:
        raise ApiError(400, str(e))




# ======== carried over from OTP 1.0.187 (lines 35382-35510): accounts, sessions, events ========
@route('GET', '/api/users')
def _users(h):
    s = h.me()
    mfa = mfa_all(h.store)
    users = h.store.accounts()
    for u in users:
        u['mfa'] = mfa.get(str(u.get('name') or '').lower())
    return {'users': users, 'may_change': s['role'] == 'fulladmin',
            'mfa_on': bool(CONFIG.get('admin_2fa')),
            'roles': [{'role': r, 'words': ROLE_WORDS[r]} for r in ROLES_ALL]}


@route('POST', '/api/users')
def _users_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act, name = b.get('action'), str(b.get('name') or '').strip()
    who = s['name']
    if act == 'add':
        h.store.add_account(name, b.get('role') or 'readonly', b.get('password'),
                            note=b.get('note') or '', must_change=b.get('must_change', 1))
        h.store.add_event('accounts', '%s made the account %s (%s)' % (who, name,
                                                                         b.get('role')), who=who)
        return {'message': 'the account %s is made' % name}
    acc = h.store.account(name)
    if not name:
        raise ApiError(400, 'which account?')                          # 1.0.103
    if not acc:
        raise ApiError(404, 'there is no account called %s' % name)
    if act in ('delete', 'disable') or (act == 'role' and b.get('role') != 'fulladmin'):
        if acc['role'] == 'fulladmin' and not h.store.fulladmins_left(but=name):
            raise ApiError(400, 'that is the last full administrator who can sign in')
    if act == 'delete':
        h.store.drop_account(name)
        h.store.add_event('accounts', '%s removed the account %s' % (who, name), 'warn', who=who)
        return {'message': 'the account %s is gone' % name}
    if act == 'role':
        h.store.set_account(name, role=b.get('role'))
        h.store.add_event('accounts', '%s made %s %s' % (who, name,
                                                         ROLE_WORDS.get(b.get('role'))), who=who)
        return {'message': 'saved'}
    if act == 'reset_cols':
        h.store.put_user_cols(acc['name'], {})
        h.store.add_event('accounts', '%s put the columns of every table back as they come '
                          'for %s' % (who, acc['name']), who=who)
        return {'message': 'the columns of %s are back as they come; they see it at their '
                           'next page load' % acc['name']}
    if act == 'password':
        h.store.set_account(name, password=b.get('password'), must_change=int(bool(
            b.get('must_change', 1))))
        h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                       ('admin', name.lower()))
        h.store.add_event('accounts', '%s set a new password for %s; their sign-ins are ended'
                          % (who, name), 'warn', who=who)
        return {'message': 'the password is set'}
    if act in ('disable', 'enable'):
        h.store.set_account(name, disabled=1 if act == 'disable' else 0)
        if act == 'disable':
            h.store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                           ('admin', name.lower()))
        h.store.add_event('accounts', '%s switched %s %s' % (who, name, 'off' if
                                                            act == 'disable' else 'on'), who=who)
        return {'message': 'saved'}
    raise ApiError(400, 'no such thing to do to an account')


@route('GET', '/api/sessions')
def _sessions(h):
    h.me('fulladmin')
    # The list is of who could still ask: the ones that sat too long are
    # tidied first (1.0.15), not shown as signed in for hours.
    h.store.sessions_tidy(int(CONFIG.get('session_idle_min') or 120) * 60,
                          int(CONFIG.get('portal_session_min') or 15) * 60)
    return {'sessions': h.store.sessions()}


@route('POST', '/api/sessions')
def _sessions_do(h):
    s = h.me('fulladmin')
    ident = int(h.body().get('id') or 0)
    row = h.store.db.row('SELECT kind, name, ip FROM sessions WHERE id = ?', (ident,))
    if not row:
        # Gone already (1.0.61): not written down as "ended the sign-in of ?".
        raise ApiError(404, 'that sign-in has ended already')
    h.store.session_drop(ident)
    h.store.add_event('sign-ins', '%s ended the sign-in of %s%s' % (
        s['name'], (row or {}).get('name') or '?', (' from %s' % row['ip']) if row and
        row.get('ip') else ''), 'warn', who=s['name'])
    return {'message': 'ended'}


@route('GET', '/api/events')
def _events(h):
    h.me()
    extra = time_span_sql(h)
    rows, total = h.reader.events(h.num('limit', 100, 1, 1000), h.num('offset', 0),
                                 h.arg('q'), h.arg('kind'), extra=extra)
    return {'rows': rows, 'total': total, 'kinds': h.reader.event_kinds()}


def time_span_sql(h):
    since, until = h.num('from', 0, 0, 10 ** 11), h.num('to', 0, 0, 10 ** 11)
    parts, args = [], []
    if since:
        parts.append('ts >= ?')
        args.append(since)
    if until:
        parts.append('ts < ?')
        args.append(until)
    return (' AND '.join(parts), args)


@route('GET', '/api/enrolment')
def _enrolment(h):
    h.me()
    since = h.num('since', 0, 0, 10 ** 9)


# ======== carried over from OTP 1.0.187 (lines 35670-35686): log ========
@route('GET', '/api/log')
def _log(h):
    h.me('fulladmin')
    return {'lines': log_tail(h.num('lines', 400, 10, 5000)), 'file': str(LOG_DIR / 'upsmon.log')}


@route('GET', '/api/db')


# ======== carried over from OTP 1.0.187 (lines 37379-37440): the API server ========
class ApiHttpServer(ThreadingHTTPServer):
    """The API's HTTP server, with room for many connections waiting at once
    (1.0.33): the default queue of five dropped the sixth of twenty pages
    asking at the same moment."""
    request_queue_size = 256
    daemon_threads = True
    # At most this many at once (1.0.101); past it a connection is closed at
    # once rather than given a thread.
    MOST = 256

    def __init__(self, *a, **kw):
        self.slots = threading.BoundedSemaphore(self.MOST)
        ThreadingHTTPServer.__init__(self, *a, **kw)

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            log_sparing('api-full', 'the API has %d connections open already: one more was '
                        'closed' % self.MOST, 'warn')
            self.shutdown_request(request)
            return
        try:
            ThreadingHTTPServer.process_request(self, request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            ThreadingHTTPServer.process_request_thread(self, request, client_address)
        finally:
            self.slots.release()


class ApiServer(object):
    def __init__(self, daemon):
        self.daemon = daemon
        self.httpd = None

    def start(self):
        port = int(CONFIG.get('admin_port') or 9849)
        # The port first, the key after (1.0.61): somebody else's program on
        # the port would otherwise have been handed the new key by the pages.
        self.httpd = ApiHttpServer(('127.0.0.1', port), ApiHandler)
        api_token(make=True)
        self.httpd.daemon_threads = True
        self.httpd.daemon = self.daemon
        threading.Thread(target=self.httpd.serve_forever, name='api', daemon=True).start()
        # Said beside the key (1.0.59): the pages read the port from here, so
        # api_port changed in the settings no longer leaves them asking 9861.
        try:
            write_replacing(RUN_DIR / 'admin-port', '%d\n' % port, 0o644)
        except OSError as e:
            log('the API port could not be written down for the pages: %s' % e, 'warn')
        log('the API is on 127.0.0.1:%d' % port)

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass




# ======== carried over from OTP 1.0.187 (lines 37441-37594): upgrades ========
# ---- maintenance and upgrades (1.0.37) -----------------------------------------------
def _upgrade_view(h):
    meta = None
    try:
        meta = json.loads(h.store.get_meta('upgrade:pkg') or 'null')
    except ValueError:
        meta = None
    nodes = []
    for n in ha_nodes(h.store):
        n = dict(n)
        n['maintenance'] = maintenance_row(h.store, n['name'])
        nodes.append(n)
    if not nodes:
        nodes = [{'name': node_name(), 'version': __version__, 'me': True, 'alive': True,
                  'maintenance': maintenance_row(h.store)}]
    ok, why = upgrade_checks(h.store, meta, pages=True)
    plan = upgrade_plan(h.store)
    # A finished one hidden by Hide this (1.0.123).
    if plan and plan.get('state') != 'running' and \
            h.store.get_meta('upgrade:seen') == str(plan.get('id') or plan.get('at')):
        plan = None
    return {'node': node_name(), 'version': __version__, 'nodes': nodes, 'package': meta,
            'plan': plan, 'ready': ok, 'not_ready': why,
            'downgrade_on': bool(CONFIG.get('upgrade_downgrade')),
            'mode': CONFIG.get('ha_mode') or '',
            'helper': UPGRADE_HELPER.exists(),
            'path_unit': Path('/etc/systemd/system/upsmon-upgrade.path').exists(),
            'log': upgrade_log_tail(120), 'web': online_view(h.store)}


@route('GET', '/api/upgrade')
def _upgrade(h):
    h.me('fulladmin')
    return _upgrade_view(h)


@route('POST', '/api/upgrade/package')
def _upgrade_package(h):
    s = h.me('fulladmin')
    UPGRADE_DIR.mkdir(mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='incoming-', suffix='.tar.gz', dir=str(UPGRADE_DIR))
    os.close(fd)
    tmp = Path(tmp)
    try:
        h.body_to_file(tmp, UPGRADE_MOST)
        try:
            info = upgrade_inspect(tmp)
        except ValueError as e:
            h.store.add_event('starting and stopping', '%s sent a package that was refused: %s'
                              % (s['name'], e), 'warn', who=s['name'])
            raise ApiError(400, str(e))
        if info.get('older'):
            raise ApiError(400, '%s is older than %s, which runs here: going back is done on '
                                'the command line' % (info['version'], info.get('installed')))
        plan = upgrade_plan(h.store)
        if plan and plan['state'] == 'running':
            raise ApiError(409, 'an upgrade is going on: wait for it, or stop it first')
        meta = upgrade_store_package(h.store, tmp, info, s['name'])
        h.store.add_event('starting and stopping', '%s sent upsmon %s (signed by %s), ready to '
                          'be put in' % (s['name'], meta['version'], meta.get('signed_by')),
                          'warn', who=s['name'])
        return dict(_upgrade_view(h), message='upsmon %s is checked and ready' % meta['version'])
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


@route('POST', '/api/upgrade')
def _upgrade_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    try:
        if act == 'start':
            upgrade_start(h.store, s['name'], pages=True)
            return dict(_upgrade_view(h), message='the upgrade has begun')
        if act == 'online_look':
            row = online_look(h.store, s['name'])
            if row.get('error'):
                raise ValueError('%s: %s' % (row.get('url'), row['error']))
            n = row.get('newest') or {}
            return dict(_upgrade_view(h), message=(
                'upsmon %s is there - newer than %s' % (n['version'], __version__) if row.get('newer')
                else ('nothing newer than %s' % __version__ if n else 'no upsmon package there')))
        if str(act or '').startswith('downgrade') and not CONFIG.get('upgrade_downgrade'):
            # Offered on the pages only when switched on (1.0.144).
            raise ValueError('going back to an older version is not offered on these pages: '
                             'switch it on in Settings → Upgrades')
        if act == 'downgrade_changelog':
            return {'changelog': downgrade_changelog(b.get('version'))}
        if act == 'downgrade_list':
            # Going back (1.0.143): the older versions there, and what stands
            # in the way of each.
            return {'downgrade': downgrade_list(h.store)}
        if act == 'downgrade_get':
            plan = upgrade_plan(h.store)
            if plan and plan['state'] == 'running':
                raise ValueError('an upgrade is going on: wait for it, or stop it first')
            meta = downgrade_fetch(h.store, str(b.get('version') or ''), s['name'])
            if b.get('start'):
                upgrade_start(h.store, s['name'], pages=True)
                return dict(_upgrade_view(h), message='upsmon %s fetched and checked; going back '
                            'to it has begun' % meta['version'])
            return dict(_upgrade_view(h), message='upsmon %s is fetched, checked for this database '
                        'and ready to go back to' % meta['version'])
        if act == 'online_get':
            plan = upgrade_plan(h.store)
            if plan and plan['state'] == 'running':
                raise ValueError('an upgrade is going on: wait for it, or stop it first')
            meta = online_fetch(h.store, str(b.get('version') or ''), s['name'])
            if b.get('start'):
                upgrade_start(h.store, s['name'], pages=True)
                return dict(_upgrade_view(h), message='upsmon %s fetched and checked; the upgrade '
                            'has begun' % meta['version'])
            return dict(_upgrade_view(h), message='upsmon %s is fetched, checked and ready'
                        % meta['version'])
        if act == 'hide':
            plan = upgrade_plan(h.store)
            if plan and plan.get('state') == 'running':
                raise ValueError('the upgrade is going on')
            if plan:
                h.store.set_meta('upgrade:seen', str(plan.get('id') or plan.get('at')))
            return _upgrade_view(h)
        if act == 'cancel':
            upgrade_cancel(h.store, s['name'])
            return dict(_upgrade_view(h), message='the upgrade is stopped')
        if act == 'maintenance':
            name = str(b.get('node') or node_name())
            if name not in [n['name'] for n in ha_nodes(h.store)] + [node_name()]:
                raise ValueError('there is no node %s' % name)
            on = bool(b.get('on'))
            maintenance_set(h.store, on, str(b.get('why') or 'by hand'), s['name'], name)
            return dict(_upgrade_view(h), message='%s: maintenance %s' % (
                name, 'on' if on else 'off'))
        if act == 'forget':
            plan = upgrade_plan(h.store)
            if plan and plan['state'] == 'running':
                raise ValueError('an upgrade is going on with it')
            h.store.db.run("DELETE FROM meta WHERE k LIKE 'upgrade:piece:%'")
            h.store.db.run("DELETE FROM meta WHERE k = 'upgrade:pkg'")
            return dict(_upgrade_view(h), message='the package is forgotten')
    except ValueError as e:
        raise ApiError(400, str(e))
    except (OSError, tarfile.TarError, subprocess.SubprocessError) as e:
        # The address not answering, a package cut off (1.0.146): said, not an
        # error 500 with its trace in the log.
        raise ApiError(502, 'the address could not be read: %s'
                       % (getattr(e, 'reason', None) or e))
    raise ApiError(400, 'no such thing to do')


# ---- high availability (1.0.13) ---------------------------------------------------


# ======== carried over from OTP 1.0.187 (lines 37782-37972): TLS on the pages ========
# ---- TLS and the cluster's VIP address (1.0.47) ------------------------------------
@route('GET', '/api/web')
def _web(h):
    me = h.me()
    store = h.store
    nodes = []
    for n in ha_nodes(store):
        one = {k: n.get(k) for k in ('name', 'me', 'alive', 'address', 'version', 'maintenance',
                                     'age', 'host')}
        one['web'] = web_state(store) if n['me'] else (n.get('web') or {})
        nodes.append(one)
    if not any(x['me'] for x in nodes):
        nodes.insert(0, {'name': node_name(), 'me': True, 'alive': True,
                         'address': node_address(), 'web': web_state(store)})
    v = vip_conf(store)
    holder = [x['name'] for x in nodes if (x.get('web') or {}).get('vip_here')]
    return {'node': node_name(), 'cluster': bool(CONFIG.get('ha_mode')), 'nodes': nodes,
            'vip': dict(v, prefer_now=vip_prefer(store, v) if CONFIG.get('ha_mode') else '',
                        holder=holder),
            'tls': {t: tls_view(tls_profile(store, t)) for t in tls_targets(store)},
            'acme': {'on': bool(CONFIG.get('acme')), 'care': {
                t: acme_care(store, t) and t in acme_wanted(store) for t in tls_targets(store)},
                     'state': {t: acme_state(store, t) for t in tls_targets(store)},
                     'before': {t: acme_before(store, t) for t in tls_targets(store)}},
            'presets': TLS_PRESETS, 'dh': DH_WORDS,
            'may': me.get('role') == 'fulladmin'}


@route('POST', '/api/web')
def _web_do(h):
    s = h.me('fulladmin')
    who = s['name']
    b = h.body()
    act = str(b.get('action') or '')
    store = h.store
    target = str(b.get('target') or '')
    if act.startswith('tls_'):
        if target not in tls_targets(store):
            raise ApiError(400, 'there is no node or address called %s' % target)
        prof = tls_profile(store, target) or {}
        words = 'the VIP address' if target == 'vip' else target
    if act in ('tls_upload', 'tls_selfsigned'):
        if act == 'tls_upload':
            pfx = b''
            if b.get('pfx'):
                try:
                    pfx = base64.b64decode(str(b['pfx']), validate=True)
                except (ValueError, binascii.Error):
                    raise ApiError(400, 'the PFX / PKCS#12 file did not arrive whole')
                if len(pfx) > 200000:
                    raise ApiError(400, 'that is far bigger than any certificate file')
            pending = unseal_secret(prof['pending_key'], 'web:tls') if prof.get('pending_key') \
                else ''
            got = cert_bundle(b.get('cert'), b.get('key'), b.get('chain'), b.get('root'), pfx,
                              str(b.get('password') or ''), pending)
            how = 'uploaded'
        else:
            names = [x.strip() for x in re.split(r'[\s,;]+', str(b.get('names') or '')) if x.strip()]
            key, crt = make_selfsigned(str(b.get('cn') or '').strip(), names,
                                       int(b.get('days') or 825), str(b.get('kind') or 'rsa2048'),
                                       org=str(b.get('org') or ''))
            got = cert_bundle(crt, key)
            how = 'self-signed, made here'
        info = got['info']
        if info.get('not_after') and info['not_after'] < time.time():
            raise ApiError(400, 'this certificate ran out on %s' % stamp(info['not_after']))
        prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                    key=seal_secret(got['key'], 'web:tls'), info=info,
                    chain_info=got['chain_info'], root_info=got['root_info'],
                    verify=got['verify'], how=how)
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        prof.setdefault('preset', 'standard')
        prof.setdefault('dh', 'none')
        tls_save(store, target, prof, who)
        # One put in by hand is kept (1.0.170): ACME does not replace it at its
        # next renewal - Automatic certificates → Look after it gives it back.
        acme_care_set(store, target, False, who, 'a certificate was put in by hand')
        store.add_event('settings', '%s put a certificate in for %s: %s (until %s)' % (
            who, words, info.get('subject'), stamp(info.get('not_after')) if info.get('not_after') else '?'), 'warn', who=who)
        return {'message': 'the certificate of %s is kept; the node%s put%s it in within a few '
                           'seconds' % (words, 's' if target == 'vip' else '',
                                        '' if target == 'vip' else 's'),
                'tls': tls_view(prof)}
    if act == 'tls_csr':
        names = [x.strip() for x in re.split(r'[\s,;]+', str(b.get('names') or '')) if x.strip()]
        key, csr = make_csr(str(b.get('cn') or '').strip(), names, str(b.get('kind') or 'rsa2048'),
                            org=str(b.get('org') or ''), unit=str(b.get('unit') or ''),
                            country=str(b.get('country') or ''), city=str(b.get('city') or ''))
        prof.update(pending_key=seal_secret(key, 'web:tls'), csr=csr,
                    csr_at=time.time(), csr_cn=str(b.get('cn') or ''))
        tls_save(store, target, prof, who)
        store.add_event('settings', '%s made a certificate request for %s (%s)'
                        % (who, words, b.get('cn')), who=who)
        return {'message': 'the request is made: give it to your certificate authority, then '
                           'upload what it sends back - the key waits here', 'csr': csr,
                'tls': tls_view(prof)}
    if act == 'tls_csr_drop':
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        tls_save(store, target, prof, who)
        return {'message': 'the request and its waiting key are gone', 'tls': tls_view(prof)}
    if act == 'tls_policy':
        prof.update(tls_policy_checked(b))
        tls_save(store, target, prof, who)
        store.add_event('settings', '%s changed the TLS settings of %s: %s, DH %s%s' % (
            who, words, prof['preset'], prof['dh'],
            ', HSTS %d s' % prof['hsts'] if prof.get('hsts') else ''), who=who)
        slow = prof['dh'] in ('gen3072', 'gen4096')
        return {'message': 'the TLS settings of %s are kept%s' % (
            words, '; making the DH parameters takes a while' if slow else ''),
                'tls': tls_view(prof)}
    if act == 'tls_forget':
        store.db.run('DELETE FROM meta WHERE k = ?', ('web:tls:' + target,))
        acme_care_set(store, target, False, who, 'upsmon lets its TLS go')
        store.add_event('settings', '%s: upsmon no longer looks after the TLS of %s (nginx keeps '
                        'what it has)' % (who, words), 'warn', who=who)
        return {'message': 'upsmon no longer looks after the TLS of %s; nginx keeps the files it '
                           'has' % words}
    if act == 'tls_export':
        if not prof.get('cert'):
            raise ApiError(404, 'no certificate is kept for %s' % words)
        fmt = str(b.get('format') or 'pem')
        pw = str(b.get('password') or '')
        got = cert_export(prof, fmt, pw, bool(b.get('with_chain', True)))
        if got.get('with_key'):
            store.add_event('settings', '%s exported the certificate of %s WITH its private key (%s%s)'
                            % (who, words, got['words'], ', locked' if pw else ', NOT locked'),
                            'warn', who=who)
        else:
            store.add_event('settings', '%s exported the certificate of %s (%s)' % (who, words, got['words']),
                            who=who)
        cn = str((prof.get('info') or {}).get('cn') or '')
        base = cn.replace('*', '_') if re.fullmatch(r'[A-Za-z0-9*.-]{1,100}', cn) else (
            'web-address' if target == 'vip' else target)
        return {'name': '%s%s' % (base, got['suffix']),
                'data': base64.b64encode(got['data']).decode('ascii'), 'mime': got['mime'],
                'with_key': got.get('with_key', False)}
    if act == 'tls_pem':
        if not prof.get('cert'):
            raise ApiError(404, 'no certificate is kept for %s' % words)
        return {'pem': prof['cert'] + (prof.get('chain') or ''), 'csr': prof.get('csr') or ''}
    if act == 'retry':
        node = str(b.get('node') or node_name())
        if node not in {n['name'] for n in ha_nodes(store)} | {node_name()}:
            raise ApiError(400, 'there is no node called %s' % node)
        store.set_meta('web:retry:' + node, str(time.time()))
        return {'message': '%s tries again within a few seconds' % node}
    raise ApiError(400, 'no such thing to do')




# ======== carried over from OTP 1.0.187 (lines 39061-39082): console at login ========
@route('GET', '/api/console-login')
def _console_login(h):
    h.me('fulladmin')
    return console_login_view(h.store)


@route('POST', '/api/console-login')
def _console_login_do(h):
    s = h.me('fulladmin')
    b = h.body()
    on = b.get('on')
    if not isinstance(on, bool):
        raise ApiError(400, 'on is true or false')
    try:
        console_login_ask(h.store, str(b.get('node') or node_name()), on, s['name'])
    except ValueError as e:
        raise ApiError(400, str(e))
    return {'message': 'asked: the console at login is switched on within seconds' if on else
            'asked: the console at login is switched off within seconds'}


# ---- root's SSH keys and the updates of the system on the pages (1.0.158) ------------


# ======== carried over from OTP 1.0.187 (lines 39008-39059): restart and power off, the time, on the pages ========
@route('GET', '/api/power')
def _power(h):
    h.me('fulladmin')
    return power_view(h.store)


@route('POST', '/api/power')
def _power_do(h):
    s = h.me('fulladmin')
    b = h.body()
    if b.get('action') == 'hide':
        plan = power_plan(h.store)
        if plan.get('id'):
            h.store.set_meta('power:seen', str(plan['id']))
        return power_view(h.store)
    try:
        plan = power_ask(h.store, str(b.get('how') or ''), b.get('targets') or [],
                         str(b.get('order') or ''), s['name'])
    except ValueError as e:
        raise ApiError(400, str(e))
    return {'message': 'asked', 'plan': plan}


@route('GET', '/api/ntp')
def _ntp(h):
    h.me('fulladmin')
    return ntp_view(h.store)


@route('POST', '/api/ntp')
def _ntp_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    node = str(b.get('node') or node_name())
    try:
        if act == 'save':
            ntp_save(h.store, b.get('conf') or {}, s['name'])
            return {'message': 'saved; each node sets its time servers within seconds'}
        if act in ('read', 'sync'):
            known = [node_name()] + [n['name'] for n in ha_nodes(h.store)]
            if node not in known:
                raise ApiError(400, 'there is no node %s' % node)
            h.store.set_meta('ntp:%s:%s' % (act, node), repr(time.time()))
            if act == 'sync':
                h.store.add_event('settings', '%s asked %s to step its clock to the time '
                                  'servers now' % (s['name'], node), 'warn', who=s['name'])
            return {'message': 'asked: %s does it within seconds' % node}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')



# ======== carried over from OTP 1.0.187 (lines 39142-39184): the updates of the system on the pages ========
@route('GET', '/api/osup')
def _osup(h):
    h.me('fulladmin')
    return osup_view(h.store)


@route('POST', '/api/osup')
def _osup_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'check':
            nodes = osup_check_ask(h.store, b.get('nodes') or host_nodes(h.store), s['name'])
            return {'message': 'looking for updates on %s' % ', '.join(nodes)}
        if act == 'start':
            plan = osup_start(h.store, b.get('nodes') or None, str(b.get('reboot') or 'ask'),
                              s['name'], security=bool(b.get('security')))
            return {'message': 'the update starts: %s, one at a time' % ', '.join(plan['order']),
                    'plan': plan}
        if act == 'cancel':
            osup_cancel(h.store, s['name'])
            return {'message': 'stopped - a node being updated finishes'}
        if act == 'clear':
            osup_clear(h.store, s['name'])
            return osup_view(h.store)
        if act == 'hide':
            plan = osup_plan(h.store)
            if plan.get('state') == 'running':
                raise ValueError('it is still going on')
            if plan.get('id'):
                h.store.set_meta('host:osup:seen', str(plan['id']))
            return osup_view(h.store)
        if act == 'reboot':
            nodes = [n for n in host_nodes(h.store) if n in (b.get('nodes') or [])]
            plan = power_ask(h.store, 'reboot', nodes, 'rolling' if len(nodes) > 1 else 'one',
                             s['name'])
            return {'message': 'restarting %s, one at a time' % ', '.join(nodes), 'plan': plan}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')




# ======== carried over from OTP 1.0.187 (lines 38599-38963): backups on the pages ========
RB_UPLOADS = STATE_DIR / 'rbackup-uploads'


def rb_tools():
    return {k: bool(shutil.which(k)) for k in ('ssh', 'sftp', 'scp', 'ssh-keygen', 'ssh-keyscan',
                                                'smbclient', 'openssl')}


def rb_page(store):
    nodes = {}
    for r in rb_history(store):
        nodes.setdefault(r.get('node') or '?', r)
    return {'targets': [rb_view(t) for t in rb_targets(store)], 'runs': rb_history(store)[:40],
            'verified': rb_verified(store)[:20],
            'last_by_node': nodes, 'job': {k: v for k, v in RB_JOB.items()},
            'kinds': [{'kind': k, 'words': RB_KIND_WORDS[k], 'port': RB_PORTS.get(k)}
                      for k in RB_KINDS],
            'tools': rb_tools(), 'node': node_name(), 'locked': bool(rb_password()),
            'iter': RB_ITER, 'site': CONFIG.get('site_name') or 'upsmon',
            'next': rb_next_words()}


def rb_next_words():
    if not CONFIG.get('rbackup'):
        return ''
    try:
        hh, mm = (int(x) for x in str(CONFIG.get('rbackup_at') or '04:15').split(':', 1))
    except ValueError:
        hh, mm = 4, 15
    now = datetime.now()
    nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    if str(CONFIG.get('rbackup_every')) == 'weekly':
        want = int(CONFIG.get('rbackup_day') or 7)
        while nxt.isoweekday() != want:
            nxt += timedelta(days=1)
    return nxt.isoformat(timespec='minutes')


@route('GET', '/api/rbackup')
def _rbackup(h):
    h.me('fulladmin')
    return rb_page(h.store)


def _rb_target_for(h, b):
    """The destination asked about: the one saved, with what is typed over
    it (Try it before Save)."""
    tid = str(b.get('id') or '')
    old = rb_target(h.store, tid) if tid else None
    if tid and not old:
        raise ApiError(404, 'no such destination')
    if isinstance(b.get('target'), dict):
        try:
            t = rb_checked(dict(b['target'], id=tid or None), old)
        except ValueError as e:
            raise ApiError(400, str(e))
        if old:
            for k in ('key', 'pub', 'hostkey', 'client_cert', 'client_key', 'key_pass', 'ca',
                      'pin', 'ssh_cert'):
                if k in old and k not in t:
                    t[k] = old[k]
        return t
    if not old:
        raise ApiError(400, 'which destination?')
    return old


@route('POST', '/api/rbackup')
def _rbackup_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    by = s['name']
    try:
        if act == 'save':
            t = rb_save(h.store, dict(b.get('target') or {}, id=b.get('id') or
                                      (b.get('target') or {}).get('id')), by)
            return {'message': 'saved', 'target': rb_view(t)}
        if act == 'delete':
            rb_delete(h.store, b.get('id'), by)
            return {'message': 'taken away'}
        if act == 'try':
            t = _rb_target_for(h, b)
            out = {}
            if t['kind'] in ('sftp', 'scp') and not t.get('hostkey'):
                lines, fps = ssh_keyscan(t['host'], t['port'])
                return {'hostkey_needed': True, 'hostkey': lines, 'fingerprints': fps,
                        'message': 'the server\'s host key is not trusted yet'}
            out = rb_try(t)
            h.store.add_event('settings', '%s tried the backup destination %s: %s' % (
                by, t['name'], 'it works' if out['ok'] else out.get('error')), who=by)
            if t.get('id') and rb_target(h.store, t['id']):
                rb_set_fields(h.store, t['id'], '', '', tried={'at': time.time(), 'ok': out['ok'],
                                                               'error': out.get('error') or ''})
            return out
        if act == 'hostkey_scan':
            t = _rb_target_for(h, b)
            lines, fps = ssh_keyscan(t['host'], t['port'])
            return {'hostkey': lines, 'fingerprints': fps}
        if act == 'hostkey_trust':
            t = _rb_target_for(h, b)
            lines = str(b.get('hostkey') or '')
            fresh, fps = ssh_keyscan(t['host'], t['port'])
            # Only what the server shows now, as the page showed it: nothing
            # typed in its place.
            if sorted(x.strip() for x in lines.splitlines() if x.strip()) != \
                    sorted(x.strip() for x in fresh.splitlines() if x.strip()):
                raise ValueError('the server shows other host keys now than the ones shown: '
                                 'Try it again')
            rb_set_fields(h.store, t['id'], by, 'its host key trusted (%s)' % '; '.join(fps),
                          hostkey=fresh)
            return {'message': 'trusted', 'fingerprints': fps}
        if act == 'hostkey_forget':
            t = _rb_target_for(h, b)
            rb_set_fields(h.store, t['id'], by, 'its host key forgotten', hostkey=None)
            return {'message': 'forgotten'}
        if act == 'keygen':
            t = _rb_target_for(h, b)
            private, public = ssh_keygen('upsmon-backup@%s' % node_name())
            rb_set_fields(h.store, t['id'], by, 'a new ssh key made here',
                          key=seal_secret(private, bind=RB_BIND), pub=public, key_pass=None)
            return {'message': 'made', 'pub': public}
        if act == 'key_paste':
            t = _rb_target_for(h, b)
            pp = str(b.get('passphrase') or '')
            private, public = ssh_public_of(b.get('key'), pp)
            rb_set_fields(h.store, t['id'], by, 'an ssh key of their own given',
                          key=seal_secret(private, bind=RB_BIND), pub=public,
                          key_pass=seal_secret(pp, bind=RB_BIND) if pp else None)
            return {'message': 'taken', 'pub': public}
        if act == 'key_download':
            t = _rb_target_for(h, b)
            private = rb_secret(t, 'key')
            if not private:
                raise ApiError(404, 'there is no key')
            h.store.add_event('settings', '%s downloaded the private ssh key of the backup '
                              'destination %s' % (by, t['name']), 'warn', who=by)
            return {'pem': private if private.endswith('\n') else private + '\n',
                    'file': 'upsmon-backup-%s-key' % rb_slug(t['name'])}
        if act == 'key_forget':
            t = _rb_target_for(h, b)
            rb_set_fields(h.store, t['id'], by, 'its ssh key forgotten', key=None, pub=None,
                          key_pass=None, ssh_cert=None)
            return {'message': 'forgotten'}
        if act == 'cert_make':
            t = _rb_target_for(h, b)
            key, crt = rb_client_cert_make(b.get('cn') or 'upsmon-backup-%s' % rb_slug(node_name()))
            rb_set_fields(h.store, t['id'], by, 'a client certificate made here',
                          client_cert=crt, client_key=seal_secret(key, bind=RB_BIND))
            return {'message': 'made', 'cert': crt, 'info': cert_info(crt)}
        if act == 'cert_given':
            t = _rb_target_for(h, b)
            key, crt = rb_client_cert_given(b.get('text'), str(b.get('password') or ''))
            rb_set_fields(h.store, t['id'], by, 'a client certificate of their own given',
                          client_cert=crt, client_key=seal_secret(key, bind=RB_BIND))
            return {'message': 'taken', 'cert': crt, 'info': cert_info(crt)}
        if act == 'cert_forget':
            t = _rb_target_for(h, b)
            rb_set_fields(h.store, t['id'], by, 'its client certificate forgotten',
                          client_cert=None, client_key=None)
            return {'message': 'forgotten'}
        if act == 'pin':
            t = _rb_target_for(h, b)
            pin = re.sub(r'[^0-9a-f]', '', str(b.get('pin') or '').lower())
            if len(pin) != 64:
                raise ValueError('the fingerprint is SHA-256: 64 hex digits')
            rb_set_fields(h.store, t['id'], by, 'the server\'s certificate pinned (%s)' % pin,
                          pin=pin, tls_check='pin')
            return {'message': 'pinned'}
        if act == 'run':
            only = [str(x) for x in (b.get('ids') or [])] or None
            job = rb_job_start(h.store, by, only)
            # Every node's, as the schedule makes them (1.0.149): in a cluster
            # Back up now made only the backup of the node the page was on.
            others = rb_now_ask_others(h.store, by) if not only else []
            return {'message': 'the backup is being made' + (
                ' here; %s make%s theirs within a minute' % (
                    ', '.join(others), 's' if len(others) == 1 else '') if others else ''),
                'job': job, 'others': others}
        if act == 'job':
            return {'job': dict(RB_JOB)}
        if act == 'verify':
            # Tried without being put back (1.0.169), followed as a backup is.
            job = rb_verify_start(h.store, by, str(b.get('id') or '') or None,
                                  str(b.get('name') or '') or None)
            return {'message': 'the backup is being tried', 'job': job}
        if act == 'verified':
            return {'verified': rb_verified(h.store)[:40]}
        if act == 'verified_forget':
            at = None
            if not b.get('all'):
                try:
                    at = float(b.get('at'))
                except (TypeError, ValueError):
                    raise ValueError('which try?')
            n = rb_verified_forget(h.store, at)
            if not n:
                raise ValueError('that try is not on the list any more')
            h.store.add_event('backups', '%s took %d tr%s of backups off the list; the backups '
                              'stay where they are' % (by, n, 'y' if n == 1 else 'ies'), who=by)
            return {'message': 'taken off the list', 'verified': rb_verified(h.store)[:20]}
        if act == 'list':
            return {'files': rb_remote_list(h.store, b.get('id'))}
        if act == 'delete_file':
            t = rb_target(h.store, b.get('id'))
            name = str(b.get('name') or '')
            if not t or not RB_NAME_RE.match(name):
                raise ValueError('which backup?')
            tr = rb_transport(t)
            try:
                tr.open()
                names = set(x['name'] for x in tr.list())
                for n in [name] + [c for c in rb_companions(name) if c in names]:
                    tr.delete(n)
            finally:
                tr.close()
            h.store.add_event('backups', '%s deleted the backup %s at %s' % (by, name, t['name']),
                              'warn', who=by)
            return {'message': 'deleted'}
        if act == 'restore_md':
            return rb_restore_guide(h.store)
        if act == 'runs_forget':
            if b.get('all'):
                n = rb_history_forget(h.store)
                h.store.add_event('backups', '%s cleared the list of backups sent (%d line(s)); '
                                  'the backups stay where they went' % (by, n), who=by)
                return {'message': 'the list is empty; the backups stay where they went',
                        'runs': rb_history(h.store)[:40]}
            try:
                at = float(b.get('at'))
            except (TypeError, ValueError):
                raise ValueError('which line?')
            n = rb_history_forget(h.store, at, b.get('file'))
            if not n:
                raise ValueError('that line is not on the list any more')
            h.store.add_event('backups', '%s took %s off the list of backups sent; the backup '
                              'stays where it went' % (by, b.get('file') or 'a failed backup'),
                              who=by)
            return {'message': 'taken off the list', 'runs': rb_history(h.store)[:40]}
        if act == 'restore':
            return _rb_restore_job(h, b, by)
    except (RbError, ValueError) as e:
        raise ApiError(400, str(e))
    except subprocess.SubprocessError as e:
        raise ApiError(504, 'it took too long: %s' % str(e)[:200])
    raise ApiError(400, 'no such thing to do')


def _rb_restore_job(h, b, by):
    """A backup put back - one at a destination, or one sent from the page -
    as a job the page follows (Settings → The database shows it too)."""
    password = str(b.get('password') or '') or rb_password()
    src = None
    if b.get('upload'):
        up = str(b.get('upload'))
        if not re.match(r'^[0-9a-f]{16}\Z', up):
            raise ValueError('which file?')
        src = RB_UPLOADS / up
        if not src.is_file():
            raise ValueError('the file sent is not here any more: send it again')
    else:
        t = rb_target(h.store, b.get('id'))
        name = str(b.get('name') or '')
        if not t or not RB_NAME_RE.match(name):
            raise ValueError('which backup?')
    store, daemon = h.store, h.d

    def work(progress):
        tmp = None
        try:
            path = src
            if path is None:
                progress(1, 4, 'fetched from %s' % t['name'])
                tmp = Path(tempfile.mkdtemp(prefix='upsmon-fetch-', dir=str(STATE_DIR)))
                os.chmod(str(tmp), 0o700)
                path = tmp / name
                rb_fetch(store, t['id'], name, str(path))
            progress(2, 4, 'opened and checked')
            got = rb_restore(store, str(path), password, by)
            progress(4, 4, 'put back')
            try:
                daemon.reload_all('a backup was put back')
            except Exception:                           # noqa: BLE001
                pass
            return got
        finally:
            if tmp:
                shutil.rmtree(str(tmp), ignore_errors=True)
            if src is not None:
                try:
                    src.unlink()
                except OSError:
                    pass
    db_job('putting a backup back', work)
    return {'message': 'the backup is being put back', 'job': job_read()}


@route('POST', '/api/rbackup/upload')
def _rbackup_upload(h):
    """A backup file sent from the page, kept for an hour to be put back."""
    h.me('fulladmin')
    RB_UPLOADS.mkdir(mode=0o700, exist_ok=True)
    now = time.time()
    for p in RB_UPLOADS.iterdir():
        try:
            if now - p.stat().st_mtime > 3600:
                p.unlink()
        except OSError:
            pass
    up = secrets.token_hex(8)
    dst = RB_UPLOADS / up
    h.body_to_file(dst, 4 * 1024 ** 3)            # as nginx takes (1.0.139)
    try:
        with open(str(dst), 'rb') as f:
            head = f.read(8)
        if not (head.startswith(b'Salted__') or head.startswith(b'\x1f\x8b')):
            raise ApiError(400, 'that is not a backup of upsmon')
        work = tempfile.mkdtemp(prefix='upsmon-peek-', dir=str(STATE_DIR))
        try:
            if head.startswith(b'Salted__') and not rb_password():
                return {'upload': up, 'locked': True}
            try:
                _top, m = rb_open(str(dst), rb_password(), work)
            except RbError as e:
                return {'upload': up, 'locked': head.startswith(b'Salted__'), 'said': str(e)}
            return {'upload': up, 'locked': head.startswith(b'Salted__'), 'manifest': m}
        finally:
            shutil.rmtree(work, ignore_errors=True)
    except ApiError:
        dst.unlink()
        raise


@route('GET', '/api/rbackup/download')
def _rbackup_download(h):
    """A backup made now for the machine somebody is sitting at - or one
    fetched from a destination."""
    s = h.me('fulladmin')
    tid, name = h.arg('id'), h.arg('name')
    work = Path(tempfile.mkdtemp(prefix='upsmon-dl-', dir=str(STATE_DIR)))
    os.chmod(str(work), 0o700)
    try:
        if tid and name:
            rb_fetch(h.store, tid, name, str(work / name))
            h.store.add_event('backups', '%s downloaded the backup %s' % (s['name'], name),
                              'warn', who=s['name'])
            h.send_file(work / name, name)
            return None
        if not rb_password():
            # Locked always (1.0.136): unlocked it holds every token's key.
            raise ApiError(403, 'without a password of the backups the file would hold every '
                                'token\'s key unlocked: set the password first')
        path, m, _md = rb_build(h.store, str(work))
        h.store.add_event('backups', '%s downloaded a backup made for it (%s, %s)' % (
            s['name'], m['file'], 'locked' if m['encrypted'] else 'NOT locked'),
            'info' if m['encrypted'] else 'warn', who=s['name'])
        h.send_file(Path(path), m['file'])
        return None
    except (RbError, ValueError) as e:
        raise ApiError(400, str(e))
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
# ---- Settings → Network, Settings → Restart and power off (1.0.119) -------------------


# ======== carried over from OTP 1.0.187 (lines 39373-39472): ACME on the pages ========
# ---- certificates by ACME (1.0.169) ---------------------------------------------------
@route('GET', '/api/acme/challenge')
def _acme_challenge(h):
    """What acme.php gives the CA on port 80 - no account: the CA asks."""
    got = acme_challenge(h.store, h.arg('token'))
    if got is None:
        raise ApiError(404, 'no such challenge')
    return {'auth': got}


@route('GET', '/api/acme')
def _acme(h):
    h.me('fulladmin')
    return acme_view(h.store)


@route('POST', '/api/acme')
def _acme_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    try:
        if act == 'order':
            if not CONFIG.get('acme'):
                raise ValueError('certificates by ACME are off - switch them on and save first')
            # Any of them from any node (1.0.170): the CA's question and the
            # certificate are kept in the database, and the node it is for -
            # every node, for the VIP address - puts it in. Ordered by hand,
            # ACME looks after it from now on.
            target = str(b.get('target') or '')
            if target not in tls_targets(h.store) or \
                    (target == 'vip' and not vip_conf(h.store).get('address')):
                raise ValueError('there is no such certificate')
            name = acme_name_of(h.store, target)
            if not name:
                raise ValueError('the name of this certificate is not known - give it (Its name…)')
            acme_care_set(h.store, target, True, s['name'], 'ordered by hand')
            acme_start(h.store, [(target, name)], s['name'])
            return dict(acme_view(h.store), message='the certificate of %s is being ordered' % name)
        if act == 'dns_check':
            return acme_dns_check(h.store)
        if act == 'put_back':
            target = str(b.get('target') or '')
            if target not in tls_targets(h.store):
                raise ValueError('there is no such certificate')
            acme_put_back(h.store, target, s['name'])
            return dict(acme_view(h.store), message='the certificate from before ACME is back; '
                        'the nodes put it in within a few seconds')
        if act == 'care':
            target = str(b.get('target') or '')
            if target not in tls_targets(h.store):
                raise ValueError('there is no such certificate')
            acme_care_set(h.store, target, bool(b.get('on')), s['name'])
            return acme_view(h.store)
        if act == 'probe':
            return acme_probe(h.store, str(b.get('target') or ''))
        if act == 'name':
            # Every certificate's name from one page (1.0.170): the other
            # node's and the VIP address's too, not only this node's.
            target = str(b.get('target') or '')
            name = str(b.get('name') or '').strip().lower().rstrip('.')
            if name and not re.match(r'^(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+'
                                     r'[a-z]{2,63}\Z', name):
                raise ValueError('%s is not a full DNS name (like otp2.example.cz)' % name[:80])
            if target == 'vip':
                if not vip_conf(h.store).get('address'):
                    raise ValueError('the VIP address is not set up (Settings → High availability)')
                vip_set(h.store, s['name'], fqdn=name)
            elif target in tls_targets(h.store):
                h.d.save_settings({'acme_node_name': name}, by=s['name'], node=target)
            else:
                raise ValueError('there is no such certificate')
            h.store.add_event('settings', '%s: the certificate of %s is for %s' % (
                s['name'], 'the VIP address' if target == 'vip' else target,
                name or 'its full host name'), who=s['name'])
            return acme_view(h.store)
        if act in ('manual_done', 'manual_drop'):
            # The TXT record put in by hand (1.0.169) - or the order given up.
            got = _meta_json(h.store, 'acme:manual') or {}
            if not got.get('id'):
                raise ValueError('no order waits for a TXT record now')
            if act == 'manual_done':
                got['done'] = time.time()
                h.store.set_meta('acme:manual', json.dumps(got))
            else:
                h.store.db.run("DELETE FROM meta WHERE k = 'acme:manual'")
            h.store.add_event('settings', '%s said the TXT record %s %s' % (
                s['name'], got.get('rr'), 'is in DNS' if act == 'manual_done' else
                'will not be put in - the order is given up'), who=s['name'])
            return acme_view(h.store)
        if act == 'forget':
            h.store.db.run("DELETE FROM meta WHERE k = 'acme:account'")
            h.store.add_event('settings', '%s forgot the account at the ACME CA - a new one is '
                              'made at the next order' % s['name'], 'warn', who=s['name'])
            return acme_view(h.store)
    except (ValueError, AcmeError) as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'no such thing to do')




# ======== carried over from OTP 1.0.187 (lines 43682-43734): console at login ========
def console_login_view(store):
    nodes = [node_name()] + [n['name'] for n in ha_nodes(store) if n['name'] != node_name()]
    out = []
    for n in nodes:
        now = _meta_json(store, 'console:now:' + n) or {}
        want = _meta_json(store, 'console:want:' + n) or {}
        out.append({'name': n, 'me': n == node_name(), 'on': now.get('on'),
                    'at': now.get('at'), 'error': now.get('error') or '',
                    'pending': bool(want) and want.get('id') != now.get('done')})
    return {'nodes': out}


def console_login_ask(store, node, on, by):
    known = [node_name()] + [n['name'] for n in ha_nodes(store)]
    if node not in known:
        raise ValueError('there is no node %s' % node)
    store.set_meta('console:want:' + node, json.dumps({
        'id': secrets.token_hex(6), 'on': bool(on), 'by': by, 'at': time.time()}))
    store.add_event('settings', ('%s switched on the upsmon console at login on %s' if on else
                                 '%s switched off the upsmon console at login on %s') % (by, node),
                    'warn', who=by)


def console_login_tick(daemon):
    """Every few seconds: a switch asked for this node done; how it is, said."""
    store = daemon.store
    me = node_name()
    want = _meta_json(store, 'console:want:' + me) or {}
    now = _meta_json(store, 'console:now:' + me) or {}
    if want and want.get('id') != now.get('done') and not CONSOLE_WORK['busy']:
        CONSOLE_WORK['busy'] = True

        def go():
            try:
                err = ''
                try:
                    root_ask('console.ask', 'console.json',
                             {'do': 'set', 'on': bool(want.get('on'))}, 60)
                except ValueError as e:
                    err = str(e)[:300]
                    log('the console at login could not be switched: %s' % err, 'warn')
                store.set_meta('console:now:' + me, json.dumps({
                    'on': console_at_login(), 'at': time.time(), 'done': want.get('id'),
                    'error': err}))
            finally:
                CONSOLE_WORK['busy'] = False
        threading.Thread(target=go, name='upsmon-console-login', daemon=True).start()
        return
    if time.time() - CONSOLE_WORK['seen'] > 60 and not CONSOLE_WORK['busy']:
        CONSOLE_WORK['seen'] = time.time()
        on = console_at_login()
        if now.get('on') != on or 'on' not in now:
            store.set_meta('console:now:' + me, json.dumps(dict(now, on=on, at=time.time())))


# ======== carried over from OTP 1.0.187 (lines 43752-44047): colour, tables, passwords asked ========
# ---------------------------------------------------------------------------
# Colour - as isemon does it
# ---------------------------------------------------------------------------
# colorama when it is installed, and the same escape sequences written by hand
# when it is not. A nicety, never a dependency: a server being put right at two
# in the morning is not the one to find that the token server will not start
# because a colour library is missing. colorama adds a Windows console, a
# terminal reset however the program ends, and nothing else on Linux.
try:
    import colorama
    from colorama import Fore as _Fore, Style as _Style
    HAVE_COLORAMA = True
except Exception:                       # not installed, or installed broken
    colorama = None
    HAVE_COLORAMA = False

    class _Fore(object):
        RED = '\033[31m'; GREEN = '\033[32m'; YELLOW = '\033[33m'
        BLUE = '\033[34m'; MAGENTA = '\033[35m'; CYAN = '\033[36m'
        WHITE = '\033[37m'; RESET = '\033[39m'

    class _Style(object):
        BRIGHT = '\033[1m'; DIM = '\033[2m'; NORMAL = '\033[22m'
        RESET_ALL = '\033[0m'

_COLORAMA_READY = False


def write_private(path, text):
    """A file only root reads, so from its first byte (1.0.94)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def start_colour():
    global _COLORAMA_READY
    if _COLORAMA_READY or not HAVE_COLORAMA:
        return
    _COLORAMA_READY = True
    try:
        if hasattr(colorama, 'just_fix_windows_console'):
            colorama.just_fix_windows_console()
        else:
            colorama.init()
    except Exception:
        pass


ANSI = re.compile(r'\033\[[0-9;]*m')
TERM_CTL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')


def term_safe(text):
    """What came from outside, safe on a terminal (1.0.139): a User-Name or a
    reason from a packet carried escapes that cleared the screen, set the
    title or wrote the clipboard. Colours are kept; any other control
    character is shown as \\xNN."""
    t = str(text)
    out, at = [], 0
    for m in ANSI.finditer(t):
        out.append(TERM_CTL.sub(lambda c: '\\x%02x' % ord(c.group(0)), t[at:m.start()]))
        out.append(m.group(0))
        at = m.end()
    out.append(TERM_CTL.sub(lambda c: '\\x%02x' % ord(c.group(0)), t[at:]))
    return ''.join(out)


def plain_len(text):
    """How wide something looks, the colour taken out."""
    return len(ANSI.sub('', str(text)))


def plain_pad(text, width):
    return str(text) + ' ' * max(0, width - plain_len(text))


class Palette(object):
    """Every colour the command line uses, in one place."""

    def __init__(self, on):
        self.on = bool(on)
        if self.on:
            start_colour()

        def code(*parts):
            return ''.join(parts) if self.on else ''

        self.c_ok = code(_Fore.GREEN)
        self.c_warn = code(_Fore.YELLOW)
        self.c_bad = code(_Style.BRIGHT, _Fore.RED)
        self.c_info = code(_Fore.CYAN)
        self.c_head = code(_Style.BRIGHT, _Fore.CYAN)
        self.c_key = code(_Fore.WHITE)
        self.c_addr = code(_Fore.MAGENTA)
        self.c_hi = code(_Style.BRIGHT)
        self.c_dim = code(_Style.DIM)
        self.off = code(_Style.RESET_ALL)
        try:
            self.width = max(60, min(120, shutil.get_terminal_size((100, 24)).columns))
        except Exception:
            self.width = 100

    def paint(self, text, colour):
        if not self.on or not colour:
            return str(text)
        return '%s%s%s' % (colour, text, self.off)

    def good(self, t):
        return self.paint(t, self.c_ok)

    def bad(self, t):
        return self.paint(t, self.c_bad)

    def warn(self, t):
        return self.paint(t, self.c_warn)

    def info(self, t):
        return self.paint(t, self.c_info)

    def dim(self, t):
        return self.paint(t, self.c_dim)

    soft = dim

    def head(self, t):
        return self.paint(t, self.c_head)

    def bold(self, t):
        return self.paint(t, self.c_hi)

    hi = bold

    def addr(self, t):
        return self.paint(t, self.c_addr)

    def ok_line(self, t):
        return (self.good('✔ ') if self.on else '[ ok ] ') + str(t)

    def warn_line(self, t):
        return (self.warn('! ') if self.on else '[warn] ') + str(t)

    def bad_line(self, t):
        return (self.bad('✘ ') if self.on else '[fail] ') + str(t)


def colour_wanted(no_color=False, stream=None):
    """What the person asked for, then NO_COLOR, then FORCE_COLOR, then the
    terminal itself - in that order, as isemon decides it."""
    if no_color or os.environ.get('NO_COLOR') is not None:
        return False
    if os.environ.get('FORCE_COLOR') or os.environ.get('CLICOLOR_FORCE'):
        return True
    if str(os.environ.get('TERM') or '').lower() in ('dumb', '') \
            and not os.environ.get('TERM_PROGRAM'):
        return False
    try:
        return bool((stream or sys.stdout).isatty())
    except Exception:
        return False


# ---- colour in every output (1.0.132) ---------------------------------------------
# With colour on, every table and every line the command line prints is
# coloured the same way - tables by their cells, other lines as they read:
# "key: value", addresses, times, and the words that say how a thing is.
# Whatever already carries its own colour is left as it is.
TABLE_PAL = None
TONE_GOOD = {'on', 'yes', 'active', 'ok', 'accept', 'accepted', 'running', 'answering',
             'in place', 'in service', 'done', 'synchronised', 'healthy', 'up', 'enabled',
             'signed in', 'good', 'valid', 'sent', 'taken', 'checked'}
TONE_BAD = {'off', 'no', 'reject', 'rejected', 'failed', 'fail', 'error', 'gone', 'down',
            'locked', 'locked out', 'expired', 'not answering', 'inactive', 'dead', 'disabled',
            'refused', 'missing', 'broken', 'lost', 'crit'}
TONE_WARN = {'pending', 'waiting', 'maintenance', 'in maintenance', 'paused', 'warn',
             'warning', 'not set up', 'unknown', 'stale', 'not yet'}
TONE_DIM = {'never', '-', '–', '(none)', 'none', 'as they come', 'not set', ''}
RE_ADDR = re.compile(r'(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?::\d{1,5})?)(?![\w.])')
RE_TIME = re.compile(r'\b(\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2})([ T]\d{2}:\d{2}(?::\d{2})?)?\b')


def tone_cell(text, pal):
    """One value coloured by what it says."""
    t = str(text)
    if not pal or not pal.on or ANSI.search(t):
        return t
    low = t.strip().lower()
    if low in TONE_GOOD:
        return pal.good(t)
    if low in TONE_BAD:
        return pal.bad(t)
    if low in TONE_WARN:
        return pal.warn(t)
    if low in TONE_DIM:
        return pal.dim(t)
    if RE_TIME.fullmatch(t.strip()):
        return pal.dim(t)
    return tone_words(t, pal)


def tone_words(t, pal):
    """Addresses and times inside a text."""
    t = RE_ADDR.sub(lambda m: pal.addr(m.group(1)), t)
    return RE_TIME.sub(lambda m: pal.dim(m.group(0)), t)


def _cut(text, width):
    """`text` no wider than `width` on the screen, its colour kept or - when it
    has to be cut - taken off."""
    if plain_len(text) <= width:
        return text
    return ANSI.sub('', text)[:width]


def table(rows, heads, widths=None):
    if not rows:
        return '  (none)'
    pal = TABLE_PAL
    cells = [[tone_cell(term_safe(c), pal) for c in r] for r in rows]
    cols = list(zip(*([heads] + [[str(c) for c in r] for r in cells])))
    w = widths or [min(48, max(plain_len(x) for x in col)) for col in cols]
    head = '  ' + '  '.join(h.upper().ljust(w[i]) for i, h in enumerate(heads))
    out = [pal.head(head) if pal and pal.on else head]
    for r in cells:
        out.append('  ' + '  '.join(plain_pad(_cut(str(c), w[i]), w[i])
                                    for i, c in enumerate(r)))
    return '\n'.join(out)


class ColourOut(object):
    """stdout, every line coloured on its way out unless it is already."""
    LINE_KV = re.compile(r'^(\s*)([A-Za-z][\w .()/\'-]{0,40}?)(:\s+|\s{2,})(\S.*)$')

    def __init__(self, stream, pal):
        self.s, self.pal, self.buf = stream, pal, ''

    def _line(self, ln):
        p = self.pal
        ln = term_safe(ln)
        if not p.on or not ln.strip() or ANSI.search(ln):
            return ln
        m = self.LINE_KV.match(ln)
        if m and not ln.lstrip().startswith(('$', '#')):
            return '%s%s%s%s' % (m.group(1), p.info(m.group(2)), m.group(3),
                                 tone_cell(m.group(4), p))
        return tone_words(ln, p)

    def write(self, text):
        self.buf += str(text)
        if '\n' in self.buf:
            done, self.buf = self.buf.rsplit('\n', 1)
            self.s.write('\n'.join(self._line(x) for x in done.split('\n')) + '\n')
        return len(text)

    def flush(self):
        if self.buf:
            self.s.write(self.buf)
            self.buf = ''
        self.s.flush()

    def __getattr__(self, name):
        return getattr(self.s, name)


def ask_password(prompt='password', twice=True, env='UPSMON_PASSWORD'):
    # Each secret its own variable (1.0.139): UPSMON_PASSWORD, set for an
    # account, became a client's shared secret.
    said = os.environ.get(env) if env else None
    if said:
        return said
    first = getpass.getpass('%s: ' % prompt)
    if twice:
        again = getpass.getpass('and again: ')
        if first != again:
            raise SystemExit('those two are not the same')
    return first


def not_on_command_line(what, value, how):
    """A secret written out on the command line is refused (1.0.187): ps, the
    shell's history and the process accounting all keep it. - asks for it."""
    if value not in (None, '', '-') and not str(value).startswith('@env'):
        raise SystemExit('upsmon: %s is not taken on the command line, where ps and the shell\'s '
                         'history keep it: %s' % (what, how))


def ask_secret_value(key):
    """KEY=- of --set: from UPSMON_VALUE_<KEY>, else asked (twice), else one line of stdin."""
    env = 'UPSMON_VALUE_' + key.upper()
    if os.environ.get(env):
        return os.environ[env]
    if sys.stdin.isatty():
        return ask_password(key, twice=True, env=None)
    return sys.stdin.readline().rstrip('\r\n')



# ======== carried over from OTP 1.0.187 (lines 44049-44148): the help, in two columns and in colour ========
class HelpfulParser(argparse.ArgumentParser):
    """An ArgumentParser whose help is isemon's: two columns, in colour.
    Anything going wrong in the drawing falls back to argparse's own."""
    palette = None

    def format_help(self):
        try:
            return help_text(self, self.palette or Palette(False))
        except Exception:
            return super(HelpfulParser, self).format_help()

    def error(self, message):
        pal = self.palette or Palette(False)
        sys.stderr.write('%s\n' % pal.bad_line(message))
        sys.stderr.write(pal.dim('try:  upsmon --help') + '\n')
        raise SystemExit(2)


def help_option_words(action):
    names = ', '.join(action.option_strings)
    if action.nargs == 0:
        return names, ''
    if action.metavar:
        meta = ' '.join(action.metavar) if isinstance(action.metavar, tuple) else action.metavar
    elif action.choices:
        meta = '{%s}' % ','.join(str(c) for c in action.choices)
    else:
        meta = action.dest.upper()
    if action.nargs in ('+', '*'):
        meta += ' ...'
    return names, meta


def help_text(parser, pal):
    """The whole of --help, in the width of this terminal."""
    import textwrap
    width = pal.width
    out = ['%s %s' % (pal.head('upsmon'), pal.bold(__version__)),
           pal.dim('monitoring, history and control of a UPS over NUT, a Shelly plug and sensors - '
                   'and Settings on the engine of OTP'),
           '',
           '%s upsmon %s' % (pal.paint('usage:', pal.c_key), pal.dim('[--json] [--no-color] '
                                                                     '[what to do]')),
           pal.dim('       upsmon shelly ... is the Shelly toolkit (upsmon shelly --help); '
                   'with nothing at all it runs the daemon')]
    every = [a for g in parser._action_groups for a in g._group_actions]
    left = min(34, max([len(' '.join(x for x in help_option_words(a) if x))
                        for a in every] or [20]) + 2)
    for group in parser._action_groups:
        actions = [a for a in group._group_actions if a.help != argparse.SUPPRESS]
        if not actions:
            continue
        out.append('')
        out.append(pal.head((group.title or '').upper()))
        if group.description:
            for line in textwrap.wrap(group.description, width - 2):
                out.append('  ' + pal.dim(line))
        for action in actions:
            names, meta = help_option_words(action)
            painted = pal.good(names) + (' ' + pal.warn(meta) if meta else '')
            says = action.help or ''
            if (action.default not in (None, False, '', argparse.SUPPRESS)
                    and action.nargs != 0 and action.default != []
                    and '[%s]' % action.default not in says):
                says += ' [%s]' % action.default
            lines = textwrap.wrap(says, max(24, width - left - 4)) or ['']
            if plain_len(painted) > left:
                out.append('  ' + painted)
                lines_at = 0
            else:
                out.append('  %s  %s' % (plain_pad(painted, left), lines[0]))
                lines_at = 1
            for more in lines[lines_at:]:
                out.append('  %s  %s' % (' ' * left, more))
    out.append('')
    out.append(pal.head('THINGS PEOPLE ACTUALLY TYPE'))
    wide = min(36, max(len(c.split('\n')[0]) for c, _ in HELP_EXAMPLES) + 2)
    for command, says in HELP_EXAMPLES:
        first, *rest = command.split('\n')
        if len(first) + 2 > wide:
            out.append('  ' + pal.info(first) + ('' if rest or not says else ''))
            for r in rest:
                out.append('  ' + pal.info(r))
            if says:
                out.append('  %s  %s' % (' ' * wide, pal.dim(says)))
        else:
            out.append('  %s%s' % (plain_pad(pal.info(first), wide), pal.dim(says)))
            for r in rest:
                out.append('  ' + pal.info(r))
    out.append('')
    for note in ('the pages are at https://<this machine>/ (the dashboard) and /settings/ · '
                 'the configuration is %s' % CONFIG_FILE,
                 'with nothing at all it is the daemon, as systemd runs it; only one runs at a time',
                 'colour is off when this is piped, and with --no-color or NO_COLOR=1'
                 + ('' if HAVE_COLORAMA else ' (colorama is not installed; colour is '
                                             'written by hand)')):
        for line in textwrap.wrap(note, width - 4):
            out.append('  ' + pal.dim(line))
    out.append('')
    return '\n'.join(out)


# ======== carried over from OTP 1.0.187 (lines 40666-43641): the console ========
import textwrap
import collections
# In /etc itself, where only root writes (1.0.136) - not in /etc/upsmon, whose
# group the daemon's account is in.
CONSOLE_PROFILE = Path('/etc/profile.d/zz-upsmon-console.sh')


class ConsoleBack(Exception):
    """Back to the menu."""


class Console(object):
    def __init__(self, pal):
        self.pal = pal
        self.me = os.path.abspath(sys.argv[0] if sys.argv and sys.argv[0].endswith('.py')
                                  else __file__)
        try:
            __import__('readline')     # arrows and history in input()
        except ImportError:
            pass

    # ---- small things ---------------------------------------------------------------
    def cmd(self, *args, show=True):
        """`upsmon ARGS`, its output on the screen; its exit code."""
        argv = otp_argv(self.me) + [str(a) for a in args]
        if not self.pal.on:
            argv.append('--no-color')
        if show:
            print(self.pal.dim('$ upsmon ' + ' '.join(self._quote(a) for a in args)))
        try:
            return subprocess.call(argv)
        except KeyboardInterrupt:
            print()
            return 130

    def out(self, *args):
        """`upsmon ARGS --json`, read."""
        try:
            got = subprocess.run(otp_argv(self.me) + [str(a) for a in args] + ['--json'],
                                 capture_output=True, text=True, timeout=60)
            return json.loads(got.stdout or 'null')
        except Exception:                               # noqa: BLE001
            return None

    @staticmethod
    def _quote(a):
        a = str(a)
        return a if re.match(r'^[A-Za-z0-9_@%+=:,./-]+\Z', a) else "'%s'" % a.replace("'", "'\\''")

    # ---- keys on the ordinary terminal: Esc goes back everywhere (1.0.132) ---------
    def _raw(self):
        """The terminal's settings, to be put back; None without a terminal."""
        try:
            import termios
            return termios.tcgetattr(sys.stdin.fileno())
        except Exception:                               # noqa: BLE001
            return None

    def _restore(self, was):
        if was is None:
            return
        import termios
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, was)

    def key(self, wait=None):
        """One key, without Enter: 'esc', 'enter', 'bs', 'up'..., a character -
        or None when `wait` seconds went by without one."""
        import select
        import tty
        fd = sys.stdin.fileno()
        was = self._raw()
        try:
            if was is not None:
                # TCSANOW: what was typed ahead is kept, not thrown away.
                import termios
                tty.setcbreak(fd, termios.TCSANOW)
            r, _w, _x = select.select([fd], [], [], wait)
            if not r:
                return None
            ch = os.read(fd, 1)
            if ch == b'\x1b':
                # Alone, Esc; followed at once by more, a key's sequence.
                r, _w, _x = select.select([fd], [], [], 0.05)
                if not r:
                    return 'esc'
                rest = os.read(fd, 8)
                full = {b'[5~': 'pgup', b'[6~': 'pgdn', b'[1~': 'home', b'[4~': 'end',
                        b'[7~': 'home', b'[8~': 'end', b'[H': 'home', b'[F': 'end',
                        b'OH': 'home', b'OF': 'end'}.get(rest)
                if full:
                    return full
                return {b'[A': 'up', b'[B': 'down', b'[C': 'right', b'[D': 'left', b'OA': 'up',
                        b'OB': 'down', b'OC': 'right', b'OD': 'left'}.get(rest[:2], 'seq')
            if ch in (b'\r', b'\n'):
                return 'enter'
            if ch in (b'\x7f', b'\x08'):
                return 'bs'
            if ch == b'\x03':
                return 'ctrl-c'
            if ch == b'\x04':
                return 'ctrl-d'
            if ch == b'\x15':
                return 'ctrl-u'
            try:
                return ch.decode('utf-8')
            except UnicodeDecodeError:
                more = ch
                while len(more) < 4:
                    more += os.read(fd, 1)
                    try:
                        return more.decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                return ''
        finally:
            self._restore(was)

    def ask(self, words, default='', secret=False):
        """A line typed; Esc (or Ctrl+C) goes back to the menu. A secret shows
        a star for each character, never the characters."""
        p = self.pal
        hint = (' [%s]' % default) if default else ''
        prompt = '  %s%s: ' % (p.info(words), p.dim(hint))
        if self._raw() is None:
            try:
                got = input(prompt)
            except EOFError:
                raise ConsoleBack()
            return got.strip() or default
        sys.stdout.write(prompt)
        sys.stdout.flush()
        got = ''
        while True:
            k = self.key()
            if k in ('esc', 'ctrl-c', 'ctrl-d'):
                sys.stdout.write(p.dim('  (back)') + '\n')
                sys.stdout.flush()
                raise ConsoleBack()
            if k == 'enter':
                sys.stdout.write('\n')
                sys.stdout.flush()
                return got.strip() or default
            if k == 'bs':
                if got:
                    got = got[:-1]
                    sys.stdout.write('\b \b')
            elif k == 'ctrl-u':
                sys.stdout.write('\b \b' * len(got))
                got = ''
            elif k and len(k) == 1 and k.isprintable():
                got += k
                sys.stdout.write('*' if secret else k)
            sys.stdout.flush()

    def yes(self, words):
        return self.ask(words + ' (y/N)').lower() in ('y', 'yes', 'a', 'ano')

    def pause(self):
        sys.stdout.write(self.pal.dim('\n  Enter or Esc - back to the menu '))
        sys.stdout.flush()
        if self._raw() is None:
            try:
                input()
            except EOFError:
                pass
            return
        while self.key() not in ('enter', 'esc', 'ctrl-c', 'ctrl-d', 'q'):
            pass
        sys.stdout.write('\n')

    def stopped(self, wait):
        """In a live view: True when Esc, q or Ctrl+C was pressed within
        `wait` seconds."""
        if self._raw() is None:
            time.sleep(wait)
            return False
        return self.key(wait) in ('esc', 'q', 'ctrl-c', 'ctrl-d')

    def clear_screen(self):
        if sys.stdout.isatty():
            sys.stdout.write('\033[H\033[2J')
            sys.stdout.flush()

    # ---- the menus: a text screen, arrows and Enter (1.0.131) ----------------------
    # curses: only what changed is written, so nothing blinks; a window made
    # bigger or smaller (PuTTY's too) is drawn again to its new size. Leaving it
    # for a command's output and coming back is the one full redraw.
    HELP = ' Up/Down move   Enter choose   Esc back   ! shell   q leave '

    def status_thread(self):
        """The line at the top, asked for again every 20 s off the screen's
        thread - the menu never waits for it."""
        def look():
            vip, vip_at = None, 0.0
            while not self.closing:
                # Nothing asked while nobody sees the bar (1.0.136): in a live
                # view, a page or a shell - asked again on the way back.
                if self.plain and not self.st_now:
                    time.sleep(0.5)
                    continue
                self.st_now = False
                st = self.out('--console-status') or {}
                active = '?'
                if shutil.which('systemctl'):
                    try:
                        active = subprocess.run(['systemctl', 'is-active', 'upsmon'],
                                                capture_output=True, text=True,
                                                timeout=10).stdout.strip() or '?'
                    except Exception:                   # noqa: BLE001
                        pass
                if time.time() - vip_at > 60 or getattr(self, 'vip_now', False):
                    self.vip_now = False
                    vip, vip_at = self.vip_where(), time.time()
                self.st = dict(st, _active=active, _vip=vip)
                self.st_gen += 1
                for _ in range(60):
                    if self.closing or self.st_now:
                        break
                    time.sleep(0.5)
        threading.Thread(target=look, name='upsmon-console-status', daemon=True).start()

    def vip_where(self):
        """The VIP address (VRRP) and which node holds it now (1.0.135):
        {'address', 'on', 'holders': [nodes]} - or None when there is none."""
        return None
        got = self.out('--web-status') or {}
        vip = got.get('vip') or {}
        if not isinstance(vip, dict) or not vip.get('address'):
            return None
        holders = [n for n, v in sorted((got.get('nodes') or {}).items())
                   if isinstance(v, dict) and (v.get('vip_here') or v.get('role') == 'MASTER')]
        return {'address': str(vip['address']).split('/')[0], 'on': bool(vip.get('on')),
                'holders': holders}

    def _put(self, y, x, text, attr=0):
        try:
            h, w = self.scr.getmaxyx()
            if y < 0 or y >= h or x >= w:
                return
            self.scr.addnstr(y, x, str(text), max(0, w - x - (1 if y == h - 1 else 0)), attr)
        except Exception:                               # noqa: BLE001 - the edge
            pass

    def _colours(self):
        c = self.curses
        self.A = {'head': c.A_REVERSE, 'sel': c.A_REVERSE | c.A_BOLD, 'ok': c.A_BOLD,
                  'warn': c.A_BOLD, 'bad': c.A_BOLD, 'dim': c.A_DIM, 'key': c.A_BOLD,
                  'title': c.A_BOLD}
        if not c.has_colors():
            return
        try:
            c.start_color()
            try:
                c.use_default_colors()
                bg = -1
            except Exception:                           # noqa: BLE001
                bg = c.COLOR_BLACK
            c.init_pair(1, c.COLOR_BLACK, c.COLOR_CYAN)
            c.init_pair(2, c.COLOR_BLACK, c.COLOR_GREEN)
            c.init_pair(3, c.COLOR_GREEN, bg)
            c.init_pair(4, c.COLOR_YELLOW, bg)
            c.init_pair(5, c.COLOR_RED, bg)
            c.init_pair(6, c.COLOR_CYAN, bg)
            self.A.update(head=c.color_pair(1), sel=c.color_pair(2) | c.A_BOLD,
                          ok=c.color_pair(3) | c.A_BOLD, warn=c.color_pair(4) | c.A_BOLD,
                          bad=c.color_pair(5) | c.A_BOLD, key=c.color_pair(6) | c.A_BOLD)
        except Exception:                               # noqa: BLE001
            pass

    def draw(self, title, items, sel, top, path):
        scr, A = self.scr, self.A
        scr.erase()
        h, w = scr.getmaxyx()
        st = self.st or {}
        # The bar at the top: what this is, and how it is.
        self._put(0, 0, ' ' * w, A['head'])
        left = ' upsmon %s  %s ' % (__version__, socket.gethostname())
        self._put(0, 0, left, A['head'] | self.curses.A_BOLD)
        active = st.get('_active') or '...'
        svc = ' service %s ' % active
        self._put(0, len(left) + 1, svc, A['sel'] if active == 'active' else
                  (A['head'] if active == '...' else self.curses.A_REVERSE | A['bad']))
        # As --status --json says it (1.0.133): maintenance is {'on': …}, the
        # nodes a list, the tokens counted by state.
        bits = []
        if st.get('ups_words'):
            bits.append(str(st['ups_words']))
        nodes = st.get('nodes') or []
        if len(nodes) > 1:
            alive = sum(1 for n in nodes if n.get('alive'))
            rep_ = st.get('replication') or {}
            bits.append('%d of %d nodes%s' % (alive, len(nodes), (
                ', replication %s' % ('ok' if rep_.get('healthy') else 'NOT ok'))
                if rep_.get('mode') == 'replicated' else ''))
        vip = st.get('_vip')
        vip_bad = False
        if vip:
            if not vip['on']:
                bits.append('VIP off')
            elif vip['holders']:
                bits.append('VIP %s on %s' % (vip['address'], ', '.join(vip['holders'])))
                vip_bad = len(vip['holders']) > 1
            else:
                bits.append('VIP %s on NO node' % vip['address'])
                vip_bad = True
        tok = (st.get('tokens') or {}).get('active')
        if tok is not None:
            bits.append('%s tokens' % tok)
        # Too long for the bar: the tokens give way, then the words get
        # shorter; still too long, it goes on the line under the bar.
        short = [b.replace(' of ', '/').replace('replication', 'repl.')
                 .replace('node ', '', 1 if b.startswith('node ') else 0) for b in bits]
        tries = [bits, bits[:-1] if tok is not None else bits, short[:-1] if tok is not None
                 else short]
        y = 1
        for b in tries:
            right = ' ' + ' | '.join(b) + ' '
            if len(left) + len(svc) + len(right) + 2 < w:
                self._put(0, w - len(right), right, A['head'])
                break
        else:
            self._put(1, 1, ' | '.join(bits[:-1] if tok is not None else bits), A['key'])
            y = 2
        if vip_bad:
            self._put(y, 1, 'the VIP address %s is held by %s' % (
                vip['address'], ', '.join(vip['holders']) if vip['holders'] else 'no node'),
                A['bad'])
            y += 1
        if ((st.get('maintenance') or {}).get('on') if isinstance(st.get('maintenance'), dict)
                else st.get('maintenance') is True):
            why = (st.get('maintenance') or {}).get('why') or ''
            self._put(y, 1, 'THIS SERVER IS IN MAINTENANCE - it is being upgraded%s' % (
                (' (%s)' % why) if why else ''), A['warn'])
            y += 1
        others = [n for n in (st.get('maint_nodes') or []) if str(n) != str(st.get('node'))]
        if others:
            self._put(y, 1, 'in maintenance: %s' % ', '.join(str(n) for n in others), A['warn'])
            y += 1
        for t in st.get('trials') or []:
            left = max(0, int(float(t.get('until') or 0) - time.time()))
            self._put(y, 1, '%s waits to be kept: %d:%02d left (Cluster > Keep or put back)' % (
                'the new network of %s' % t.get('node') if t.get('kind') == 'net'
                else 'the change of the firewall', left // 60, left % 60), A['warn'])
            y += 1
        if st and st.get('daemon_alive') is False:
            self._put(y, 1, 'the daemon is not answering', A['bad'])
            y += 1
        for one in (st.get('problems') or [])[:max(0, min(4, h - 12))]:
            self._put(y, 1, '! ' + str(one), A['warn'])
            y += 1
        y += 1
        self._put(y, 2, path, A['dim'])
        self._put(y, 2 + len(path), title, A['title'])
        y += 2
        # The items, a window of them when the screen is short.
        room = max(1, h - y - 2)
        if sel < top:
            top = sel
        if sel >= top + room:
            top = sel - room + 1
        width = max(20, min(w - 6, max(len(it[1]) for it in items) + 10))
        for n, it in enumerate(items[top:top + room]):
            i = top + n
            line = ' %3s  %s' % (it[0], it[1])
            line = line + ' ' * max(0, width - len(line))
            if i == sel:
                self._put(y + n, 2, line, A['sel'])
            else:
                self._put(y + n, 2, ' %3s' % it[0], A['key'])
                self._put(y + n, 8, it[1])
        if top > 0:
            self._put(y - 1, 4, '^ more', A['dim'])
        if top + room < len(items):
            self._put(y + room, 4, 'v more', A['dim'])
        self._put(h - 1, 0, ' ' * (w - 1), A['head'])
        self._put(h - 1, 0, self.HELP[:w - 1], A['head'])
        scr.noutrefresh()
        return top

    def menu(self, title, items, path=''):
        """items: [(key, words, function[, 'plain'])]; returns 'back' or 'quit'."""
        c = self.curses
        sel, top, typed, typed_at, seen = 0, 0, '', 0.0, -1
        while True:
            if self.plain:
                # Back from a command's screen: drawn whole, once.
                c.reset_prog_mode()
                self.scr.clear()
                self.plain = False
                self.st_now = True
            top = self.draw(title, items, sel, top, path)
            self.curses.doupdate()
            self.backdrop = (lambda _s=sel, _t=top: self.draw(title, items, _s, _t, path))
            seen = self.st_gen
            self.scr.timeout(500)
            while True:
                k = self.scr.getch()
                if k != -1 or self.st_gen != seen:
                    break
                # The window's size looked at too (PuTTY and others whose
                # change is not always told): drawn again to the new one.
                try:
                    size = os.get_terminal_size(sys.__stdout__.fileno())
                    if (size.lines, size.columns) != self.scr.getmaxyx():
                        c.resizeterm(size.lines, size.columns)
                        k = c.KEY_RESIZE
                        break
                except (OSError, ValueError, c.error):
                    pass
            if k == -1:
                continue
            if k == 27:
                # An arrow some terminals send as ESC [ B rather than as the
                # key the terminal description names: read whole here.
                self.scr.nodelay(True)
                k2 = self.scr.getch()
                if k2 in (ord('['), ord('O')):
                    k3 = self.scr.getch()
                    k = {ord('A'): c.KEY_UP, ord('B'): c.KEY_DOWN, ord('C'): c.KEY_RIGHT,
                         ord('D'): c.KEY_LEFT, ord('H'): c.KEY_HOME,
                         ord('F'): c.KEY_END}.get(k3, -1)
                    if k3 in (ord('5'), ord('6')):            # PgUp / PgDn: ESC [ 5 ~
                        self.scr.getch()
                        k = c.KEY_PPAGE if k3 == ord('5') else c.KEY_NPAGE
                    if k == -1:
                        continue
                elif k2 != -1:
                    c.ungetch(k2)
                self.scr.nodelay(False)
            if k == c.KEY_RESIZE:
                try:
                    c.update_lines_cols()
                except Exception:                       # noqa: BLE001
                    pass
                self.scr.clear()
                continue
            if k in (c.KEY_UP, ord('k')):
                sel = (sel - 1) % len(items)
            elif k in (c.KEY_DOWN, ord('j'), 9):
                sel = (sel + 1) % len(items)
            elif k in (c.KEY_HOME, c.KEY_PPAGE):
                sel = 0
            elif k in (c.KEY_END, c.KEY_NPAGE):
                sel = len(items) - 1
            elif k in (27, c.KEY_LEFT, c.KEY_BACKSPACE, 127, 8):
                if path:
                    return 'back'
            elif k in (ord('q'), ord('Q')):
                return 'quit'
            elif k == ord('!'):
                self.go_plain(self.shell)
            elif ord('0') <= k <= ord('9'):
                now = time.time()
                typed = (typed if now - typed_at < 1.0 else '') + chr(k)
                typed_at = now
                hit = [i for i, it in enumerate(items) if it[0] == typed]
                if hit:
                    sel = hit[0]
                    # One that no longer number can grow into: chosen at once.
                    if not any(it[0].startswith(typed) and it[0] != typed for it in items):
                        k = 10
                        typed = ''
            if k in (10, 13, c.KEY_ENTER, c.KEY_RIGHT):
                it = items[sel]
                # Run on the text screen - its questions are windows there
                # (1.0.135); only a view of its own ('plain') leaves it.
                if len(it) > 3 and it[3] == 'plain':
                    r = self.go_plain(it[2])
                else:
                    try:
                        r = it[2]()
                    except ConsoleBack:
                        r = None
                if r == 'quit':
                    return 'quit'

    def go_plain(self, fn):
        """`fn` on the ordinary terminal - a command's output, a question, the
        live log - and back to the screen after it."""
        c = self.curses
        c.def_prog_mode()
        c.endwin()
        self.plain = True
        # A clean screen for it - not what the last command left there.
        if sys.stdout.isatty():
            sys.stdout.write('\033[H\033[2J\033[3J')
            sys.stdout.flush()
        try:
            return fn()
        except ConsoleBack:
            return None
        except KeyboardInterrupt:
            print()
            return None

    def run(self):
        main = [
            ('1', 'The UPS, the plug and the sensors', self.m_ups),
            ('2', 'Status and checks', self.m_status),
            ('3', 'Live log', self.m_live_log),
            ('4', 'Accounts of the settings pages', self.m_accounts),
            ('5', 'Settings', self.m_settings),
            ('6', 'The database and backups', self.m_backups),
            ('7', 'Upgrades', self.m_upgrades),
            ('8', 'The service', self.m_service),
            ('9', 'Certificates, updates, restarts, the time', self.m_ops),
        ]
        os.environ.setdefault('ESCDELAY', '25')     # Esc at once, not after a second
        # Lines and blocks drawn as UTF-8 characters, as PuTTY in UTF-8 shows
        # them - not the line-drawing set, which it draws as letters.
        os.environ.setdefault('NCURSES_NO_UTF8_ACS', '1')
        try:
            import locale
            locale.setlocale(locale.LC_ALL, '')
        except Exception:                               # noqa: BLE001
            pass
        import curses
        self.curses = curses
        self.st, self.st_gen, self.st_now, self.closing, self.plain = {}, 0, False, False, False

        def body(scr):
            self.scr = scr
            try:
                curses.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass
            scr.keypad(True)
            self._colours()
            self.status_thread()
            # It opens on the live log, every line (1.0.135); Esc: the menu.
            if os.environ.get('UPSMON_CONSOLE_START', 'log') == 'log':
                self.go_plain(lambda: self.live_log(''))
            self.menu('Main menu', main)
        try:
            curses.wrapper(body)
        finally:
            self.closing = True
        print(self.pal.dim('  The upsmon console is closed - `upsmon --console` opens it again.'))
        return 0

    def shell(self):
        sh = os.environ.get('SHELL') or '/bin/bash'
        print(self.pal.dim('  A shell - exit (or Ctrl+D) comes back to the upsmon console.'))
        try:
            subprocess.call([sh], env=dict(os.environ, UPSMON_CONSOLE='1'))
        except KeyboardInterrupt:
            pass

    def sub(self, title, items):
        r = self.menu(title, items, path='Main menu > ')
        return 'quit' if r == 'quit' else None

    # ---- long output: a screen of its own, scrolled (1.0.134) -------------------
    # As the fullscreen pickers of video_tools: the terminal is not scrolled, a
    # window (top) into the lines is; each frame is one write (home, each line
    # cleared to its end, the rest cleared) so nothing blinks, and the scroll
    # bar is drawn after it into the last column. Arrows, PgUp/PgDn, Home/End,
    # Space; Esc, q or Enter back. A window made bigger or smaller is drawn
    # again to its size.
    def capture(self, argv, env=None):
        """What a command writes, its colour kept: (text, exit code)."""
        e = dict(os.environ, **(env or {}))
        if self.pal.on:
            e.update(FORCE_COLOR='1', SYSTEMD_COLORS='1')
        e['COLUMNS'] = str(max(60, self._cols() - 2))
        try:
            got = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, env=e, timeout=1800)
            # Made safe here whatever the colour (1.0.146): with colour off the
            # command wrote what a packet carried as it came, and page() put it
            # on root's terminal - the title, the clipboard, the screen.
            return term_safe(got.stdout.decode('utf-8', 'replace')), got.returncode
        except subprocess.TimeoutExpired:
            return 'it took more than 30 minutes and was stopped', 124
        except OSError as ex:
            return str(ex), 127

    @staticmethod
    def _cols():
        try:
            return os.get_terminal_size(sys.__stdout__.fileno()).columns
        except (OSError, ValueError):
            return 100

    @staticmethod
    def _fit(line, width):
        """`line` cut to `width` columns on the screen, its colours kept."""
        out, seen = [], 0
        for part in re.split(r'(\x1b\[[0-9;?]*[A-Za-z])', line):
            if not part:
                continue
            if part.startswith('\x1b['):
                out.append(part)
                continue
            if seen + len(part) > width:
                out.append(part[:max(0, width - seen)])
                out.append('\x1b[0m')
                return ''.join(out)
            out.append(part)
            seen += len(part)
        return ''.join(out) + ('\x1b[0m' if '\x1b[' in line else '')

    def page(self, title, text):
        p = self.pal
        lines = [ln.expandtabs(8).replace('\r', '') for ln in text.rstrip('\n').split('\n')] or ['']
        tty = self._raw() is not None and sys.stdout.isatty()
        if not tty:
            print(text)
            return
        out = sys.stdout
        out.write('\x1b[?1049h\x1b[?25l')
        top, size = 0, None
        try:
            while True:
                try:
                    sz = os.get_terminal_size(sys.__stdout__.fileno())
                    cols, rows = max(40, sz.columns), max(8, sz.lines)
                except OSError:
                    cols, rows = 100, 30
                avail = max(3, rows - 2)
                top = max(0, min(top, max(0, len(lines) - avail)))
                end = min(len(lines), top + avail)
                head = ' %s ' % title
                where = ' %d-%d of %d ' % (top + 1, end, len(lines)) if len(lines) > avail \
                    else ' %d lines ' % len(lines)
                bar = (head + ' ' * max(0, cols - len(head) - len(where)) + where)[:cols]
                foot = (' Up/Down PgUp/PgDn Home/End scroll   Esc, q or Enter back ')[:cols - 1]
                body = [self._fit(ln, cols - 2) for ln in lines[top:end]]
                body += [''] * (avail - len(body))
                frame = ['\x1b[7m' + bar + '\x1b[0m' if p.on else bar] + body + \
                    ['\x1b[7m' + foot + ' ' * max(0, cols - 1 - len(foot)) + '\x1b[0m'
                     if p.on else foot]
                out.write('\x1b[H' + '\n'.join(ln + '\x1b[K' for ln in frame) + '\x1b[J')
                self._scrollbar(2, avail, len(lines), avail, top, cols)
                out.flush()
                size = (cols, rows)
                while True:
                    k = self.key(0.3)
                    if k is not None:
                        break
                    try:
                        sz = os.get_terminal_size(sys.__stdout__.fileno())
                        if (max(40, sz.columns), max(8, sz.lines)) != size:
                            break
                    except OSError:
                        pass
                if k in ('esc', 'q', 'enter', 'ctrl-c', 'ctrl-d'):
                    return
                if k in ('up', 'k'):
                    top -= 1
                elif k in ('down', 'j'):
                    top += 1
                elif k in ('pgup', 'b'):
                    top -= avail - 1
                elif k in ('pgdn', ' ', 'f'):
                    top += avail - 1
                elif k in ('home', 'g'):
                    top = 0
                elif k in ('end', 'G'):
                    top = len(lines)
        finally:
            out.write('\x1b[?25h\x1b[?1049l')
            out.flush()

    def _scrollbar(self, base_row, nrows, total, visible, top, cols):
        if total <= visible or nrows <= 0:
            return
        thumb = max(1, min(nrows, round(nrows * visible / total)))
        span = nrows - thumb
        denom = max(1, total - visible)
        tstart = max(0, min(span, round(span * (top / denom))))
        on = self.pal.on
        parts = ['\x1b[?7l']
        for r in range(nrows):
            hit = tstart <= r < tstart + thumb
            g = '\u2588' if hit else '\u2502'
            if on:
                g = ('\x1b[36m' if hit else '\x1b[2m') + g + '\x1b[0m'
            parts.append('\x1b[%d;%dH%s' % (base_row + r, cols, g))
        parts.append('\x1b[?7h')
        sys.stdout.write(''.join(parts))

    def show(self, *args):
        """`upsmon ARGS`, its output on a screen of its own."""
        # A question left empty is nothing asked for: back to the menu.
        if any(a is None or str(a).strip() == '' for a in args):
            return
        self.clear_screen()
        print(self.pal.dim('  working… $ upsmon ' + ' '.join(self._quote(a) for a in args)))
        argv = otp_argv(self.me) + [str(a) for a in args]
        text, rc = self.capture(argv)
        if rc not in (0, None):
            text += '\n' + self.pal.dim('(it ended with %d)' % rc)
        self.page('$ upsmon ' + ' '.join(self._quote(a) for a in args), text)

    def show_live(self, *args):
        """`upsmon ARGS` straight on the terminal - one that asks something."""
        if any(a is None or str(a).strip() == '' for a in args):
            return
        self.clear_screen()
        self.cmd(*args)
        self.pause()

    # ---- 1 status ---------------------------------------------------------------
    def m_status(self):
        def events():
            got = self.form('Events', [
                {'key': 'n', 'label': 'how many', 'kind': 'number', 'value': '40',
                 'range': (1, 5000), 'need': True},
                {'key': 'q', 'label': 'only with the words', 'help':
                 'Empty: every event. Or a name, a kind (sign-ins, accounts) or a word.'}])
            if got:
                self.act('--audit', '--limit', got['n'], *(['--search', got['q']]
                                                            if got['q'] else []))
        return self.sub('Status and checks', [
            ('1', 'Checks (the daemon, the UPS, the database, the pages)', lambda: self.act('--check')),
            ('2', 'Settings, API latency, database size', lambda: self.act('--diag')),
            ('3', 'Events of the settings pages (sign-ins, accounts, certificates)', events),
        ])

    def m_ups(self):
        def history():
            got = self.form('Recorded samples', [
                {'key': 'r', 'label': 'how far back', 'value': '24h', 'need': True,
                 'help': '6h, 24h, 7d, 30d, 1y'}])
            if got:
                self.act('--history', got['r'])
        return self.sub('The UPS, the plug and the sensors', [
            ('1', 'The UPS now (every variable)', lambda: self.act('--status')),
            ('2', 'What this UPS lets you change', lambda: self.act('--list-rw')),
            ('3', 'The event log of the UPS', lambda: self.act('--events')),
            ('4', 'Self tests', lambda: self.act('--tests')),
            ('5', 'Recorded samples', history),
            ('6', 'The smart plug', lambda: self.act('--plug')),
            ('7', 'The sensors', lambda: self.act('--sensors')),
        ])

    # ---- 2 live log -------------------------------------------------------------
    LOG_TONES = {'error': 'bad', 'crit': 'bad', 'warn': 'warn', 'info': '', 'debug': 'dim'}

    def m_live_log(self):
        self.live(lambda: self.live_log(''))

    # ---- live views: scrolled, and what is typed is a grep (1.0.135) ------------
    # The log, the RADIUS requests and the journal come into one screen of
    # their own: the newest at the bottom, followed while the view is at the
    # end. Up/PgUp/Home scroll back (the view then stays where it is and counts
    # what came meanwhile), End follows again; a bar on the right shows where
    # the window is. Whatever is typed filters the lines as `grep -i` does (a
    # regular expression, or the words as they are when it is not one), the
    # hits marked; Backspace takes a character back, Ctrl+U all of them. Esc
    # clears the filter first, then goes back to the menu.
    LIVE_KEEP = 20000

    def live_log(self, what=''):
        path = LOG_DIR / 'upsmon.log'
        st = {'f': None, 'ino': None}

        def opened():
            # Not through a link, nor stuck on a FIFO (1.0.149): the folder is
            # the upsmon account's, and this is root's console.
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                import stat as _st
                if not _st.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError('not a plain file')
            except OSError:
                os.close(fd)
                raise
            return os.fdopen(fd, 'r', encoding='utf-8', errors='replace')

        def first():
            try:
                f = opened()
            except OSError as e:
                return [self.pal.bad_line('%s cannot be read: %s' % (path, e))]
            st['f'] = f
            st['ino'] = os.fstat(f.fileno()).st_ino
            # Read from near the end only: a log can be gigabytes.
            f.seek(0, 2)
            start = max(0, f.tell() - 2 * 1024 * 1024)
            f.seek(start)
            got = f.read().splitlines()
            # The first line only when reading began inside it (1.0.146): a short
            # log lost its first whole line.
            if start and len(got) > 1:
                got = got[1:]
            return got[-self.LIVE_KEEP:]

        def more():
            f = st['f']
            if f is None:
                return []
            out = []
            while len(out) < 5000:
                ln = f.readline()
                if not ln:
                    break
                out.append(ln.rstrip('\n'))
            if not out:
                try:
                    if os.stat(str(path)).st_ino != st['ino']:      # rotated
                        f.close()
                        st['f'] = opened()
                        st['ino'] = os.fstat(st['f'].fileno()).st_ino
                except OSError:
                    pass
            return out
        try:
            self.live_view('Live log  %s' % path, first, more, self._log_text, what)
        finally:
            if st['f']:
                st['f'].close()

    def journal(self):
        """journalctl -u upsmon -f, in the live view."""
        try:
            pr = subprocess.Popen(['journalctl', '-u', 'upsmon', '-f', '-n', '400', '--no-pager'],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                  errors='replace')
        except OSError as e:
            self.page('journalctl', self.pal.bad_line(str(e)))
            return
        q = collections.deque()

        def pump():
            for ln in pr.stdout:
                q.append(ln.rstrip('\n'))
        threading.Thread(target=pump, daemon=True).start()

        def more():
            out = []
            while q:
                out.append(q.popleft())
            return out

        def paint(ln):
            return self._log_text(ln) if re.match(
                r'^\S+ \S+ (info|warn|error|debug|crit) ', ln) else tone_words(ln, self.pal)
        try:
            self.live_view('journalctl -u upsmon -f', lambda: [], more, paint, '')
        finally:
            pr.terminate()
            try:
                pr.wait(3)
            except Exception:                           # noqa: BLE001
                pr.kill()

    @staticmethod
    def _grep(find):
        """What is typed as `grep -i` takes it: a test of one line."""
        if not find:
            return lambda s: True
        try:
            rx = re.compile(find, re.I)
            return lambda s: rx.search(s) is not None
        except (re.error, OverflowError, RecursionError):   # a{9999999999} too (1.0.139)
            low = find.lower()
            return lambda s: low in s.lower()

    def _mark(self, coloured, find):
        """The hits of `find` shown reversed - in the text between the colours."""
        if not find or not self.pal.on:
            return coloured
        try:
            rx = re.compile(find, re.I)
        except (re.error, OverflowError, RecursionError):
            rx = re.compile(re.escape(find), re.I)
        out = []
        for part in re.split(r'(\x1b\[[0-9;?]*[A-Za-z])', coloured):
            if part.startswith('\x1b['):
                out.append(part)
            elif part:
                out.append(rx.sub(lambda m: '\x1b[7m' + m.group(0) + '\x1b[27m'
                                  if m.group(0) else '', part))
        return ''.join(out)

    @staticmethod
    def _slice(line, start, width):
        """Columns start..start+width of `line` on the screen, its colours kept."""
        out, seen = [], 0
        end = start + width
        for part in re.split(r'(\x1b\[[0-9;?]*[A-Za-z])', line):
            if not part:
                continue
            if part.startswith('\x1b['):
                out.append(part)
                continue
            a, b = seen, seen + len(part)
            if b > start and a < end:
                out.append(part[max(0, start - a):max(0, end - a)])
            seen = b
        return ''.join(out) + ('\x1b[0m' if '\x1b[' in line else '')

    def live_view(self, title, first, more, paint, find=''):
        """The live screen: `first()` the lines there are, `more()` those come
        since (asked a few times a second), `paint(line)` its colours."""
        p = self.pal
        if self._raw() is None or not sys.stdout.isatty():
            for ln in first() + more():
                print(ln)
            return
        import termios
        import tty
        fd = sys.stdin.fileno()
        was = termios.tcgetattr(fd)
        out = sys.stdout
        lines = []                       # (plain, coloured)

        def add(raw):
            for ln in raw:
                ln = term_safe(ln.expandtabs(8).replace('\r', ''))
                col = (paint(ln) if paint else ln) if p.on else self._plain_text(ln)
                lines.append((self._plain_text(col), col))
        add(first())
        test = self._grep(find)
        hits = [i for i, x in enumerate(lines) if test(x[0])]
        top, follow, xoff, new, dirty, size = 0, True, 0, 0, True, None
        tty.setcbreak(fd, termios.TCSANOW)
        out.write('\x1b[?1049h\x1b[?25l')
        try:
            while True:
                came = more()
                if came:
                    n0 = len(lines)
                    add(came)
                    got = [i for i in range(n0, len(lines)) if test(lines[i][0])]
                    hits += got
                    if not follow:
                        new += len(got)
                    if len(lines) > self.LIVE_KEEP * 1.25:
                        cut = len(lines) - self.LIVE_KEEP
                        gone = sum(1 for i in hits if i < cut)
                        del lines[:cut]
                        hits = [i - cut for i in hits if i >= cut]
                        top = max(0, top - gone)
                    dirty = dirty or bool(got)
                try:
                    sz = os.get_terminal_size(sys.__stdout__.fileno())
                    cols, rows = max(40, sz.columns), max(8, sz.lines)
                except OSError:
                    cols, rows = 100, 30
                if (cols, rows) != size:
                    size, dirty = (cols, rows), True
                avail = max(3, rows - 2)
                last = max(0, len(hits) - avail)
                if follow:
                    top = last
                top = max(0, min(top, last))
                if dirty:
                    end = min(len(hits), top + avail)
                    where = (' %d-%d of %d ' % (top + 1, end, len(hits))) if hits else ' 0 '
                    state = ' following ' if follow else (' PAUSED%s ' % (
                        ', %d new below' % new if new else ''))
                    head = ' %s ' % title
                    gp = '  grep -i: %s_ ' % find if find else '  type to grep '
                    right = state + where
                    bar = (head + gp)[:max(0, cols - len(right))]
                    bar = bar + ' ' * max(0, cols - len(bar) - len(right)) + right
                    foot = (' type: grep (any case)  Bksp  Ctrl+U clear   Up/Down PgUp/PgDn '
                            'Home  End: follow   Left/Right  Esc back ')[:cols - 1]
                    body = [self._slice(self._mark(lines[i][1], find), xoff, cols - 2)
                            for i in hits[top:end]]
                    if not hits:
                        body = ['', '   ' + (p.dim('nothing with "%s" yet' % find) if find
                                             else p.dim('nothing yet'))]
                    body += [''] * (avail - len(body))
                    inv = (lambda t: '\x1b[7m' + t + '\x1b[0m') if p.on else (lambda t: t)
                    tone = '\x1b[33m' if (not follow and p.on) else ''
                    frame = [tone + inv(bar[:cols])] + body[:avail] + \
                        [inv(foot + ' ' * max(0, cols - 1 - len(foot)))]
                    out.write('\x1b[H' + '\n'.join(ln + '\x1b[K' for ln in frame) + '\x1b[J')
                    self._scrollbar(2, avail, len(hits), avail, top, cols)
                    out.flush()
                    dirty = False
                k = self.key(0.25)
                if k is None:
                    continue
                dirty = True
                if k in ('esc', 'ctrl-c', 'ctrl-d'):
                    if find and k == 'esc':
                        find = ''
                    else:
                        return
                elif k == 'up':
                    follow, top = False, top - 1
                elif k == 'down':
                    top += 1
                    follow = top >= last
                elif k == 'pgup':
                    follow, top = False, top - (avail - 1)
                elif k == 'pgdn':
                    top += avail - 1
                    follow = top >= last
                elif k == 'home':
                    follow, top = False, 0
                elif k in ('end', 'enter'):
                    follow, new = True, 0
                elif k == 'left':
                    xoff = max(0, xoff - 20)
                    continue
                elif k == 'right':
                    xoff += 20
                    continue
                elif k == 'bs':
                    find = find[:-1]
                elif k == 'ctrl-u':
                    find = ''
                elif k and len(k) == 1 and k.isprintable():
                    find += k
                else:
                    continue
                if k in ('bs', 'ctrl-u', 'esc') or (k and len(k) == 1 and k.isprintable()):
                    test = self._grep(find)
                    hits = [i for i, x in enumerate(lines) if test(x[0])]
                    follow, new = True, 0
                if follow:
                    new = 0
        finally:
            out.write('\x1b[?25h\x1b[?1049l')
            out.flush()
            termios.tcsetattr(fd, termios.TCSADRAIN, was)

    def _log_text(self, ln):
        """One line of the log, coloured (colorama when it is there): the time
        dim, the level by how bad, what it is about in cyan, addresses in
        magenta, accept and reject in green and red, a whole warning in yellow
        and a whole error in red."""
        p = self.pal
        ln = ln.rstrip('\n')
        m = re.match(r'^(\S+ \S+) (\w+)(\s+)(.*)$', ln)
        if not m or not p.on:
            return ln
        lvl, rest = m.group(2), m.group(4)
        tone = self.LOG_TONES.get(lvl, '')
        paint = {'bad': p.bad, 'warn': p.warn, 'dim': p.dim}.get(tone)
        what = re.match(r'^([a-z][a-z -]{1,30}): (.*)$', rest)
        head, body = (what.group(1) + ':', what.group(2)) if what else ('', rest)

        def words(t):
            t = re.sub(r'(\[?[0-9a-fA-F:]*\d{1,3}(?:\.\d{1,3}){3}\]?(?::\d+)?|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b)',
                       lambda x: p.addr(x.group(1)) + (p.c_warn if tone == 'warn' else
                                                       p.c_bad if tone == 'bad' else ''), t)
            t = re.sub(r'\b(accept(?:ed)?|signed in|in place|done|ok)\b',
                       lambda x: p.good(x.group(1)) + (p.c_warn if tone == 'warn' else ''), t)
            t = re.sub(r'\b(reject(?:ed)?|refused|failed|wrong|locked out|not answering)\b',
                       lambda x: p.bad(x.group(1)) + (p.c_warn if tone == 'warn' else ''), t)
            return t
        body = words(body)
        if paint is not None and tone != 'dim':
            body = paint(body)
        elif tone == 'dim':
            body = p.dim(body)
        lv = (paint or p.info)(lvl.ljust(5))
        return '%s %s %s%s' % (p.dim(m.group(1)), lv, p.info(head) + (' ' if head else ''), body)

    def _log_line(self, ln):
        print(self._log_text(ln))

    # ---- 3 live RADIUS ----------------------------------------------------------
    # ---- 5 accounts -------------------------------------------------------------
    ROLES = [('fulladmin', 'fulladmin - everything'),
             ('readonly', 'readonly - looks, changes nothing')]

    def _pw_fields(self):
        return [{'key': 'pw', 'label': 'password', 'kind': 'secret', 'need': True,
                 'help': 'At least 8 characters; only stars are shown.',
                 'check': lambda v, _: None if len(v) >= 8 else 'at least 8 characters'},
                {'key': 'again', 'label': 'again', 'kind': 'secret', 'need': True,
                 'check': lambda v, vals: None if v == vals.get('pw')
                 else 'the two passwords are not the same'}]

    def m_accounts(self):
        def load():
            got = self.out('--users') or {}
            self._mfa_on = bool(got.get('mfa_on')) if isinstance(got, dict) else False
            return self._rows(got, 'users')

        cols = [('account', lambda u: u.get('name'), 24, None),
                ('role', lambda u: u.get('role'), 10, None),
                ('state', lambda u: 'off' if u.get('disabled') else 'on', 5,
                 lambda u: 'dim' if u.get('disabled') else 'ok'),
                ('from', lambda u: u.get('source') or 'local', 9, None),
                ('last in', lambda u: self._when(u.get('last_in')), 16, None),
                ('note', lambda u: u.get('note') or '', 40, lambda u: 'dim')]
        return self.sub('Accounts of the settings pages', [
            ('1', 'Browse them (Enter: what to do with one)',
             lambda: self.pick('Accounts of the settings pages', load, cols, self.account_do)),
            ('2', 'Make one', self.account_new),
        ])

    def account_do(self, u):
        name = u['name']
        local = (u.get('source') or 'local') == 'local'
        opts = []
        if local:
            opts.append(('pw', 'Set its password'))
        opts.append(('role', 'Change its role (now %s)' % u.get('role')))
        opts.append(('on', 'Switch it on again') if u.get('disabled') else
                    ('off', 'Switch it off'))
        if u.get('mfa'):
            opts.append(('mfa', 'Reset its second step (it sets one up again)'))
        opts += [('show', 'Show it all'), ('delete', 'Delete it')]
        what = self.choose(name, opts, '%s, %s, %s' % (u.get('role'), u.get('source') or 'local',
                                                      'off' if u.get('disabled') else 'on'))
        if what == 'pw':
            got = self.form('A new password for %s' % name, self._pw_fields())
            if got:
                self.act('--passwd', name, env={'UPSMON_PASSWORD': got['pw']})
        elif what == 'role':
            r = self.choose('The role of %s' % name, self.ROLES,
                            cur=[x[0] for x in self.ROLES].index(u.get('role'))
                            if u.get('role') in [x[0] for x in self.ROLES] else 0)
            if r and r != u.get('role'):
                self.act('--set-role', name, '--role', r)
        elif what == 'off':
            if self.confirm('Switch off', '%s can no longer sign in to the settings pages.'
                            % name, 'Switch it off'):
                self.act('--disable-user', name)
        elif what == 'on':
            self.act('--enable-user', name)
        elif what == 'mfa':
            if self.confirm('Reset the second step', '%s sets its second step up again at '
                            'its next sign-in.' % name, 'Reset it'):
                self.act('--reset-2fa', name)
        elif what == 'show':
            self.details(name, u, skip=('prefs',))
        elif what == 'delete':
            if self.confirm('Delete', 'The account %s is deleted. This cannot be undone.' % name,
                            'Delete it', danger=True):
                self.act('--del-user', name)

    def account_new(self):
        got = self.form('Make an account', [
            {'key': 'name', 'label': 'name', 'need': True,
             'help': 'What it signs in with: letters, digits, . _ -',
             'check': lambda v, _: None if re.match(r'^[A-Za-z0-9._@-]{1,64}$', v)
             else 'letters, digits and . _ - @ only'},
            {'key': 'role', 'label': 'role', 'kind': 'choice', 'value': 'readonly',
             'options': self.ROLES,
             'help': 'fulladmin may do everything; readonly looks.'}]
            + self._pw_fields())
        if got:
            self.act('--add-user', got['name'], '--role', got['role'],
                     env={'UPSMON_PASSWORD': got['pw']})

    # ---- 6 settings -------------------------------------------------------------
    def m_settings(self):
        def by_key():
            keys = sorted(set(DEFAULTS) | set(TUNABLE))
            key = self.ask_one('Change one by its key', 'the key', help_=(
                'Its key, as `upsmon --settings` shows it - e.g. acme_email, upgrade_check. '
                'Then the same window as in Browse opens.'),
                check=lambda v, _: None if v in keys else 'there is no setting %s' % v)
            if not key:
                return
            row = next((r[1] for r in self._settings_rows() if r[0] == 'set'
                        and r[1]['key'] == key), None)
            if not row:
                self.note('Change one', 'there is no setting %s' % key, 'bad')
                return
            done = self._edit_one(row)
            if done:
                self.note('Change one', done[0], 'bad' if done[1] else 'ok')

        def export():
            got = self.form('Export the settings', [
                {'key': 'file', 'label': 'to the file', 'value': '/root/upsmon-config.json',
                 'need': True, 'help': 'A JSON file; the secrets are left out of it.',
                 'check': lambda v, _: None if v.startswith('/') else 'a full path, from /'}])
            if got:
                self.act('--export-config', got['file'])
        return self.sub('Settings', [
            ('1', 'Browse and change (arrows, Enter)', self.settings_tui),
            ('2', 'Change one by its key', by_key),
            ('3', 'All of them as text', lambda: self.act('--settings')),
        ])

    # ---- 8 cluster --------------------------------------------------------------
    def _nodes(self):
        return [node_name()]

    # ---- settings on the text screen: arrows, Enter, a window to change one (1.0.134)
    PANE_TITLES = [('people', 'Accounts'), ('acme', 'Automatic certificates'),
                   ('upgrade', 'Upgrades'), ('about', 'About and debugging')]

    def _settings_rows(self):
        got = self.out('--settings') or []
        rows = got.get('settings') if isinstance(got, dict) else got
        by = {r['key']: r for r in rows or [] if isinstance(r, dict) and r.get('key')}
        out, seen = [], set()
        for pane, words in self.PANE_TITLES:
            keys = [k for k in PANES.get(pane, []) if k in by]
            if not keys:
                continue
            out.append(('head', words))
            for k in keys:
                out.append(('set', by[k]))
                seen.add(k)
        rest = [k for k in by if k not in seen]
        if rest:
            out.append(('head', 'Everything else'))
            out += [('set', by[k]) for k in rest]
        return out

    @staticmethod
    def _shown(v):
        if v is True:
            return 'on'
        if v is False:
            return 'off'
        return '' if v is None else str(v)

    def _kind(self, key):
        shape = TUNABLE.get(key)
        d = DEFAULTS.get(key)
        if isinstance(d, bool) or shape == (0, 1):
            return 'switch', ['1', '0']
        if isinstance(shape, tuple) and shape and isinstance(shape[0], str):
            return 'choice', [str(x) for x in shape]
        if isinstance(shape, tuple) and len(shape) == 2:
            return 'number', list(shape)
        return 'text', None

    def settings_tui(self):
        c, A = self.curses, self.A
        rows = self._settings_rows()
        if not rows:
            return None
        sel = next(i for i, r in enumerate(rows) if r[0] == 'set')
        top, said, said_bad, find = 0, '', False, ''
        while True:
            if self.plain:
                c.reset_prog_mode()
                self.scr.clear()
                self.plain = False

            def paint():
                nonlocal top
                h, w = self.scr.getmaxyx()
                self.scr.erase()
                self._put(0, 0, ' ' * w, A['head'])
                self._put(0, 0, ' upsmon %s  Settings' % __version__, A['head'] | c.A_BOLD)
                if find:
                    self._put(0, max(0, w - len(find) - 12), ' find: %s ' % find, A['head'])
                avail = max(3, h - 3)
                if sel < top:
                    top = sel
                if sel >= top + avail:
                    top = sel - avail + 1
                top = max(0, min(top, max(0, len(rows) - avail)))
                if top > 0 and rows[top - 1][0] == 'head' and sel - top < avail - 1:
                    top -= 1                    # the group's heading with its first setting
                namew = max(20, min(44, w // 3))
                valw = max(10, min(40, w - namew - 30))
                for n, r in enumerate(rows[top:top + avail]):
                    y = 1 + n
                    if r[0] == 'head':
                        self._put(y, 1, r[1].upper(), A['key'])
                        continue
                    st = r[1]
                    val = self._shown(st.get('value'))
                    line = '  %-*s %-*s %s' % (namew, (st.get('name') or st['key'])[:namew], valw,
                                              val[:valw], st.get('key'))
                    if top + n == sel:
                        self._put(y, 0, line + ' ' * max(0, w - 2 - len(line)), A['sel'])
                    else:
                        self._put(y, 0, '  ' + (st.get('name') or st['key'])[:namew])
                        tone = A['dim'] if st.get('source') == 'default' else A['ok']
                        self._put(y, 3 + namew, val[:valw], tone)
                        self._put(y, 4 + namew + valw, st.get('key'), A['dim'])
                # The bar on the right.
                total = len(rows)
                if total > avail:
                    thumb = max(1, min(avail, round(avail * avail / total)))
                    tstart = max(0, min(avail - thumb, round((avail - thumb) * top
                                                              / max(1, total - avail))))
                    utf = 'utf' in (sys.stdout.encoding or '').lower()
                    for r in range(avail):
                        hit = tstart <= r < tstart + thumb
                        self._put(1 + r, w - 1, ('\u2588' if hit else '\u2502') if utf
                                  else ('#' if hit else '|'), A['key'] if hit else A['dim'])
                if said:
                    self._put(h - 2, 1, said[:w - 2], A['bad'] if said_bad else A['ok'])
                help_ = ' Up/Down PgUp/PgDn Home/End move   Enter change   / find   Esc back '
                self._put(h - 1, 0, ' ' * (w - 1), A['head'])
                self._put(h - 1, 0, help_[:w - 1], A['head'])
                self.scr.noutrefresh()
                return h, avail
            self.backdrop = paint
            h, avail = paint()
            c.doupdate()
            self.scr.timeout(500)
            k = self._getkey()
            if k is None:
                continue
            said = ''
            sets = [i for i, r in enumerate(rows) if r[0] == 'set']
            if k == 'esc':
                if find:
                    find = ''
                    continue
                return None
            if k == 'q':
                return 'quit'
            if k in ('up', 'down', 'pgup', 'pgdn', 'home', 'end'):
                pos = sets.index(sel) if sel in sets else 0
                pos = {'up': pos - 1, 'down': pos + 1, 'pgup': pos - (avail - 2),
                       'pgdn': pos + (avail - 2), 'home': 0, 'end': len(sets) - 1}[k]
                sel = sets[max(0, min(len(sets) - 1, pos))]
            elif k == '/':
                find = self._line_in(h - 2, 'Find (a word of its name or key): ', '') or ''
                if find:
                    hit = [i for i in sets if find.lower() in (
                        str(rows[i][1].get('name')) + ' ' + rows[i][1]['key']).lower()]
                    if hit:
                        sel = hit[0]
                    else:
                        said, said_bad = 'nothing with "%s"' % find, True
            elif k == 'n' and find:
                hit = [i for i in sets if i > sel and find.lower() in (
                    str(rows[i][1].get('name')) + ' ' + rows[i][1]['key']).lower()]
                if hit:
                    sel = hit[0]
            elif k == 'enter':
                done = self._edit_one(rows[sel][1])
                if done:
                    said, said_bad = done
                    if not said_bad:
                        cur = rows[sel][1]['key']
                        rows = self._settings_rows()
                        sel = next((i for i, r in enumerate(rows)
                                    if r[0] == 'set' and r[1]['key'] == cur), sel)

    def _getkey(self, win=None):
        """A key on the text screen, by name: 'up', 'enter', 'esc', or the character."""
        c = self.curses
        src = win or self.scr
        k = src.getch()
        if k == -1:
            # The window's size looked at, as the menus do.
            try:
                size = os.get_terminal_size(sys.__stdout__.fileno())
                if (size.lines, size.columns) != self.scr.getmaxyx():
                    c.resizeterm(size.lines, size.columns)
                    self.scr.clear()
                    return 'resize'
            except (OSError, ValueError, c.error):
                pass
            return None
        if k == 27:
            src.nodelay(True)
            k2 = src.getch()
            if k2 in (ord('['), ord('O')):
                seq = ''
                while True:
                    k3 = src.getch()
                    if k3 == -1:
                        break
                    seq += chr(k3)
                    if chr(k3).isalpha() or chr(k3) == '~':
                        break
                src.nodelay(False)
                return {'A': 'up', 'B': 'down', 'C': 'right', 'D': 'left', 'H': 'home',
                        'F': 'end', '5~': 'pgup', '6~': 'pgdn', '1~': 'home', '4~': 'end',
                        '7~': 'home', '8~': 'end', '3~': 'del'}.get(seq, None)
            if k2 != -1:
                c.ungetch(k2)
            src.nodelay(False)
            return 'esc'
        named = {c.KEY_UP: 'up', c.KEY_DOWN: 'down', c.KEY_LEFT: 'left', c.KEY_RIGHT: 'right',
                 c.KEY_PPAGE: 'pgup', c.KEY_NPAGE: 'pgdn', c.KEY_HOME: 'home', c.KEY_END: 'end',
                 c.KEY_ENTER: 'enter', 10: 'enter', 13: 'enter', c.KEY_BACKSPACE: 'bs',
                 127: 'bs', 8: 'bs', c.KEY_DC: 'del', c.KEY_RESIZE: 'resize', 21: 'ctrl-u',
                 9: 'tab'}
        if k in named:
            if k == c.KEY_RESIZE:
                try:
                    c.update_lines_cols()
                except Exception:                       # noqa: BLE001
                    pass
            return named[k]
        if 0xc0 <= k < 0xf8:
            # getch() gives UTF-8 a byte at a time (1.0.139): "ž" came as two
            # Latin-1 letters, and a password typed here was not the one meant.
            raw = bytearray([k])
            src.nodelay(True)
            try:
                for _ in range(1 if k < 0xe0 else 2 if k < 0xf0 else 3):
                    k2 = src.getch()
                    if not 0x80 <= k2 < 0xc0:
                        break
                    raw.append(k2)
            finally:
                src.nodelay(False)
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return None
        if 32 <= k < 0x110000:
            try:
                return chr(k)
            except ValueError:
                return None
        return None

    def _line_in(self, y, prompt, text, secret=False, win=None, x=1, width=None):
        """A line typed on the text screen: Enter gives it, Esc gives None."""
        c = self.curses
        scr = win or self.scr
        pos = len(text)
        try:
            c.curs_set(1)
        except Exception:                               # noqa: BLE001
            pass
        try:
            while True:
                h, w = scr.getmaxyx()
                room = (width or (w - x - len(prompt) - 2))
                shown = ('*' * len(text)) if secret else text
                start = max(0, pos - room + 1)
                try:
                    scr.addstr(y, x, prompt, self.A['key'])
                    scr.addstr(y, x + len(prompt), shown[start:start + room].ljust(room),
                               self.curses.A_UNDERLINE)
                    scr.move(y, x + len(prompt) + pos - start)
                except c.error:
                    pass
                scr.refresh()
                scr.timeout(500)
                k = self._getkey(scr)
                if k == 'enter':
                    return text
                if k == 'esc':
                    return None
                if k == 'bs' and pos > 0:
                    text = text[:pos - 1] + text[pos:]
                    pos -= 1
                elif k == 'del':
                    text = text[:pos] + text[pos + 1:]
                elif k == 'left':
                    pos = max(0, pos - 1)
                elif k == 'right':
                    pos = min(len(text), pos + 1)
                elif k == 'home':
                    pos = 0
                elif k == 'end':
                    pos = len(text)
                elif k == 'ctrl-u':
                    text, pos = '', 0
                elif k and len(k) == 1 and k.isprintable():
                    text = text[:pos] + k + text[pos:]
                    pos += 1
        finally:
            try:
                c.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass

    def _box(self, win, h, w):
        """A frame round a window, in UTF-8 lines where the terminal takes them."""
        c, A = self.curses, self.A
        if 'utf' in (sys.stdout.encoding or '').lower():
            hz, vt, tl, tr, bl, br = '\u2500', '\u2502', '\u250c', '\u2510', '\u2514', '\u2518'
        else:
            hz, vt, tl, tr, bl, br = '-', '|', '+', '+', '+', '+'
        for y, line in ((0, tl + hz * (w - 2) + tr), (h - 1, bl + hz * (w - 2) + br)):
            try:
                win.addstr(y, 0, line, A['key'])
            except c.error:
                pass                                    # the bottom-right corner
        for y in range(1, h - 1):
            for x in (0, w - 1):
                try:
                    win.addstr(y, x, vt, A['key'])
                except c.error:
                    pass

    def _edit_one(self, st):
        """The window to change one setting: what it is, what it may be, the
        value checked as the daemon checks it before it is saved. Returns
        (words, bad) or None when nothing was done."""
        c, A = self.curses, self.A
        key = st['key']
        if key.startswith(('db_', 'ha_')):
            # Their own steps (1.0.136), as on the pages: a database named
            # here opens empty at the next restart, a cluster is made whole.
            self.note(st.get('name') or key, (
                '%s is changed by the cluster\'s own steps: Settings - High availability on '
                'the pages, or upsmon --ha-setup / --ha-join / --ha-standalone.' % key)
                if key.startswith('ha_') else (
                '%s names the database: it is moved on the pages (Settings - The database: '
                'Try it, Set it up, Carry everything across, Start using it). Only to point at '
                'the same data somewhere new (a moved server, a new password), on the command '
                'line:  upsmon --set %s=%s --yes' % (key, key, '-' if key in SECRET_KEYS else '...')))
            return None
        kind, shape = self._kind(key)
        secret = bool(st.get('secret'))
        cur = self._shown(st.get('value'))
        if kind == 'switch':
            cur = '1' if st.get('value') in (True, 1, '1', 'on') else '0'
        text = '' if secret else cur
        choice = shape.index(cur) if kind in ('switch', 'choice') and cur in (shape or []) else 0
        err = ''
        helptext = re.sub(r'<[^>]+>', '', html.unescape(str(st.get('says') or '')))
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(40, min(96, w - 4))
            body = []
            for para in helptext.split('\n'):
                body += textwrap.wrap(para, ww - 4) or ['']
            facts = ['now: %s%s' % ('(hidden)' if secret else (self._shown(st.get('value')) or '(empty)'),
                                    '' if st.get('source') == 'default' else
                                    '   - %s' % (st.get('source_says') or st.get('source'))),
                     'as it comes: %s' % (self._shown(st.get('default')) or '(empty)')]
            if kind == 'number':
                facts.append('a whole number from %s to %s' % (shape[0], shape[1]))
            elif kind == 'choice':
                facts.append('one of: ' + ', '.join(shape))
            if st.get('file_only'):
                facts.append('kept in config.json on this machine - it takes effect after a restart')
            if st.get('node_key'):
                facts.append('this node\'s own (each node of a cluster has its own)')
            # The help cut to what the screen has room for - the rest always fits.
            fixed = len(facts) + 9 + (len(shape) - 1 if kind == 'choice' else 0)
            body = body[:max(1, h - 2 - fixed)]
            wh = min(h - 2, len(body) + fixed)
            win = c.newwin(wh, ww, max(0, (h - wh) // 2), max(0, (w - ww) // 2))
            win.keypad(True)
            win.erase()
            self._box(win, wh, ww)
            title = ' %s ' % (st.get('name') or key)
            try:
                win.addnstr(0, 2, title, ww - 4, A['title'])
                win.addnstr(1, 2, key, ww - 4, A['dim'])
                y = 2
                for ln in body:
                    win.addnstr(y, 2, ln, ww - 4)
                    y += 1
                y += 1
                for f in facts:
                    win.addnstr(y, 2, f, ww - 4, A['dim'])
                    y += 1
                y += 1
                if err:
                    win.addnstr(wh - 2, 2, err[:ww - 4], ww - 4, A['bad'])
                else:
                    win.addnstr(wh - 2, 2, ('Left/Right choose' if kind in ('switch', 'choice')
                                            else 'type the new value') +
                                '   Enter save   Esc cancel', ww - 4, A['dim'])
            except c.error:
                pass
            if kind in ('switch', 'choice'):
                words = {'1': 'on', '0': 'off'} if kind == 'switch' else {}
                x = 2
                for i, opt in enumerate(shape):
                    lab = ' %s ' % (words.get(opt) or (CHOICE_WORDS.get(key, {}).get(opt) or opt))
                    if kind == 'choice':
                        # One under the other: their words can be long.
                        lab = (' > ' if i == choice else '   ') + lab.strip() + ' '
                        try:
                            win.addnstr(y, 2, lab, ww - 4, A['sel'] if i == choice else 0)
                        except c.error:
                            pass
                        y += 1
                        continue
                    try:
                        win.addnstr(y, x, lab, max(0, ww - x - 2), A['sel'] if i == choice else 0)
                    except c.error:
                        pass
                    x += len(lab) + 1
                win.noutrefresh()
                c.doupdate()
                win.timeout(500)
                k = self._getkey(win)
                if k == 'esc':
                    return None
                if k in ('left', 'up'):
                    choice = (choice - 1) % len(shape)
                elif k in ('right', 'down', 'tab', ' '):
                    choice = (choice + 1) % len(shape)
                elif k == 'enter':
                    value = shape[choice]
                else:
                    continue
                if k != 'enter':
                    continue
            else:
                win.noutrefresh()
                c.doupdate()
                got = self._line_in(y, 'value: ', text, secret=secret, win=win, x=2,
                                    width=ww - 14)
                if got is None:
                    return None
                text = got
                if secret and not got:
                    return ('nothing typed - %s stays as it was' % key, False)
                value = got
            # Checked here as the daemon checks it, then saved by `upsmon --set`.
            try:
                check_setting(key, value)
            except (BadSetting, ValueError, TypeError) as e:
                err = str(e)
                continue
            # A secret goes by the environment, not the command line (1.0.136).
            env = {'UPSMON_VALUE_' + key.upper(): value} if secret else None
            out, rc = self.capture(otp_argv(self.me) + ['--setting', '%s=%s' % (
                key, '@env' if secret else value), '--no-color'], env=env)
            if rc != 0:
                err = (out.strip().splitlines() or ['it was not saved'])[-1]
                continue
            return ('%s = %s - saved%s' % (key, '(hidden)' if secret else value,
                                           '; the running service takes it within seconds'
                                           if not st.get('file_only') else
                                           '; restart the service for it'), False)

    # ---- windows on the text screen for every menu: arrows and Enter (1.0.135) ----
    # Nothing is typed at a bare prompt any more: a question is a window (a
    # form) whose fields are moved between by the arrows, a choice is picked
    # by the arrows, a list (tokens, accounts, clients, files…) is scrolled and
    # Enter on one offers what can be done with it. What is typed is checked
    # before anything is run; Esc closes the window and goes back. The screen
    # under a window is drawn again by `self.backdrop` - so a window made
    # bigger or smaller (PuTTY's too) is drawn right.
    def _fresh(self):
        """Back from a command's own screen: the text screen drawn whole again."""
        if self.plain:
            self.curses.reset_prog_mode()
            self.scr.clear()
            self.plain = False
            self.st_now = True

    def _under(self):
        """The screen under a window, written but not yet shown."""
        self._fresh()
        fn = getattr(self, 'backdrop', None)
        if fn:
            try:
                fn()
                return
            except Exception:                           # noqa: BLE001
                pass
        self.scr.noutrefresh()

    def _window(self, want_h, want_w):
        """A framed window in the middle of the screen; (win, h, w)."""
        c = self.curses
        h, w = self.scr.getmaxyx()
        ww = max(20, min(want_w, w - 2))
        wh = max(5, min(want_h, h - 2))
        win = c.newwin(wh, ww, max(0, (h - wh) // 2), max(0, (w - ww) // 2))
        win.keypad(True)
        win.erase()
        self._box(win, wh, ww)
        return win, wh, ww

    def _wput(self, win, y, x, text, attr=0, width=None):
        try:
            wh, ww = win.getmaxyx()
            if 0 < y < wh - 1 and x < ww - 1:
                win.addnstr(y, x, str(text), max(0, (width or ww) - (x if width is None else 0)
                                                 - (1 if width is None else 0)), attr)
        except self.curses.error:
            pass

    def _wkey(self, win, wait=500):
        win.timeout(wait)
        return self._getkey(win)

    def _wrap(self, text, width):
        out = []
        for para in str(text or '').split('\n'):
            out += textwrap.wrap(para, max(10, width)) or ['']
        return out

    @staticmethod
    def _plain_text(text):
        return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', str(text or ''))

    def note(self, title, text, tone=''):
        """Words in a window; any of Enter, Esc, q or Space closes it."""
        A = self.A
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(30, min(100, w - 4))
            lines = self._wrap(text, ww - 4)[:max(1, h - 6)]
            win, wh, ww = self._window(len(lines) + 4, max(len(title) + 8, min(
                ww, max(len(x) for x in lines + ['']) + 6, ww)))
            self._wput(win, 0, 2, ' %s ' % title, A['title'])
            try:
                win.addnstr(0, 2, ' %s ' % title, ww - 4, A['title'])
            except self.curses.error:
                pass
            for i, ln in enumerate(lines):
                self._wput(win, 1 + i, 2, ln, A.get(tone, 0) if tone else 0)
            self._wput(win, wh - 2, 2, 'Enter or Esc - back', A['dim'])
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ('enter', 'esc', 'q', ' '):
                return

    def working(self, words):
        """A window that says something is being done (the screen waits for it)."""
        self._under()
        win, wh, ww = self._window(3, min(100, len(words) + 6))
        self._wput(win, 1, 2, words, self.A['dim'])
        win.noutrefresh()
        self.curses.doupdate()

    def confirm(self, title, words, yes='Yes', no='No', danger=False):
        """Yes or no, chosen by the arrows (or y / n); No unless chosen."""
        A = self.A
        pick = 1
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(40, min(80, w - 4))
            lines = self._wrap(words, ww - 4)[:max(1, h - 8)]
            win, wh, ww = self._window(len(lines) + 5, ww)
            try:
                win.addnstr(0, 2, ' %s ' % title, ww - 4, A['bad'] if danger else A['title'])
            except self.curses.error:
                pass
            for i, ln in enumerate(lines):
                self._wput(win, 1 + i, 2, ln)
            x = 2
            y = wh - 2
            for i, lab in enumerate((yes, no)):
                lab = '  %s  ' % lab
                self._wput(win, y, x, lab, (A['bad'] if danger and i == 0 else A['sel'])
                           if i == pick else A['key'])
                x += len(lab) + 2
            self._wput(win, y, x + 2, 'Left/Right  Enter  Esc', A['dim'])
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ('esc', 'n', 'N'):
                return False
            if k in ('y', 'Y'):
                return True
            if k in ('left', 'right', 'tab', 'up', 'down'):
                pick = 1 - pick
            elif k == 'enter':
                return pick == 0

    def choose(self, title, options, words='', cur=0):
        """One of `options` ([(value, words)]), picked by the arrows; Esc None."""
        A = self.A
        if not options:
            return None
        sel = max(0, min(cur or 0, len(options) - 1))
        top = 0
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = min(90, w - 4, max(36, max(len(o[1]) for o in options) + 12,
                                    len(title) + 8, len(words) + 6 if words else 0))
            head = self._wrap(words, ww - 4) if words else []
            room = max(1, min(len(options), h - 6 - len(head)))
            win, wh, ww = self._window(room + len(head) + (4 if head else 3), ww)
            try:
                win.addnstr(0, 2, ' %s ' % title, ww - 4, A['title'])
            except self.curses.error:
                pass
            y = 1
            for ln in head:
                self._wput(win, y, 2, ln, A['dim'])
                y += 1
            if head:
                y += 1
            if sel < top:
                top = sel
            if sel >= top + room:
                top = sel - room + 1
            for n, (val, lab) in enumerate(options[top:top + room]):
                i = top + n
                line = ' %2d  %s' % (i + 1, lab)
                if i == sel:
                    self._wput(win, y + n, 2, line.ljust(ww - 5), A['sel'])
                else:
                    self._wput(win, y + n, 2, ' %2d' % (i + 1), A['key'])
                    self._wput(win, y + n, 7, lab)
            if len(options) > room:
                self._wbar(win, y, room, len(options), top, ww - 2)
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ('esc', 'left'):
                return None
            if k == 'q':
                return None
            if k == 'up':
                sel = (sel - 1) % len(options)
            elif k in ('down', 'tab'):
                sel = (sel + 1) % len(options)
            elif k in ('home', 'pgup'):
                sel = 0
            elif k in ('end', 'pgdn'):
                sel = len(options) - 1
            elif k and k.isdigit():
                n = int(k) - 1
                if 0 <= n < len(options):
                    sel = n
                    return options[sel][0]
            elif k in ('enter', 'right'):
                return options[sel][0]

    def _wbar(self, win, y0, rows, total, top, x):
        """The scroll bar on the right of a list in a window."""
        A = self.A
        if total <= rows:
            return
        thumb = max(1, min(rows, round(rows * rows / total)))
        tstart = max(0, min(rows - thumb, round((rows - thumb) * top / max(1, total - rows))))
        utf = 'utf' in (sys.stdout.encoding or '').lower()
        for r in range(rows):
            hit = tstart <= r < tstart + thumb
            try:
                win.addstr(y0 + r, x, ('█' if hit else '│') if utf else
                           ('#' if hit else '|'), A['key'] if hit else A['dim'])
            except self.curses.error:
                pass

    def form(self, title, fields, words='', check=None, ok='OK'):
        """Questions in one window. fields: [{'key', 'label', 'kind': 'text' |
        'secret' | 'choice' | 'number', 'value', 'options': [(value, words)],
        'need': True, 'range': (a, b), 'help', 'check': fn(value, values) ->
        an error or None, 'when': fn(values) -> shown or not}]. Up/Down (Tab)
        move between them, a choice is changed by Left/Right, Enter checks
        them all and gives {key: value}; Esc gives None. A secret shows a star
        for each character, never the characters."""
        c, A = self.curses, self.A
        vals, pos = {}, {}
        for f in fields:
            f.setdefault('kind', 'text')
            if f['kind'] == 'choice':
                opts = [o[0] for o in f['options']]
                vals[f['key']] = f.get('value') if f.get('value') in opts else opts[0]
            else:
                vals[f['key']] = str(f.get('value') if f.get('value') is not None else '')
            pos[f['key']] = len(vals[f['key']]) if f['kind'] != 'choice' else 0
        at, err, err_at = 0, '', None
        try:
            c.curs_set(1)
        except Exception:                               # noqa: BLE001
            pass
        try:
            while True:
                shown = [f for f in fields if not f.get('when') or f['when'](vals)]
                at = max(0, min(at, len(shown) - 1))
                f = shown[at]
                self._under()
                h, w = self.scr.getmaxyx()
                ww = max(50, min(100, w - 4))
                head = self._wrap(words, ww - 4) if words else []
                labw = min(30, max(len(x.get('label') or x['key']) for x in shown) + 1)
                fieldw = max(8, ww - labw - 7)
                helps = self._wrap(f.get('help') or '', ww - 4) if f.get('help') else []
                helps = helps[:4]
                wh = len(head) + (1 if head else 0) + len(shown) + 2 + 4 + 1
                win, wh, ww = self._window(wh, ww)
                try:
                    win.addnstr(0, 2, ' %s ' % title, ww - 4, A['title'])
                except c.error:
                    pass
                y = 1
                for ln in head:
                    self._wput(win, y, 2, ln, A['dim'])
                    y += 1
                if head:
                    y += 1
                cursor = None
                for i, x in enumerate(shown):
                    lab = (x.get('label') or x['key'])[:labw - 1]
                    here = i == at
                    self._wput(win, y, 2, lab.rjust(labw), A['key'] if here else 0)
                    vx = 3 + labw + 1
                    v = vals[x['key']]
                    if x['kind'] == 'choice':
                        words_ = dict(x['options']).get(v, v)
                        txt = ('< %s >' % words_) if here else ('  %s' % words_)
                        self._wput(win, y, vx, txt[:fieldw], A['sel'] if here else A['ok'])
                    else:
                        t = ('*' * len(v)) if x['kind'] == 'secret' else v
                        p = pos[x['key']] if here else len(t)
                        start = max(0, p - fieldw + 1)
                        self._wput(win, y, vx, t[start:start + fieldw].ljust(fieldw),
                                   c.A_UNDERLINE | (A['key'] if here else 0))
                        if here:
                            cursor = (y, vx + p - start)
                    if err and err_at == x['key']:
                        self._wput(win, y, ww - 3, '!', A['bad'])
                    y += 1
                y += 1
                for ln in helps:
                    self._wput(win, y, 2, ln, A['dim'])
                    y += 1
                if err:
                    self._wput(win, wh - 2, 2, err[:ww - 4], A['bad'])
                else:
                    self._wput(win, wh - 2, 2, ('Up/Down field   ' + ('Left/Right choose   '
                               if any(x['kind'] == 'choice' for x in shown) else '') +
                               'Enter %s   Esc cancel' % ok)[:ww - 4], A['dim'])
                if cursor:
                    try:
                        c.curs_set(1)
                        win.move(*cursor)
                    except c.error:
                        pass
                else:
                    try:
                        c.curs_set(0)
                    except Exception:                   # noqa: BLE001
                        pass
                win.noutrefresh()
                c.doupdate()
                k = self._wkey(win)
                if k is None or k == 'resize':
                    continue
                key, kind = f['key'], f['kind']
                if k == 'esc':
                    return None
                if k in ('up',) or (k == 'tab' and False):
                    at = (at - 1) % len(shown)
                elif k in ('down', 'tab'):
                    at = (at + 1) % len(shown)
                elif k == 'enter':
                    err, err_at = '', None
                    for i, x in enumerate(shown):
                        v = vals[x['key']]
                        if x['kind'] != 'choice':
                            v = v.strip() if x['kind'] != 'secret' else v
                            vals[x['key']] = v
                        bad = None
                        if x.get('need') and v == '':
                            bad = '%s - it is needed' % (x.get('label') or x['key'])
                        elif x['kind'] == 'number' and v != '':
                            try:
                                n = int(v)
                                lo, hi = x.get('range') or (None, None)
                                if (lo is not None and n < lo) or (hi is not None and n > hi):
                                    bad = '%s - a whole number from %s to %s' % (
                                        x.get('label') or x['key'], lo, hi)
                            except ValueError:
                                bad = '%s - a whole number' % (x.get('label') or x['key'])
                        if not bad and x.get('check') and v != '':
                            try:
                                bad = x['check'](v, vals)
                            except Exception as e:              # noqa: BLE001
                                bad = str(e)
                        if bad:
                            err, err_at, at = bad, x['key'], i
                            break
                    if err:
                        continue
                    got = {x['key']: vals[x['key']] for x in shown}
                    if check:
                        bad = check(got)
                        if bad:
                            err, err_at = (bad if isinstance(bad, tuple) else (bad, None))
                            if err_at:
                                at = next((i for i, x in enumerate(shown) if x['key'] == err_at),
                                          at)
                            continue
                    return got
                elif kind == 'choice':
                    opts = [o[0] for o in f['options']]
                    i = opts.index(vals[key]) if vals[key] in opts else 0
                    if k in ('left',):
                        vals[key] = opts[(i - 1) % len(opts)]
                    elif k in ('right', ' '):
                        vals[key] = opts[(i + 1) % len(opts)]
                    err = ''
                else:
                    t, p = vals[key], pos[key]
                    if k == 'bs' and p > 0:
                        t, p = t[:p - 1] + t[p:], p - 1
                    elif k == 'del':
                        t = t[:p] + t[p + 1:]
                    elif k == 'left':
                        p = max(0, p - 1)
                    elif k == 'right':
                        p = min(len(t), p + 1)
                    elif k == 'home':
                        p = 0
                    elif k == 'end':
                        p = len(t)
                    elif k == 'ctrl-u':
                        t, p = '', 0
                    elif k and len(k) == 1 and k.isprintable():
                        if kind == 'number' and not (k.isdigit() or (k == '-' and p == 0)):
                            continue
                        t, p = t[:p] + k + t[p:], p + 1
                    else:
                        continue
                    vals[key], pos[key] = t, p
                    if err_at == key:
                        err, err_at = '', None
        finally:
            try:
                c.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass

    def ask_one(self, title, label, value='', help_='', need=True, secret=False, check=None):
        """One question in a window; its answer, or None (Esc)."""
        got = self.form(title, [{'key': 'v', 'label': label, 'value': value, 'help': help_,
                                 'need': need, 'kind': 'secret' if secret else 'text',
                                 'check': check}])
        return None if got is None else got['v']

    def pick(self, title, load, cols, act=None, empty='nothing here', words=''):
        """A list to scroll with the arrows: `load()` gives its rows (asked
        again after something was done to one), `cols` [(heading, fn(row),
        width, tone fn(row) or None)]. Enter calls `act(row)`; / finds. Esc
        back, q leaves the console."""
        c, A = self.curses, self.A
        rows = load() or []
        sel, top, find, said, said_bad = 0, 0, '', '', False
        while True:
            self._fresh()
            h, w = self.scr.getmaxyx()
            seen = [r for r in rows if not find or find.lower() in ' '.join(
                str(fn(r)) for _h, fn, _w, _t in cols).lower()]
            sel = max(0, min(sel, len(seen) - 1))
            avail = max(3, h - 5 - (1 if words else 0))
            if sel < top:
                top = sel
            if sel >= top + avail:
                top = sel - avail + 1
            top = max(0, min(top, max(0, len(seen) - avail)))
            # Widths: as given; the last one takes what is left.
            ws = [cw for _h, _f, cw, _t in cols]
            fixed = sum(x + 2 for x in ws[:-1])
            ws[-1] = max(8, min(ws[-1] or 200, w - 4 - fixed))

            def paint(_title=title, _seen=seen, _top=top, _sel=sel, _ws=ws, _avail=avail):
                self.scr.erase()
                self._put(0, 0, ' ' * w, A['head'])
                self._put(0, 0, ' upsmon %s  %s ' % (__version__, _title), A['head'] | c.A_BOLD)
                right = ' %d%s ' % (len(_seen), (' of %d, with "%s"' % (len(rows), find))
                                    if find else '')
                self._put(0, max(0, w - len(right) - 1), right, A['head'])
                y = 1
                if words:
                    self._put(y, 1, words[:w - 2], A['dim'])
                    y += 1
                x = 2
                for (hd, _f, _w, _t), cw in zip(cols, _ws):
                    self._put(y + 1, x, hd[:cw], A['key'])
                    x += cw + 2
                y += 2
                if not _seen:
                    self._put(y + 1, 4, empty if not find else 'nothing with "%s"' % find,
                              A['dim'])
                for n, r in enumerate(_seen[_top:_top + _avail]):
                    i = _top + n
                    x = 2
                    if i == _sel:
                        self._put(y + n, 1, ' ' * (w - 3), A['sel'])
                    for (hd, fn, _w, tone), cw in zip(cols, _ws):
                        try:
                            v = str(fn(r))
                        except Exception:               # noqa: BLE001
                            v = '?'
                        attr = A['sel'] if i == _sel else (A.get(tone(r) or '', 0) if tone else 0)
                        self._put(y + n, x, v[:cw], attr)
                        x += cw + 2
                if len(_seen) > _avail:
                    thumb = max(1, min(_avail, round(_avail * _avail / len(_seen))))
                    ts = max(0, min(_avail - thumb, round((_avail - thumb) * _top
                                                          / max(1, len(_seen) - _avail))))
                    utf = 'utf' in (sys.stdout.encoding or '').lower()
                    for r_ in range(_avail):
                        hit = ts <= r_ < ts + thumb
                        self._put(y + r_, w - 1, ('█' if hit else '│') if utf
                                  else ('#' if hit else '|'), A['key'] if hit else A['dim'])
                if said:
                    self._put(h - 2, 1, said[:w - 2], A['bad'] if said_bad else A['ok'])
                help_ = ' Up/Down PgUp/PgDn Home/End move   Enter %s   / find   Esc back ' % (
                    'what to do with it' if act else 'look')
                self._put(h - 1, 0, ' ' * (w - 1), A['head'])
                self._put(h - 1, 0, help_[:w - 1], A['head'])
                self.scr.noutrefresh()
            self.backdrop = paint
            paint()
            c.doupdate()
            self.scr.timeout(500)
            k = self._getkey()
            if k is None:
                continue
            said = ''
            if k == 'esc':
                if find:
                    find = ''
                    continue
                return None
            if k == 'q':
                return 'quit'
            if k in ('up', 'down', 'pgup', 'pgdn', 'home', 'end'):
                sel = {'up': sel - 1, 'down': sel + 1, 'pgup': sel - (avail - 1),
                       'pgdn': sel + (avail - 1), 'home': 0, 'end': len(seen) - 1}[k]
            elif k == '/':
                got = self.ask_one('Find', 'with the words', find, need=False,
                                   help_='Only the rows with these words in them stay; '
                                         'Esc in the list shows them all again.')
                if got is not None:
                    find, sel, top = got, 0, 0
            elif k in ('enter', 'right') and seen and act:
                r = act(seen[sel])
                if r == 'quit':
                    return 'quit'
                if isinstance(r, tuple):
                    said, said_bad = r
                rows = load() or []

    def act(self, *args, env=None, title=None, quiet_ok=None):
        """`upsmon ARGS` run: a short answer in a window, a long one on a screen
        of its own to scroll. Returns the exit code."""
        argv = otp_argv(self.me) + [str(a) for a in args]
        shown = '$ upsmon ' + ' '.join(self._quote(a) for a in args)
        return self.act_argv(argv, title or shown, env=env, quiet_ok=quiet_ok)

    def act_argv(self, argv, title, env=None, quiet_ok=None):
        self.working('working…  ' + title)
        text, rc = self.capture(argv, env=env)
        plain = self._plain_text(text).rstrip()
        if rc == 0 and not plain and quiet_ok:
            plain = text = quiet_ok
        h, w = self.scr.getmaxyx()
        lines = self._wrap(plain, max(30, min(100, w - 4)) - 4)
        if len(lines) <= max(3, min(14, h - 8)):
            self.note(title if rc == 0 else '%s - it ended with %d' % (title, rc),
                      plain or '(it said nothing)', '' if rc == 0 else 'bad')
        else:
            if rc not in (0, None):
                text += '\n' + self.pal.dim('(it ended with %d)' % rc)
            self.go_plain(lambda: self.page(title, text))
        return rc

    def live(self, fn):
        """A view of its own on the terminal (a live log, a progress)."""
        self.go_plain(fn)

    # ---- small parts the lists use ------------------------------------------------
    @staticmethod
    def _when(ts):
        if not ts:
            return '-'
        try:
            return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(ts)))
        except (TypeError, ValueError):
            return str(ts)

    @staticmethod
    def _rows(got, *keys):
        if isinstance(got, dict):
            for k in keys:
                if isinstance(got.get(k), list):
                    return got[k]
            return []
        return got if isinstance(got, list) else []

    def details(self, title, row, skip=()):
        """One row's fields as words, in a window or on its own screen."""
        lines = []
        for k, v in row.items():
            if k in skip or v in (None, '', [], {}):
                continue
            if isinstance(v, (list, dict)):
                v = json.dumps(v, default=str, ensure_ascii=False)
            elif k in ('created', 'last_used', 'last_seen', 'last_in', 'activated', 'at',
                       'pending_at', 'locked_until') and isinstance(v, (int, float)):
                v = self._when(v)
            lines.append('%-16s %s' % (k, v))
        h, w = self.scr.getmaxyx()
        if len(lines) <= h - 8:
            self.note(title, '\n'.join(lines))
        else:
            self.go_plain(lambda: self.page(title, '\n'.join(lines)))

    def m_ops(self):
        """Certificates and TLS, and the automatic ones, for a server whose pages are down."""
        def acme_order():
            got = self.out('--acme') or {}
            opts = [('all', 'every one ACME looks after here')] + [
                (t['target'], '%s - %s' % (t['target'], t.get('name') or 'no name yet'))
                for t in got.get('targets') or []]
            which = self.choose('Order a certificate now', opts)
            if which is not None:
                self.live(lambda: self.show_live('--acme-order', which))

        def selfsigned():
            got = self.form('A self-signed certificate', [
                {'key': 'cn', 'label': 'its name', 'value': socket.getfqdn(), 'need': True,
                 'help': 'The name the dashboard is reached by: ups.example.cz'},
                {'key': 'days', 'label': 'days', 'kind': 'number', 'value': '825',
                 'range': (1, 3650), 'need': True}])
            if got and self.confirm('A self-signed certificate', 'nginx gets a new certificate '
                                    'for %s; browsers warn about it until one from a CA is put '
                                    'in.' % got['cn'], 'Make it'):
                self.act('--cert-selfsigned', got['cn'], '--days', got['days'])
        def updates_start():
            how = self.choose('When the update needs a restart', [
                ('ask', 'ask on the pages first'), ('auto', 'restarted by itself'),
                ('never', 'not restarted')])
            if how is None:
                return
            if self.confirm('Update now', 'The updates of the system are put in on this server '
                            '(PHP among them).', 'Update', danger=True):
                self.act('--updates', 'start', '--reboot', how, '--yes')

        def power(how):
            def go():
                if self.confirm('Restart' if how == 'reboot' else 'Switch off',
                                'This machine restarts now; the dashboard is away for a minute or two.'
                                if how == 'reboot' else 'This machine is switched off now; it comes '
                                'back only by its button.', 'Restart' if how == 'reboot' else 'Switch off',
                                danger=True):
                    self.act('--restart-server' if how == 'reboot' else '--poweroff-server', '--yes')
            return go

        def lockout_clear():
            rows = [r for r in ((self.out('--lockouts') or {}).get('rows') or []) if isinstance(r, dict)]
            if not rows:
                self.note('Lockouts', 'Nobody and nothing is counted now.')
                return
            opts = [('all', 'every one')] + [('%s:%s' % (r['kind'], r['who']), '%s:%s' % (
                r['kind'], r['who'])) for r in rows]
            which = self.choose('Forget a lockout', opts)
            if which is not None:
                self.act('--lockouts-clear', which)

        return self.sub('Certificates, updates, restarts, the time', [
            ('1', 'The certificate nginx has now', lambda: self.act('--cert')),
            ('2', 'Automatic certificates (ACME): how they stand', lambda: self.act('--acme')),
            ('3', 'Order a certificate by ACME now', acme_order),
            ('4', 'A self-signed certificate, made here', selfsigned),
            ('5', 'The certificate as PEM', lambda: self.act('--cert', '--pem')),
            ('6', 'Updates of the system: how they stand', lambda: self.act('--updates', 'status')),
            ('7', 'Look for updates now', lambda: self.act('--updates', 'check')),
            ('8', 'Put the updates in', updates_start),
            ('9', 'Stop the updates going on', lambda: self.act('--updates', 'cancel')),
            ('10', 'Restarts: how they went', lambda: self.act('--restarts')),
            ('11', 'Restart this machine', power('reboot')),
            ('12', 'Switch this machine off', power('poweroff')),
            ('13', 'The time: how the clock stands', lambda: self.act('--time')),
            ('14', 'The time: step the clock now', lambda: self.act('--time', 'sync')),
            ('15', 'Lockouts: who is locked out now', lambda: self.act('--lockouts')),
            ('16', 'Forget a lockout', lockout_clear),
        ])

    def m_backups(self):
        def kept():
            return self.pick('Copies kept here', lambda: kept_copies(), [
                ('made', lambda f: self._when(f['at']), 16, None),
                ('size', lambda f: human_bytes(f['bytes']), 10, None),
                ('key', lambda f: 'yes' if f['key'] else 'no', 5, None),
                ('file', lambda f: f['name'], 60, None)], self.backup_do,
                'no copy is kept here yet')

        def by_path(restore):
            def go():
                path = self.ask_one('Put a copy back' if restore else 'What is in a file',
                                    'the file', str(BACKUP_DIR) + '/', help_=(
                                        'A copy made here or brought from elsewhere '
                                        '(upsmon-copy-….tar.gz, its .key beside it).'),
                                    check=lambda v, _: None if os.path.isfile(v)
                                    else 'there is no such file')
                if path:
                    self.backup_do({'path': path, 'name': os.path.basename(path)},
                                   'restore' if restore else 'info')
            return go

        def bundle():
            path = self.ask_one('Put a backup back', 'the file', '/root/', help_=(
                'upsmon-backup-….tar.gz.enc, from a destination; the password of the backups '
                'is asked (or the one set here is used).'),
                check=lambda v, _: None if os.path.isfile(v) else 'there is no such file')
            if path and self.confirm('Put a backup back', 'Both databases here are replaced by '
                                     'what is in %s, and the service restarts on it.'
                                     % os.path.basename(path), 'Put it back', danger=True):
                self.act('--restore-bundle', path, '--yes')
                self.act_argv(['systemctl', 'restart', 'upsmon'], '$ systemctl restart upsmon',
                              quiet_ok='restarted')
        return self.sub('The database and backups', [
            ('1', 'A copy of both databases now', lambda: self.act('--backup')),
            ('2', 'The copies kept here (Enter: look in one, put it back)', kept),
            ('3', 'What is in a file', by_path(False)),
            ('4', 'Put a copy back from a file', by_path(True)),
            ('5', 'Both databases read through', lambda: self.act('--db-check')),
            ('6', 'Backups to other machines: how they went', lambda: self.act('--rbackup-status')),
            ('7', 'Backups to other machines: one now', lambda: self.act('--rbackup-now')),
            ('8', 'Put a backup from another machine back', bundle),
        ])

    def backup_do(self, f, what=None):
        path = f.get('path') or str(BACKUP_DIR / f['name'])
        if what is None:
            what = self.choose(f['name'], [('info', 'What is in it'),
                                            ('restore', 'Put it back (replaces everything)')])
        if what == 'info':
            self.act('--restore', path)
        elif what == 'restore':
            if self.confirm('Put a copy back', 'Both databases are replaced by %s; the history, the '
                            'accounts and the settings since are lost (a copy of them is made first).'
                            % f['name'], 'Put it back', danger=True):
                self.act('--restore', path, '--yes')
                self.act_argv(['systemctl', 'restart', 'upsmon'], '$ systemctl restart upsmon',
                              quiet_ok='restarted')

    def m_upgrades(self):
        def online():
            self.working('working…  looking for a new version')
            row = self.out('--upgrade-check') or {}
            if row.get('error'):
                self.note('Upgrade from the web', '%s:\n%s' % (row.get('url'), row['error']),
                          'bad')
                return
            here = _ver_tuple(__version__)
            newer = [p for p in row.get('packages') or []
                     if _ver_tuple(p.get('version')) > here]
            if not newer:
                self.note('Upgrade from the web', 'Nothing newer than %s at %s.' % (
                    __version__, row.get('url')), 'ok')
                return
            ver = self.choose('Upgrade from the web', [
                (p['version'], 'upsmon %s%s' % (p['version'], '   (the newest)' if i == 0 else ''))
                for i, p in enumerate(newer)], 'This server runs %s. Found at %s:' % (
                    __version__, row.get('url')))
            if not ver:
                return
            nodes = self._nodes()
            if not self.confirm('Upgrade to %s' % ver, (
                    'The nodes %s are upgraded one at a time - each in maintenance while '
                    'it is, the other answering.' % ', '.join(nodes)) if len(nodes) > 1 else
                    'This server is upgraded - for a minute the dashboard is away.',
                    'Upgrade'):
                return
            self.live(lambda: self.show_live('--upgrade-online', ver, '--yes'))

        def install():
            path = self.ask_one('Upgrade this node from a package', 'the package', '/root/',
                                help_='upsmon-X.Y.Z.tar.gz, or the folder it was unpacked to.',
                                check=lambda v, _: None if (
                                    os.path.isfile(v) and v.endswith('.tar.gz')) or
                                os.path.isfile(os.path.join(v, 'install.sh'))
                                else 'neither an upsmon-X.Y.Z.tar.gz nor a folder with install.sh')
            if not path:
                return
            folder = path
            if path.endswith('.tar.gz'):
                # A package goes through root's own helper (1.0.149): copied out
                # of reach, its signature checked before anything of it is
                # unpacked or run - a package in /var/lib/upsmon/upgrade is the upsmon
                # account's to change, and was unpacked and run as it was.
                helper = str(UPGRADE_HELPER)
                if not os.path.isfile(helper):
                    self.note('Upgrade', '%s is not installed - upgrade once with install.sh '
                              '--upgrade from a package you checked' % helper, 'bad')
                    return
                if not self.confirm('Upgrade', 'This node is upgraded with %s once its '
                                    'signature is checked.' % path, 'Upgrade'):
                    return

                def run_signed():
                    self.clear_screen()
                    subprocess.call(['/usr/bin/python3', '-I', helper, '--run', path])
                    self.pause()
                self.live(run_signed)
                return
            script = os.path.join(folder, 'install.sh')
            if not os.path.isfile(script):
                self.note('Upgrade', 'there is no install.sh in %s' % folder, 'bad')
                return
            # The version the package's upsmon.py says (1.0.146), not its folder's name.
            m = None
            try:
                with open(os.path.join(folder, 'upsmon.py'), encoding='utf-8') as f:
                    m = re.search(r"^__version__ = '(\d+\.\d+\.\d+)'", f.read(), re.M)
            except OSError:
                pass
            if m and _ver_tuple(m.group(1)) < _ver_tuple(__version__):
                # Never past the checks (1.0.143): an older one goes the safe way.
                self.note('Upgrade', '%s is older than %s, which runs here. Going back is '
                          'checked first - Upgrades → Go back to an older version, or\n'
                          'upsmon --downgrade %s' % (m.group(1), __version__,
                                                  path if path.endswith('.tar.gz') else
                                                  'upsmon-%s.tar.gz' % m.group(1)), 'warn')
                return
            # A folder carries no signature (1.0.149): said so, and only one of
            # root's own - nobody else may have changed what root runs.
            try:
                st = os.lstat(folder)
                owned = st.st_uid == 0 and not st.st_mode & 0o022 and \
                    os.lstat(script).st_uid == 0 and not os.lstat(script).st_mode & 0o022
            except OSError:
                owned = False
            if not owned:
                self.note('Upgrade', '%s is not root\'s alone - another account could have '
                          'changed what would be run as root. Use the signed package '
                          '(upsmon-X.Y.Z.tar.gz).' % folder, 'bad')
                return
            if self.confirm('Upgrade', 'This node is upgraded with %s. A folder is not '
                            'checked for a signature - only one you unpacked yourself from a '
                            'signed package.' % script, 'Upgrade unchecked'):
                def go():
                    self.clear_screen()
                    subprocess.call(['bash', script, '--upgrade'])
                    self.pause()
                self.live(go)

        def cancel():
            if self.confirm('Stop the upgrade', 'The nodes not yet begun stay as they are; '
                            'one being upgraded finishes.', 'Stop it'):
                self.act('--upgrade-cancel')

        def back():
            # Going back to an older version (1.0.143): only one that is safe.
            self.working('working…  looking for older versions')
            got = self.out('--downgrade-check') or {}
            if not got.get('versions') and got.get('url') is None:
                self.note('Go back to an older version', 'The versions could not be read: '
                          'is upgrade_url set? (upsmon --downgrade-check says why)', 'bad')
                return
            vs = got.get('versions') or []
            ok = [v for v in vs if not v.get('why')]
            if not ok:
                self.note('Go back to an older version', 'Nothing older at %s may be gone back '
                          'to.\n\n%s' % (got.get('url'), '\n'.join(
                              '%s: %s' % (v['version'], '; '.join(v['why'])) for v in vs)
                              or 'No older version is there.'), 'warn')
                return
            ver = self.choose('Go back to an older version', [
                (v['version'], 'upsmon %s' % v['version']) for v in ok],
                'This server runs %s and may go back to %s or newer (the database is not '
                'touched). Found at %s:' % (__version__, got.get('floor'), got.get('url')))
            if not ver:
                return
            nodes = self._nodes()
            if not self.confirm('Go back to %s' % ver, (
                    'The nodes %s go back one at a time - each in maintenance while it is, '
                    'the other answering.' % ', '.join(nodes) if len(nodes) > 1 else
                    'This server goes back - for a minute the dashboard is away.') +
                    ' The package is checked against the database first. What came in the '
                    'newer versions is gone until you upgrade again.', 'Go back',
                    danger=True):
                return
            self.live(lambda: self.show_live('--downgrade', ver, '--yes'))
        return self.sub('Upgrades', [
            ('1', 'How it stands', lambda: self.act('--upgrade-status')),
            ('2', 'Look for a new version on the web now', lambda: self.act('--upgrade-check')),
            ('3', 'Upgrade from the web (every node, with its progress)', online),
            ('4', 'Follow the upgrade going on', lambda: self.show_live('--upgrade-follow'),
             'plain'),
            ('5', 'Upgrade this node from a package file', install),
            ('6', 'Stop an upgrade going on', cancel),
            ('7', 'Go back to an older version (only a safe one)', back),
        ])

    # ---- 11 the service ---------------------------------------------------------
    def m_service(self):
        def restart():
            if self.confirm('Restart the service', 'The dashboard and the settings pages are '
                            'away for a few seconds.', 'Restart'):
                self.act_argv(['systemctl', 'restart', 'upsmon'], '$ systemctl restart upsmon',
                              quiet_ok='restarted')
                self.st_now = True

        def at_login():
            on = console_at_login()
            r = self.choose('The console at login', [
                ('on', 'On - root sees this console first when signing in'),
                ('off', 'Off - root gets the ordinary shell')],
                'It is %s now.' % ('ON' if on else 'off'), cur=0 if on else 1)
            if r and (r == 'on') != on:
                try:
                    self.note('The console at login', console_at_login_set(r == 'on'), 'ok')
                except SystemExit as e:
                    self.note('The console at login', str(e), 'bad')
        return self.sub('The service', [
            ('1', 'Its state', lambda: self.act_argv(
                ['systemctl', 'status', 'upsmon', '--no-pager', '-n', '60', '-l'],
                '$ systemctl status upsmon')),
            ('2', 'Restart it', restart),
            ('3', 'The pages (nginx, PHP)', lambda: self.act_argv(
                ['systemctl', 'status', 'nginx', 'php-fpm', '--no-pager', '-n', '5'],
                '$ systemctl status nginx php-fpm')),
            ('4', 'Its journal, live', self.journal, 'plain'),
            ('5', 'The console at login: on or off', at_login),
        ])




# ======== carried over from OTP 1.0.187 (lines 44489-44537): the command line as the service ========
def become_service_user():
    """Run as the daemon's own account when started as root, so that nothing
    the command line writes - the database file and its journal, a copy, the
    key of the tokens - ends up root's and out of the daemon's reach."""
    if os.geteuid() != 0 or os.environ.get('UPSMON_STAY_ROOT'):
        return
    try:
        import pwd
        import grp
        pw = pwd.getpwnam(SERVICE_USER)
    except (KeyError, ImportError):
        return
    try:
        groups = [g.gr_gid for g in grp.getgrall() if SERVICE_USER in g.gr_mem]
        os.setgroups(sorted(set(groups + [pw.pw_gid])))
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
    except OSError as e:
        sys.stderr.write('upsmon: could not become %s (%s); going on as root\n' % (SERVICE_USER, e))


def chown_to_service(path, mode=None):
    """A file root just wrote, given to the daemon's account - opened without
    following a link, and changed as the open file (1.0.101): by its name,
    a link put in its place meanwhile handed the service any file."""
    if os.geteuid() != 0:
        return
    ids = service_ids()
    if not ids:
        return
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
    except OSError:
        return
    try:
        if (os.fstat(fd).st_mode & 0o170000) != 0o100000:    # not a plain file
            return
        os.fchown(fd, ids[0], ids[1])
        if mode is not None:
            os.fchmod(fd, mode)
    except OSError:
        pass
    finally:
        os.close(fd)


NGINX_CONF_PATHS = ('/etc/nginx/conf.d/upsmon.conf', '/etc/nginx/sites-enabled/upsmon.conf',
                    '/etc/nginx/sites-available/upsmon.conf')



# ======== carried over from OTP 1.0.187 (lines 45372-45458): an upgrade followed ========
def upgrade_percent(st, plan):
    """How far one node is, as the pages draw it."""
    now = time.time()
    since = now - float(st.get('at') or now)
    state = st.get('state')
    if state in ('done', 'failed'):
        return 100
    if state == 'draining':
        return round(3 + 17 * min(1, since / max(1, float(plan.get('drain_s') or 20))))
    if state == 'installing':
        asked = now - float(st.get('asked') or st.get('at') or now)
        return round(min(82, 20 + 60 * min(0.95, float(st.get('part') or 0) / 6)
                         + min(6, asked / 15)))
    if state == 'checking':
        return round(85 + min(10, since / 3))
    return 0


def cli_upgrade_follow(store, pal):
    """An upgrade followed on the terminal: a bar for the whole and one for each
    node, drawn again in place every second, until it ends. Ctrl+C stops the
    following, not the upgrade."""
    tty = sys.stdout.isatty()
    drawn = 0
    last = None
    try:
        while True:
            try:
                plan = upgrade_plan(store)
            except Exception as e:                      # noqa: BLE001 - a node restarting
                plan = last
                if plan is None:
                    raise SystemExit('upsmon: %s' % e)
            if not plan:
                print('no upgrade going on')
                return 0
            last = plan
            steps = plan.get('steps') or []
            whole = round(sum(upgrade_percent(x, plan) for x in steps) / len(steps)) if steps else 0
            try:
                width = max(20, min(50, shutil.get_terminal_size((100, 24)).columns - 60))
            except Exception:                           # noqa: BLE001
                width = 30

            def bar(pc, bad=False, good=False):
                n = int(round(width * pc / 100.0))
                fill = '█' * n + '░' * (width - n)
                paint = pal.bad if bad else (pal.good if good else pal.info)
                return paint(fill) + ' %3d %%' % pc
            lines = [pal.head(('going back to %s' if plan.get('downgrade') else 'upgrade to %s')
                              % plan.get('version')) + pal.dim(
                '  started by %s · %s' % (plan.get('by') or '?', plan.get('state')))]
            lines.append('  %-16s %s  %d of %d node(s) done' % (
                'all', bar(whole, plan.get('state') == 'failed', plan.get('state') == 'done'),
                sum(1 for x in steps if x.get('state') == 'done'), len(steps)))
            for x in steps:
                pc = upgrade_percent(x, plan)
                words = x.get('said') or x.get('state') or 'waiting'
                if x.get('state') == 'installing' and x.get('part_words'):
                    words = x['part_words']
                lines.append('  %-16s %s  %s' % (x['name'][:16], bar(
                    pc, x.get('state') == 'failed', x.get('state') == 'done'),
                    str(words)[:60]))
            # Past ColourOut (1.0.146): it shows any escape that is not a
            # colour as text - the frame was drawn again below, never over.
            sys.stdout.flush()
            raw = getattr(sys.stdout, 's', sys.stdout)
            if tty and drawn:
                raw.write('\x1b[%dA' % drawn)
            for ln in lines:
                raw.write(('\x1b[2K' if tty else '') + term_safe(ln) + '\n')
            raw.flush()
            drawn = len(lines)
            if plan.get('state') != 'running':
                ok = plan.get('state') == 'done'
                print((pal.ok_line if ok else pal.bad_line)(
                    '%s %s' % ('going back' if plan.get('downgrade') else 'the upgrade',
                               'is done - every node runs %s' % plan.get('version')
                               if ok else 'ended: %s' % plan.get('state'))))
                return 0 if ok else 1
            if not tty:
                drawn = 0
            time.sleep(1 if tty else 5)
    except KeyboardInterrupt:
        print('\n' + pal.dim('no longer followed here - it goes on; upsmon --upgrade-follow '
                             'follows it again'))
        return 0


# ---------------------------------------------------------------------------
# The database: SQLite, /var/lib/upsmon/upsmon.db
# ---------------------------------------------------------------------------
class DbError(Exception):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT, at REAL, by_who TEXT);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, node TEXT, level TEXT,
    who TEXT, words TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, role TEXT, pw TEXT,
    source TEXT DEFAULT 'local', disabled INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0,
    note TEXT DEFAULT '', created REAL, last_in REAL, last_from TEXT DEFAULT '',
    prefs TEXT DEFAULT '{}', display TEXT DEFAULT '', dn TEXT DEFAULT '',
    group_list TEXT DEFAULT '', cols TEXT, cols_at REAL);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE, kind TEXT, name TEXT,
    role TEXT, created REAL, last REAL, expires REAL, ip TEXT, data TEXT DEFAULT '{}');
"""


class Db(object):
    """SQLite with the few calls upsmon's code makes of its database."""
    engine = 'sqlite'

    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False,
                                        isolation_level=None)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA busy_timeout=30000')
        except sqlite3.Error as e:
            raise DbError('the database %s will not open: %s' % (self.path, e))

    def make_tables(self):
        with self.lock:
            self.conn.executescript(SCHEMA)
            # Columns a newer version added, added to an older database.
            have = {r['name'] for r in self.conn.execute('PRAGMA table_info(accounts)')}
            for col, kind in (('cols', 'TEXT'), ('cols_at', 'REAL'), ('display', "TEXT DEFAULT ''"),
                              ('dn', "TEXT DEFAULT ''"), ('group_list', "TEXT DEFAULT ''")):
                if col not in have:
                    self.conn.execute('ALTER TABLE accounts ADD COLUMN %s %s' % (col, kind))

    def _do(self, sql, args=()):
        try:
            return self.conn.execute(sql, tuple(args or ()))
        except sqlite3.Error as e:
            raise DbError('the database: %s' % e)

    def run(self, sql, args=()):
        with self.lock:
            return self._do(sql, args).rowcount

    def rows(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self._do(sql, args).fetchall()]

    def row(self, sql, args=()):
        with self.lock:
            r = self._do(sql, args).fetchone()
            return dict(r) if r else None

    def value(self, sql, args=(), default=None):
        with self.lock:
            r = self._do(sql, args).fetchone()
        if r is None:
            return default
        v = r[0]
        return default if v is None else v

    def insert(self, table, data):
        cols = list(data)
        with self.lock:
            cur = self._do('INSERT INTO %s (%s) VALUES (%s)' % (
                table, ', '.join(cols), ', '.join('?' * len(cols))), [data[c] for c in cols])
            return cur.lastrowid

    def update(self, table, ident, fields):
        if not fields:
            return 0
        cols = list(fields)
        return self.run('UPDATE %s SET %s WHERE id = ?' % (table, ', '.join('%s = ?' % c for c in cols)),
                        [fields[c] for c in cols] + [ident])

    def where(self):
        return self.path

    def version(self):
        return 'SQLite ' + sqlite3.sqlite_version

    def close(self):
        try:
            self.conn.close()
        except Exception:                               # noqa: BLE001
            pass


def like_escape(text):
    return '%' + like_pattern(str(text).lower()) + '%'


class Storage(object):
    _KINDS = (0.0, [])

    def __init__(self, path=None):
        self.db = Db(path or DB_FILE)
        self.db.make_tables()

    # ---- meta -----------------------------------------------------------------
    def get_meta(self, k):
        return self.db.value('SELECT v FROM meta WHERE k = ?', (k,))

    def set_meta(self, k, v):
        self.db.run('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v',
                    (k, v))

    # ---- settings saved on the pages ---------------------------------------------
    def settings_saved(self):
        out = {}
        for r in self.db.rows('SELECT k, v FROM settings'):
            try:
                out[r['k']] = json.loads(r['v'])
            except (TypeError, ValueError):
                pass
        return out

    def settings_written(self):
        return {r['k']: {'at': r['at'], 'by': r['by_who']}
                for r in self.db.rows('SELECT k, at, by_who FROM settings')}

    def save_setting(self, k, v, by=''):
        self.db.run('INSERT INTO settings (k, v, at, by_who) VALUES (?, ?, ?, ?) ON CONFLICT(k) '
                    'DO UPDATE SET v = excluded.v, at = excluded.at, by_who = excluded.by_who',
                    (k, json.dumps(v), time.time(), str(by or '')[:190]))

    def drop_setting(self, k):
        self.db.run('DELETE FROM settings WHERE k = ?', (k,))

    # ---- events ---------------------------------------------------------------------
    def add_event(self, kind, words, level='info', who=''):
        try:
            self.db.insert('events', {'ts': time.time(), 'kind': str(kind)[:60],
                                      'node': node_name(), 'level': level,
                                      'who': str(who or '')[:190], 'words': str(words)[:4000]})
        except Exception as e:                          # noqa: BLE001
            log('the event could not be written down: %s (%s)' % (words, e), 'warn')
        log('%s: %s%s' % (kind, words, (' (%s)' % who) if who else ''),
            'warn' if level in ('warn', 'bad') else 'info')

    def events(self, limit=100, offset=0, q='', kind='', extra=None):
        where, args = [], []
        if extra and extra[0]:
            where.append(extra[0])
            args += list(extra[1])
        if q:
            where.append("(LOWER(words) LIKE ? ESCAPE '!' OR LOWER(who) LIKE ? ESCAPE '!' OR "
                         "LOWER(kind) LIKE ? ESCAPE '!')")
            like = like_escape(q)
            args += [like, like, like]
        if kind:
            where.append('kind = ?')
            args.append(kind)
        sql = ' WHERE ' + ' AND '.join(where) if where else ''
        total = self.db.value('SELECT COUNT(*) AS n FROM events' + sql, args, 0)
        rows = self.db.rows('SELECT * FROM events' + sql + ' ORDER BY ts DESC, id DESC '
                            'LIMIT %d OFFSET %d' % (int(limit), int(offset)), args)
        return rows, int(total or 0)

    def event_kinds(self):
        at, kinds = Storage._KINDS
        if time.time() - at < 60 and kinds:
            return kinds
        kinds = [r['kind'] for r in self.db.rows('SELECT DISTINCT kind FROM events ORDER BY kind')]
        Storage._KINDS = (time.time(), kinds)
        return kinds

    def events_tidy(self, days=730):
        self.db.run('DELETE FROM events WHERE ts < ?', (time.time() - days * 86400,))

    def accounts(self):
        rows = self.db.rows('SELECT * FROM accounts ORDER BY name')
        for r in rows:
            r.pop('pw', None)
            # How somebody laid out their tables is theirs and can be big:
            # only whether there is any, for the Accounts list.
            r['cols_tables'] = len(self._cols_of(r.pop('cols', None)))
            r.pop('cols_at', None)
        return rows

    def account(self, name):
        return self.db.row('SELECT * FROM accounts WHERE LOWER(name) = ?',
                           (str(name or '').strip().lower(),))

    def add_account(self, name, role, password=None, source='local', note='', must_change=0,
                    display='', dn='', groups=''):
        name = str(name or '').strip()
        if not ACCOUNT_NAME_RE.match(name):
            raise ValueError('a name has letters, digits, dots, dashes, @ and nothing else')
        bad = name_letters_problem(name)
        if bad:
            raise ValueError(bad)
        if role not in ROLES_ALL:
            raise ValueError('the role is one of %s' % ', '.join(ROLES_ALL))
        if self.account(name):
            raise ValueError('there is an account called %s already' % name)
        if source == 'local':
            bad = password_problem(password)
            if bad:
                raise ValueError(bad)
        # A second step left by an account of this name taken away before
        # (1.0.146) is not this one's: somebody else's phone would answer it.
        self.db.run('DELETE FROM meta WHERE k = ?', ('adm2fa:' + name.lower(),))
        return self.db.insert('accounts', {
            'name': name, 'role': role, 'pw': password_hash(password) if password else '',
            'source': source, 'disabled': 0, 'must_change': int(bool(must_change)),
            'note': str(note or '')[:400], 'created': time.time(), 'last_in': None,
            'last_from': '', 'prefs': '{}', 'display': display, 'dn': dn,
            'group_list': groups})

    def set_account(self, name, **fields):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        if 'password' in fields:
            bad = password_problem(fields['password'])
            if bad:
                raise ValueError(bad)
            fields['pw'] = password_hash(fields.pop('password'))
        if 'role' in fields and fields['role'] not in ROLES_ALL:
            raise ValueError('the role is one of %s' % ', '.join(ROLES_ALL))
        self.db.update('accounts', one['id'], fields)

    def drop_account(self, name):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        self.db.run('DELETE FROM accounts WHERE id = ?', (one['id'],))
        self.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                    ('admin', one['name'].lower()))
        # Its second step with it (1.0.146): a new account of the same name
        # took it over - the old owner's authenticator signing it in.
        self.db.run('DELETE FROM meta WHERE k = ?', ('adm2fa:' + one['name'].lower(),))

    # ---- how somebody laid out the tables (as on isemon, 1.10.146 on) -------
    COLS_MOST_TABLES = 300
    COLS_MOST_COLUMNS = 60
    COLS_MOST_BYTES = 60000

    @staticmethod
    def _cols_of(text):
        if not text:
            return {}
        try:
            got = json.loads(text)
        except (TypeError, ValueError):
            return {}
        return got if isinstance(got, dict) else {}

    @classmethod
    def clean_cols(cls, cols):
        """A layout as the page sent it, reduced to what a layout can hold:
        `{table: {"w": {column: pixels}, "o": [order], "h": [hidden],
        "v": [optional shown], "s": [empty columns], "t": when}}` and nothing
        else. Anything not understood is dropped rather than kept."""
        if cols == [] or cols is None:
            cols = {}                       # PHP passes an empty object on as []
        if not isinstance(cols, dict):
            raise ValueError('a layout of the columns is an object of tables')
        out = {}

        def names(v, most):
            return [str(c)[:80] for c in v[:most] if isinstance(c, (str, int))] \
                if isinstance(v, list) else []

        for key, one in list(cols.items())[:cls.COLS_MOST_TABLES]:
            key = str(key)[:160]
            if not key or not isinstance(one, dict):
                continue
            kept = {}
            widths = one.get('w')
            if isinstance(widths, dict):
                w = {}
                for col, px in list(widths.items())[:cls.COLS_MOST_COLUMNS]:
                    try:
                        px = int(round(float(px)))
                    except (TypeError, ValueError, OverflowError):
                        continue
                    w[str(col)[:80]] = max(24, min(3000, px))
                if w:
                    kept['w'] = w
            for k in ('o', 'h', 'v'):
                got = names(one.get(k), cls.COLS_MOST_COLUMNS)
                if got:
                    kept[k] = got
            sp = [c for c in names(one.get('s'), 20) if re.match(r'^~\d{1,4}\Z', c)]
            if sp:
                kept['s'] = sp
            if kept:
                try:
                    kept['t'] = int(float(one.get('t') or 0))
                except (TypeError, ValueError, OverflowError):
                    kept['t'] = 0
                out[key] = kept
        if len(json.dumps(out, separators=(',', ':'))) > cls.COLS_MOST_BYTES:
            raise ValueError('that layout of the columns is too big to keep (more than %d '
                             'characters)' % cls.COLS_MOST_BYTES)
        return out

    def user_cols(self, name):
        """How this person has laid out the tables, or {} for as they come."""
        try:
            one = self.account(name)
        except Exception:                               # noqa: BLE001
            return {}
        return self._cols_of(one.get('cols')) if one else {}

    def put_user_cols(self, name, cols):
        """Keep this person's layout; an empty one puts every table back."""
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        cols = self.clean_cols(cols or {})
        self.db.update('accounts', one['id'], {
            'cols': json.dumps(cols, separators=(',', ':')) if cols else None,
            'cols_at': time.time()})
        return cols

    @staticmethod
    def clean_prefs(prefs):
        if prefs == [] or prefs is None:
            prefs = {}
        if not isinstance(prefs, dict):
            raise ValueError('the choices are an object')
        out = {}
        if 'lang' in prefs:
            if str(prefs['lang']) not in ('cs', 'en'):
                raise ValueError('no such language here: %s' % prefs['lang'])
            out['lang'] = str(prefs['lang'])
        return out

    def user_prefs(self, name):
        one = self.account(name)
        return self._cols_of(one.get('prefs')) if one else {}

    def put_user_prefs(self, name, prefs):
        one = self.account(name)
        if not one:
            raise ValueError('there is no account called %s' % name)
        kept = dict(self._cols_of(one.get('prefs')))
        kept.update(self.clean_prefs(prefs))
        self.db.update('accounts', one['id'], {'prefs': json.dumps(kept)})
        return kept

    def fulladmins_left(self, but=''):
        return sum(1 for a in self.accounts() if a['role'] == 'fulladmin' and not a['disabled']
                   and a['name'].lower() != str(but).lower())

    # ---- sessions ----------------------------------------------------------
    def session_new(self, kind, name, role, ip, hours, data=None):
        token = secrets.token_urlsafe(32)
        t = time.time()
        self.db.insert('sessions', {
            'token_hash': hashlib.sha256(token.encode()).hexdigest(), 'kind': kind,
            'name': name, 'role': role, 'created': t, 'last': t,
            'expires': t + float(hours) * 3600, 'ip': str(ip or '')[:60],
            'data': json.dumps(data or {})})
        return token

    def session_get(self, token, kind, idle_s, touch=True):
        if not token:
            return None
        row = self.db.row('SELECT * FROM sessions WHERE token_hash = ? AND kind = ?',
                          (hashlib.sha256(str(token).encode()).hexdigest(), kind))
        if not row:
            return None
        t = time.time()
        if row['expires'] < t or t - float(row['last'] or 0) > idle_s:
            self.db.run('DELETE FROM sessions WHERE id = ?', (row['id'],))
            return None
        if touch and t - float(row['last'] or 0) > 20:
            self.db.run('UPDATE sessions SET last = ? WHERE id = ?', (t, row['id']))
        try:
            row['data'] = json.loads(row.get('data') or '{}')
        except ValueError:
            row['data'] = {}
        return row

    def session_take(self, ident, field):
        """`field` taken out of a session's data, by one request only
        (1.0.101): written back only if nobody changed the data meanwhile.
        True if this request took it."""
        for _round in range(8):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return False
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                return False
            if field not in data:
                return False
            data.pop(field, None)
            if self.db.run('UPDATE sessions SET data = ? WHERE id = ? AND data = ?',
                           (json.dumps(data), ident, raw)):
                return True
        return False

    def session_merge(self, ident, changes, expect=None):
        """Only the keys given changed in a session's data, over what the
        database holds now (1.0.101): the whole of a copy read at the start of
        a request, written back at its end, put back what another request
        had taken meanwhile - a code already used became usable again.
        None as a value takes the key out. The data as it is now."""
        data = {}
        for _round in range(8):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return None
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                data = {}
            # `expect`: written only while these keys still hold what the
            # caller read - else nothing, and False.
            for k, v in (expect or {}).items():
                if data.get(k) != v:
                    return False
            for k, v in changes.items():
                if v is None:
                    data.pop(k, None)
                else:
                    data[k] = v
            if self.db.run('UPDATE sessions SET data = ? WHERE id = ? AND data = ?',
                           (json.dumps(data), ident, raw)):
                return data
        return data

    def session_count_try(self, ident, field, code, most):
        """A wrong try counted on the one-time code kept under `field` - the
        one whose hash is `code` - as the database holds it now (1.0.101);
        taken away at the last try. Whether it is gone now."""
        for _round in range(16):
            raw = self.db.value('SELECT data FROM sessions WHERE id = ?', (ident,))
            if raw is None:
                return True
            try:
                data = json.loads(raw or '{}')
            except ValueError:
                return True
            cur = data.get(field)
            if not isinstance(cur, dict) or cur.get('code') != code:
                return True             # taken, or another code asked for since
            cur['tries'] = int(cur.get('tries') or 0) + 1
            gone = cur['tries'] >= most
            if gone:
                data.pop(field, None)
            else:
                data[field] = cur
            if self.db.run('UPDATE sessions SET data = ? WHERE id = ? AND data = ?',
                           (json.dumps(data), ident, raw)):
                return gone
        return False

    def session_set_data(self, ident, data):
        self.db.run('UPDATE sessions SET data = ? WHERE id = ?', (json.dumps(data), ident))

    def session_end(self, token):
        self.db.run('DELETE FROM sessions WHERE token_hash = ?',
                    (hashlib.sha256(str(token or '').encode()).hexdigest(),))

    def sessions(self, kind=None):
        sql, args = 'SELECT id, kind, name, role, created, last, expires, ip FROM sessions', []
        if kind:
            sql += ' WHERE kind = ?'
            args.append(kind)
        return self.db.rows(sql + ' ORDER BY last DESC', args)

    def session_drop(self, ident):
        self.db.run('DELETE FROM sessions WHERE id = ?', (int(ident),))

    def sessions_tidy(self, idle_admin_s=None, idle_portal_s=None):
        t = time.time()
        self.db.run('DELETE FROM sessions WHERE expires < ?', (t,))
        for kind, idle in (('admin', idle_admin_s), ('portal', idle_portal_s)):
            if idle:
                self.db.run('DELETE FROM sessions WHERE kind = ? AND last < ?', (kind, t - float(idle)))


# ---------------------------------------------------------------------------
# The databases of upsmon, as Settings → The database and Backups see them
# ---------------------------------------------------------------------------
# Two SQLite files: upsmon.db (accounts, settings of the pages, events,
# certificates - this module's) and history.db (the UPS, the plug, the
# sensors - upsmon.py's). A copy is both of them, taken with SQLite's own
# backup (consistent while the daemon writes), with config.json to read and
# a head saying what it is: one .tar.gz, the key that opens the sealed
# secrets beside it as NAME.key. Putting one back is laid down in
# /var/lib/upsmon/restore/ and done by the daemon when it starts again -
# never under a database that is open.
BACKUP_DIR = STATE_DIR / 'backups'
HISTORY_FILE = STATE_DIR / 'history.db'
RESTORE_DIR = STATE_DIR / 'restore'
DB_UPLOADS = STATE_DIR / 'db-uploads'
DAEMON_DB = [None]
COPY_RE = re.compile(r'^upsmon-copy-(\d{8}-\d{6})(-[a-z0-9-]+)?\.tar\.gz\Z')
COPY_FILES = ('upsmon.db', 'history.db', 'config.json', 'head.json')
COPY_KEY_RE = re.compile(r'^upsmon-copy-.*-with-key\.tar\.gz\.enc\Z')
TABLE_WORDS = {'samples': 'samples of the UPS (full)', 'samples_hourly': 'samples of the UPS (hourly)',
               'snapshots': 'every variable, when it changed', 'outages': 'power failures',
               'tests': 'self tests', 'plug_samples': 'samples of the plug (full)',
               'plug_hourly': 'samples of the plug (hourly)', 'sensor_samples': 'readings of the sensors'}


def history_path():
    ups = ENGINE[0].ups if ENGINE[0] is not None else None
    p = getattr(getattr(ups, 'store', None), 'path', None)
    return Path(p) if p else HISTORY_FILE


def _sqlite_copy(src, dst):
    """A consistent copy of a live SQLite file, by its own backup."""
    a = sqlite3.connect('file:%s?mode=ro' % src, uri=True, timeout=60)
    try:
        b = sqlite3.connect(str(dst))
        try:
            a.backup(b)
        finally:
            b.close()
    finally:
        a.close()


def _stamp():
    return datetime.now().strftime('%Y%m%d-%H%M%S')


def make_copy(store, label='', folder=None, progress=None):
    """A copy of both databases now: its path. The key beside it."""
    folder = Path(folder or BACKUP_DIR)
    folder.mkdir(mode=0o750, parents=True, exist_ok=True)
    name = 'upsmon-copy-%s%s.tar.gz' % (_stamp(), ('-' + re.sub(r'[^a-z0-9-]', '', label)) if label else '')
    work = Path(tempfile.mkdtemp(prefix='upsmon-copy-', dir=str(STATE_DIR)))
    try:
        if progress:
            progress(1, 4, 'upsmon.db')
        _sqlite_copy(store.db.path, work / 'upsmon.db')
        hp = history_path()
        if hp.exists():
            if progress:
                progress(2, 4, 'history.db')
            _sqlite_copy(hp, work / 'history.db')
        try:
            shutil.copyfile(str(CONFIG_FILE), str(work / 'config.json'))
        except OSError:
            pass
        head = {'upsmon': __version__, 'made': time.time(), 'node': node_name(),
                'host': socket.getfqdn(), 'site': CONFIG.get('site_name') or '',
                'files': sorted(p.name for p in work.iterdir())}
        (work / 'head.json').write_text(json.dumps(head, indent=1))
        if progress:
            progress(3, 4, 'packed')
        tmp = folder / ('.' + name + '.part')
        with tarfile.open(str(tmp), 'w:gz', compresslevel=6) as tf:
            for p in sorted(work.iterdir()):
                tf.add(str(p), arcname=p.name)
        os.chmod(str(tmp), 0o640)
        os.replace(str(tmp), str(folder / name))
        key = sealing_key(make=True)
        if key:
            kp = folder / (name + '.key')
            fd = os.open(str(kp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(key.hex() + '\n')
        if progress:
            progress(4, 4, 'done')
        return folder / name
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def kept_copies():
    out = []
    try:
        names = os.listdir(str(BACKUP_DIR))
    except OSError:
        return out
    for n in names:
        if not COPY_RE.match(n):
            continue
        p = BACKUP_DIR / n
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({'name': n, 'bytes': st.st_size, 'at': st.st_mtime,
                    'key': (BACKUP_DIR / (n + '.key')).exists(), 'from': 'sqlite', 'kind': 'copy'})
    return sorted(out, key=lambda x: x['at'], reverse=True)


def copies_prune(keep=None):
    keep = int(keep or CONFIG.get('backup_keep') or 14)
    for c in kept_copies()[keep:]:
        for p in (BACKUP_DIR / c['name'], BACKUP_DIR / (c['name'] + '.key')):
            try:
                p.unlink()
            except OSError:
                pass


def copy_unpack(path, work):
    """A copy's files into `work`, nothing but the ones a copy has."""
    work = Path(work)
    try:
        tf = tarfile.open(str(path), 'r:gz')
    except (tarfile.TarError, OSError) as e:
        raise ValueError('that is not a copy of upsmon (%s)' % e)
    with tf:
        seen = []
        for m in tf.getmembers():
            if not m.isfile() or m.name not in COPY_FILES:
                raise ValueError('that is not a copy of upsmon: it has %r' % m.name[:80])
            if m.size > 8 * 1024 ** 3:
                raise ValueError('%s is far too big' % m.name)
            with tf.extractfile(m) as s, open(str(work / m.name), 'wb') as d:
                shutil.copyfileobj(s, d)
            seen.append(m.name)
    if 'upsmon.db' not in seen and 'history.db' not in seen:
        raise ValueError('that is not a copy of upsmon: neither database is in it')
    return seen


def _sqlite_counts(p):
    out = {}
    c = sqlite3.connect('file:%s?mode=ro' % p, uri=True)
    try:
        for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"):
            out[t] = c.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
        ok = c.execute('PRAGMA quick_check').fetchone()[0]
    finally:
        c.close()
    return out, ok


def copy_peek(path, key_file=None):
    """What a copy holds, read without putting any of it back."""
    work = Path(tempfile.mkdtemp(prefix='upsmon-peek-', dir=str(STATE_DIR)))
    try:
        seen = copy_unpack(path, work)
        counts, tables, admins = {}, 0, 0
        for f in ('upsmon.db', 'history.db'):
            if f in seen:
                got, ok = _sqlite_counts(work / f)
                if ok != 'ok':
                    raise ValueError('%s in it is damaged: %s' % (f, ok))
                tables += len(got)
                for k, v in got.items():
                    counts[k if f == 'upsmon.db' or k not in counts else 'history.' + k] = v
        if 'upsmon.db' in seen:
            c = sqlite3.connect('file:%s?mode=ro' % (work / 'upsmon.db'), uri=True)
            try:
                admins = c.execute("SELECT COUNT(*) FROM accounts WHERE role = 'fulladmin' AND "
                                   "COALESCE(disabled, 0) = 0").fetchone()[0]
            except sqlite3.Error:
                admins = 0
            finally:
                c.close()
        head, conf = {}, None
        try:
            head = json.loads((work / 'head.json').read_text())
        except (OSError, ValueError):
            pass
        try:
            conf = json.loads((work / 'config.json').read_text())
            for k in list(conf):
                if 'password' in k or k in ('pin',):
                    conf[k] = '•••' if conf[k] else ''
        except (OSError, ValueError):
            conf = None
        return {'kind': 'copy', 'bytes': os.path.getsize(str(path)), 'tables': tables,
                'counts': counts, 'admins': admins, 'version': head.get('upsmon') or '',
                'files': seen, 'key_beside': bool(key_file and os.path.exists(str(key_file))),
                'machine': {'node': head.get('node'), 'host': head.get('host'),
                            'in_use': {'db_engine': 'sqlite'}, 'config': conf,
                            'config_file': str(CONFIG_FILE)}}
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


RESTART_AFTER = {'at': 0.0}


def restart_soon(why, secs=2.0):
    """The daemon ends a moment after the answer has gone; systemd starts it
    again (Restart=on-failure), and it opens the databases put back."""
    RESTART_AFTER['at'] = time.time() + secs
    if ENGINE[0] is None:
        return                          # the command line: systemctl restart upsmon does it

    def go():
        time.sleep(secs)
        log('restarting: %s' % why, 'warn')
        os._exit(75)
    threading.Thread(target=go, name='restart', daemon=True).start()


def copy_restore(store, path, by, key_file=None, from_name='', key_hex=None):
    """A copy put back: laid down for the start, a copy of what it replaces
    made first, the daemon restarted."""
    says = copy_peek(path, key_file)
    if 'upsmon.db' in says['files'] and not says['admins']:
        raise ValueError('there is no full administrator in it who could sign in afterwards - '
                         'not put back')
    safety = make_copy(store, 'before-restore')
    shutil.rmtree(str(RESTORE_DIR), ignore_errors=True)
    RESTORE_DIR.mkdir(mode=0o700)
    seen = copy_unpack(path, RESTORE_DIR)
    key_words = 'the key in use stays'
    k = key_hex
    if not k and key_file and os.path.exists(str(key_file)):
        k = open(str(key_file)).read().strip()
    if k:
        try:
            if len(bytes.fromhex(k)) == 32:
                (RESTORE_DIR / 'secrets.key').write_text(k + '\n')
                key_words = 'the key that came with it is in use'
        except ValueError:
            pass
    (RESTORE_DIR / 'ready').write_text(json.dumps({'by': by, 'from': from_name or str(path),
                                                    'files': seen, 'at': time.time()}))
    store.add_event('settings', '%s put the copy %s back (both databases); what it replaced is '
                    'in %s - the service restarts' % (by, from_name or os.path.basename(str(path)),
                                                      safety.name), 'warn', who=by)
    restart_soon('a copy of the databases is being put back')
    return {'safety': safety.name, 'key': key_words, 'says': says}


def apply_pending_restore(log_fn=None):
    """At the start of the daemon, before a database is opened: a copy laid
    down to be put back goes into place."""
    say = log_fn or (lambda w, level='info': log(w, level))
    ready = RESTORE_DIR / 'ready'
    if not ready.exists():
        return False
    try:
        info = json.loads(ready.read_text())
    except (OSError, ValueError):
        info = {}
    for f, dst in (('upsmon.db', DB_FILE), ('history.db', HISTORY_FILE)):
        src = RESTORE_DIR / f
        if not src.exists():
            continue
        for suffix in ('-wal', '-shm'):
            try:
                os.unlink(str(dst) + suffix)
            except OSError:
                pass
        os.replace(str(src), str(dst))
    k = RESTORE_DIR / 'secrets.key'
    if k.exists():
        os.replace(str(k), str(STATE_DIR / 'secrets.key'))
        os.chmod(str(STATE_DIR / 'secrets.key'), 0o600)
    shutil.rmtree(str(RESTORE_DIR), ignore_errors=True)
    say('the copy %s is put back (by %s)' % (info.get('from') or '?', info.get('by') or '?'), 'warning')
    return True


def keyed_bundle(copy_path, passphrase, out):
    """A copy and the key that opens its secrets in one file, locked with a
    passphrase (openssl enc, AES-256-CBC, PBKDF2)."""
    work = Path(tempfile.mkdtemp(prefix='upsmon-keyed-', dir=str(STATE_DIR)))
    try:
        inner = work / 'b.tar'
        with tarfile.open(str(inner), 'w') as tf:
            tf.add(str(copy_path), arcname='copy.tar.gz')
            kp = work / 'secrets.key'
            kp.write_text((sealing_key(make=True) or b'').hex() + '\n')
            tf.add(str(kp), arcname='secrets.key')
        _openssl(['enc', '-aes-256-cbc', '-pbkdf2', '-iter', str(RB_ITER), '-md', 'sha256', '-salt',
                  '-in', str(inner), '-out', str(out), '-pass', 'env:UPSMON_DBK'],
                 env={'UPSMON_DBK': passphrase}, what='locking it')
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def keyed_open(path, passphrase, work):
    """(the copy in it, the key's hex) - or ValueError."""
    work = Path(work)
    inner = work / 'b.tar'
    try:
        _openssl(['enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', str(RB_ITER), '-md', 'sha256',
                  '-in', str(path), '-out', str(inner), '-pass', 'env:UPSMON_DBK'],
                 env={'UPSMON_DBK': passphrase}, what='opening it')
    except ValueError:
        raise ValueError('the passphrase does not open it (or the file is damaged)')
    with tarfile.open(str(inner), 'r') as tf:
        for m in tf.getmembers():
            if not m.isfile() or m.name not in ('copy.tar.gz', 'secrets.key'):
                raise ValueError('that is not a copy of upsmon with its key')
            with tf.extractfile(m) as s, open(str(work / m.name), 'wb') as d:
                shutil.copyfileobj(s, d)
    k = (work / 'secrets.key').read_text().strip() if (work / 'secrets.key').exists() else ''
    return work / 'copy.tar.gz', k


DB_TICKETS = {}


def db_view(store):
    files = [(store.db.path, 'upsmon.db', 'accounts, settings of the pages, events, certificates'),
             (str(history_path()), 'history.db', 'the UPS, the plug and the sensors: samples, events, tests')]
    tables, size, parts, free = [], 0, [], 0
    for path, nick, what in files:
        try:
            got, _ = _sqlite_counts(path)
        except (sqlite3.Error, OSError):
            got = {}
        for t, n in got.items():
            tables.append({'table': ('history.' + t) if nick == 'history.db' and t in ('events', 'meta') else t,
                           'rows': n, 'bytes': None})
        for suffix in ('', '-wal', '-shm'):
            try:
                b = os.path.getsize(path + suffix)
            except OSError:
                continue
            size += b
            parts.append({'name': os.path.basename(path + suffix), 'what': what if not suffix else
                          'its write-ahead log' if suffix == '-wal' else 'its shared memory', 'bytes': b})
        try:
            c = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
            try:
                free += c.execute('PRAGMA freelist_count').fetchone()[0] * c.execute('PRAGMA page_size').fetchone()[0]
            finally:
                c.close()
        except sqlite3.Error:
            pass
    copies = kept_copies()
    cb = sum(c['bytes'] for c in copies)
    if copies:
        parts.append({'name': 'backups/', 'what': '%d copy(copies) kept' % len(copies), 'bytes': cb})
    try:
        du = shutil.disk_usage(str(STATE_DIR))
        disk = {'total': du.total, 'free': du.free, 'share': round(100.0 * (du.total - du.free) / du.total),
                'where': str(STATE_DIR), 'holds': 'both databases and the copies kept beside them'}
    except OSError:
        disk = {}
    grew = db_growth(store, size)
    if disk and grew.get('a_day'):
        disk['days_left'] = int(disk['free'] / grew['a_day'])
    counts = {t['table']: t['rows'] for t in tables}
    return {'engine': 'sqlite', 'where': store.db.path, 'version': 'SQLite ' + sqlite3.sqlite_version,
            'size': size, 'config_file': str(CONFIG_FILE), 'tables': tables, 'counts': counts,
            'key': str(sealing_key_path()), 'key_there': bool(sealing_key()), 'free': free,
            'copies': copies, 'dumps': [], 'keep': int(CONFIG.get('backup_keep') or 14),
            'backup_dir': str(BACKUP_DIR), 'dump_dir': str(BACKUP_DIR),
            'dump': {'ready': True, 'words': 'a copy of both files', 'suffix': '.tar.gz'},
            'disk': disk, 'growth': grew, 'parts': parts, 'cache': None, 'drivers': {},
            'erasable': db_erasable(store), 'tune': None, 'job': job_read()}


def db_growth(store, size):
    """How fast the files grow: the size noted once a day, the slope of a fortnight."""
    try:
        seen = json.loads(store.get_meta('db:sizes') or '[]')
    except ValueError:
        seen = []
    day = datetime.now().strftime('%Y-%m-%d')
    if not seen or seen[-1][0] != day:
        seen.append([day, size, time.time()])
        seen = seen[-15:]
        store.set_meta('db:sizes', json.dumps(seen))
    if len(seen) < 2:
        return {}
    a, b = seen[0], seen[-1]
    days = max(1.0, (b[2] - a[2]) / 86400)
    per = (b[1] - a[1]) / days
    return {'a_day': int(per) if per > 0 else 0, 'over_days': int(round(days))}


ERASE_GROUPS = (
    ('history', 'The history of the UPS', 'Every sample the charts are drawn from, full and hourly, and every '
     'variable as it changed. The charts start again from now.'),
    ('events', 'The events of the UPS', 'Power failures as events, status changes, commands run.'),
    ('outages', 'The power failures', 'How long each lasted and how far the battery fell.'),
    ('tests', 'The self tests', 'Every test followed, with the voltage of the battery.'),
    ('plug', 'The history of the plug', 'Power, energy, voltage and the rest, full and hourly.'),
    ('sensor', 'The readings of the sensors', 'Temperature, humidity, battery and signal.'),
    ('audit', 'The events of these pages', 'Every sign-in, every change of an account, a setting or a '
     'certificate, every upgrade.'),
)


def db_erasable(store):
    ups = ENGINE[0].ups if ENGINE[0] is not None else None
    groups, total = [], 0
    for key, name, says in ERASE_GROUPS:
        rows = 0
        try:
            if key == 'audit':
                rows = int(store.db.value('SELECT COUNT(*) FROM events', (), 0) or 0)
            elif ups is not None:
                rows = sum(ups.store.counts(ups.store.RESET_SCOPES[key]).values())
        except Exception:                               # noqa: BLE001
            rows = 0
        groups.append({'key': key, 'name': name, 'says': says, 'rows': rows})
    try:
        total = sum(os.path.getsize(p) for p in (store.db.path, str(history_path())) if os.path.exists(p))
    except OSError:
        total = 0
    return {'groups': groups, 'bytes': total}


def db_check(store):
    said, ok = [], True
    for path in (store.db.path, str(history_path())):
        try:
            c = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
            try:
                got = [r[0] for r in c.execute('PRAGMA integrity_check')]
            finally:
                c.close()
        except sqlite3.Error as e:
            got = [str(e)]
        good = got == ['ok']
        ok = ok and good
        said.append('%s: %s' % (os.path.basename(path), 'ok' if good else '; '.join(got[:20])))
    return {'ok': ok, 'said': said}


def db_give_back(store, progress):
    before = sum(os.path.getsize(p) for p in (store.db.path, str(history_path())) if os.path.exists(p))
    progress(1, 2, 'upsmon.db')
    with store.db.lock:
        store.db.conn.execute('VACUUM')
    progress(2, 2, 'history.db')
    ups = ENGINE[0].ups if ENGINE[0] is not None else None
    if ups is not None:
        with ups.store.lock:
            ups.store.connection().execute('VACUUM')
    after = sum(os.path.getsize(p) for p in (store.db.path, str(history_path())) if os.path.exists(p))
    return {'before': before, 'after': after}


def db_erase(store, groups, tidy, by, progress):
    copy = make_copy(store, 'before-erase')
    ups = ENGINE[0].ups if ENGINE[0] is not None else None
    n = 0
    for g in groups:
        n += 1
        progress(n, len(groups) + (1 if tidy else 0), g)
        if g == 'audit':
            store.db.run('DELETE FROM events')
        elif ups is not None and g in ups.store.RESET_SCOPES:
            ups.reset_data(g)
    if tidy:
        progress(n + 1, n + 1, 'the disk given back')
        with store.db.lock:
            store.db.conn.execute('VACUUM')
    store.add_event('settings', '%s erased %s; a copy was made first: %s'
                    % (by, ', '.join(groups), copy.name), 'warn', who=by)
    return {'erased': groups, 'copy': copy.name}


def db_prune(store, days, everything, by):
    """UPS samples, plug samples, sensor readings and events older than `days`."""
    ups = ENGINE[0].ups if ENGINE[0] is not None else None
    cutoff = 0 if everything else int(time.time() - days * 86400)
    n = 0
    if ups is not None:
        with ups.store.lock:
            conn = ups.store.connection()
            for t in ('samples', 'samples_hourly', 'snapshots', 'events', 'plug_samples', 'plug_hourly',
                      'sensor_samples'):
                try:
                    n += conn.execute('DELETE FROM %s WHERE ts < ?' % t if cutoff else 'DELETE FROM %s' % t,
                                      (cutoff,) if cutoff else ()).rowcount
                except sqlite3.Error:
                    pass
            conn.commit()
    n += store.db.run('DELETE FROM events WHERE ts < ?', (cutoff,)) if cutoff else \
        store.db.run('DELETE FROM events')
    store.add_event('settings', '%s forgot %d record(s) %s' % (
        by, n, 'of every age' if everything else 'older than %d day(s)' % days), 'warn', who=by)
    return n


def copy_read_through(path, key=None, sample=50, child=False):
    """A copy read through (Backups → Try it): what Backups' checks want to know."""
    says = copy_peek(path)
    return {'head': {'upsmon': says.get('version')}, 'counts': says['counts'],
            'admins': says['admins'], 'tried': 0, 'opened': 0}


def dump_tables(db, f):
    raise ValueError('not used in upsmon')


def db_file_restore(store, path, by, key_file=None, from_name='', need_admin=True):
    return copy_restore(store, path, by, key_file=key_file, from_name=from_name)


def daily_copy_tick(store):
    """backup_daily: a copy of both databases a day, at backup_at, backup_keep kept."""
    if not CONFIG.get('backup_daily'):
        return
    due, day = _due('daily', '', CONFIG.get('backup_at') or '03:30')
    if not due or store.get_meta('db:copy:day') == day:
        return
    store.set_meta('db:copy:day', day)
    try:
        p = make_copy(store, 'daily')
        copies_prune()
        log('the daily copy of the databases: %s' % p.name)
    except Exception as e:                              # noqa: BLE001
        store.add_event('settings', 'the daily copy of the databases was not made: %s' % e, 'bad')


@route('GET', '/api/db')
def _db(h):
    h.me()
    return db_view(h.store)


@route('POST', '/api/db')
def _db_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    who = s['name']
    store = h.store
    try:
        if act == 'job':
            return {'job': job_read()}
        if act == 'backup':
            p = make_copy(store, 'by-hand')
            copies_prune()
            store.add_event('settings', '%s made a copy of the databases: %s' % (who, p.name), who=who)
            return {'message': 'a copy was made: %s (%s)' % (p.name, human_bytes(p.stat().st_size))}
        if act == 'check':
            return db_check(store)
        if act == 'tidy':
            ups = ENGINE[0].ups if ENGINE[0] is not None else None
            rolled = ups.store.aggregate() if ups is not None else 0
            gone = store.db.run('DELETE FROM events WHERE ts < ?', (time.time() - 730 * 86400,))
            return {'message': 'done: %d hour(s) of samples rolled up, %d old event(s) forgotten' % (rolled, gone)}
        if act == 'prune':
            n = db_prune(store, max(1, int(b.get('days') or 90)), bool(b.get('everything')), who)
            return {'message': '%d record(s) forgotten' % n}
        if act == 'give_back':
            return {'job': db_job('giving the disk back', lambda p: db_give_back(store, p))}
        if act == 'erase':
            groups = [g for g in (b.get('groups') or []) if g in dict((x[0], 1) for x in ERASE_GROUPS)]
            if not groups:
                raise ValueError('nothing ticked')
            return {'job': db_job('erasing', lambda p: db_erase(store, groups, bool(b.get('tidy')), who, p))}
        if act == 'delete':
            name = str(b.get('name') or '')
            if not COPY_RE.match(name):
                raise ValueError('no such copy')
            for p in (BACKUP_DIR / name, BACKUP_DIR / (name + '.key')):
                try:
                    p.unlink()
                except OSError:
                    pass
            store.add_event('settings', '%s deleted the copy %s' % (who, name), 'warn', who=who)
            return {'message': '%s is deleted' % name}
        if act == 'restore_kept':
            name = str(b.get('name') or '')
            if not COPY_RE.match(name) or not (BACKUP_DIR / name).exists():
                raise ValueError('no such copy')
            if b.get('check'):
                return {'says': copy_peek(BACKUP_DIR / name, BACKUP_DIR / (name + '.key'))}
            return copy_restore(store, BACKUP_DIR / name, who, key_file=BACKUP_DIR / (name + '.key'),
                                from_name=name)
        if act == 'download_ticket':
            pp = str(b.get('passphrase') or '')
            if len(pp) < 10:
                raise ValueError('a passphrase of 10 characters at least')
            name = str(b.get('name') or '')
            if name:
                if not COPY_RE.match(name) or not (BACKUP_DIR / name).exists():
                    raise ValueError('no such copy')
                src = BACKUP_DIR / name
            else:
                src = make_copy(store, 'download')
                copies_prune()
            DB_UPLOADS.mkdir(mode=0o700, exist_ok=True)
            out_name = src.name[:-len('.tar.gz')] + '-with-key.tar.gz.enc'
            ticket = secrets.token_hex(16)
            out = DB_UPLOADS / ('dl-' + ticket)
            keyed_bundle(src, pp, out)
            DB_TICKETS[ticket] = {'path': str(out), 'name': out_name, 'who': who, 'at': time.time()}
            store.add_event('settings', '%s downloaded %s with its key, locked' % (who, out_name), 'warn', who=who)
            return {'ticket': ticket, 'name': out_name}
        if act == 'upload_restore':
            up = re.sub(r'[^a-f0-9]', '', str(b.get('upload') or ''))[:32]
            p = DB_UPLOADS / ('up-' + up)
            if not up or not p.exists():
                raise ValueError('that upload is not here any more - send the file again')
            work = Path(tempfile.mkdtemp(prefix='upsmon-up-', dir=str(STATE_DIR)))
            try:
                copy, k = keyed_open(p, str(b.get('passphrase') or ''), work)
                if b.get('check'):
                    return {'says': copy_peek(copy)}
                got = copy_restore(store, copy, who, key_hex=k, from_name='an uploaded copy with its key')
                p.unlink()
                return got
            finally:
                shutil.rmtree(str(work), ignore_errors=True)
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'that is not something done here on upsmon (one SQLite server)')


@route('GET', '/api/db/download')
def _db_download(h):
    s = h.me('fulladmin')
    t = re.sub(r'[^a-f0-9]', '', h.arg('ticket'))
    if t:
        got = DB_TICKETS.pop(t, None)
        if not got or got['who'] != s['name'] or time.time() - got['at'] > 600:
            raise ApiError(404, 'that download is not here any more')
        try:
            h.send_file(got['path'], got['name'])
        finally:
            try:
                os.unlink(got['path'])
            except OSError:
                pass
        return None
    name = h.arg('name')
    if name:
        if not COPY_RE.match(name) or not (BACKUP_DIR / name).exists():
            raise ApiError(404, 'there is no such copy')
        h.send_file(BACKUP_DIR / name, name)
        return None
    p = make_copy(h.store, 'download')
    copies_prune()
    h.send_file(p, p.name)
    return None


@route('POST', '/api/db/restore')
def _db_restore(h):
    s = h.me('fulladmin')
    DB_UPLOADS.mkdir(mode=0o700, exist_ok=True)
    up = secrets.token_hex(16)
    p = DB_UPLOADS / ('up-' + up)
    h.body_to_file(p, 8 * 1024 ** 3)
    with open(str(p), 'rb') as f:
        head = f.read(8)
    if head.startswith(b'Salted__'):
        return {'upload': up}
    try:
        if h.arg('check'):
            got = {'says': copy_peek(p)}
            return got
        return copy_restore(h.store, p, s['name'], from_name='an uploaded copy')
    except ValueError as e:
        raise ApiError(400, str(e))
    finally:
        if not h.arg('check') or not head.startswith(b'Salted__'):
            try:
                p.unlink()
            except OSError:
                pass

# ---------------------------------------------------------------------------
# The settings in effect: the defaults, then /etc/upsmon/config.json (only the
# keys of these pages - the UPS's own keys are upsmon.py's), then what was
# saved on the pages.
# ---------------------------------------------------------------------------
def load_config(path=None, saved=None):
    global FILE_CONFIG, FILE_KEYS
    where = Path(path) if path else CONFIG_FILE
    fresh = dict(DEFAULTS)
    named, refused = set(), []
    try:
        with open(where, encoding='utf-8') as f:
            given = json.load(f)
        if isinstance(given, dict):
            for key, value in given.items():
                if key in fresh:
                    try:
                        fresh[key] = _coerce(fresh[key], value)
                        named.add(key)
                    except BadSetting as bad:
                        refused.append('%s (%s)' % (key, bad))
    except (OSError, ValueError):
        pass
    FILE_CONFIG = dict(fresh)
    FILE_KEYS = named
    whole = dict(fresh)
    for key, value in (saved or {}).items():
        if key in DEFAULTS:
            try:
                whole[key] = _coerce(DEFAULTS[key], value)
            except BadSetting:
                pass
    whole.update(FROM_ARGV)
    CONFIG.clear()
    CONFIG.update(whole)
    BAD_CONFIG[:] = sorted(refused)
    return CONFIG


# ---------------------------------------------------------------------------
# The engine: what upsmon's daemon is to its pages, for upsmon's settings
# ---------------------------------------------------------------------------
class Engine(object):
    TICK_S = 3

    def __init__(self, ups=None):
        import collections
        self.ups = ups                          # upsmon.py's daemon, for About
        ENGINE[0] = self
        self.store = Storage()
        HA_STORE['store'] = self.store
        self.started = time.time()
        self.login_fails = collections.defaultdict(list)
        self.login_info = {}
        self.api = None
        self.stopping = threading.Event()
        self.reload_all()
        for d in (WEB_DIR, UPGRADE_DIR):
            try:
                d.mkdir(mode=0o750, exist_ok=True)
            except OSError:
                pass

    def reader(self):
        return self.store

    def cluster_nodes(self):
        return [node_name()]

    def changed(self, what):
        pass

    def reload_all(self):
        load_config(saved=self.store.settings_saved())

    def save_settings(self, changes, by='', node=None, drawn_by=None, keep_session=None):
        checked = {}
        for key, value in (changes or {}).items():
            if key in SECRET_KEYS and is_masked(value):
                continue
            checked[key] = check_setting(key, value)
            if key in SEALED_KEYS and checked[key]:
                checked[key] = seal_secret(checked[key])
        for k, v in checked.items():
            if v == FILE_CONFIG.get(k, DEFAULTS[k]):
                self.store.drop_setting(k)
            else:
                self.store.save_setting(k, v, by)
        if checked:
            self.store.add_event('settings', 'changed: %s' % ', '.join(
                '%s=%s' % (k, '***' if k in SECRET_KEYS else json.dumps(v, ensure_ascii=False))
                for k, v in sorted(checked.items())), who=by)
        self.reload_all()
        said = []
        if 'admin_port' in checked:
            said.append('the new port is used when the service is restarted (systemctl restart upsmon)')
        return {'message': ' '.join(['%d setting(s) saved.' % len(checked)] + said),
                'saved': sorted(checked)}

    def settings_state(self, may_change=True):
        out = []
        saved = self.store.settings_saved()
        written = self.store.settings_written()
        for key in DEFAULTS:
            if key in HIDDEN_KEYS:
                continue
            value = CONFIG.get(key)
            shape = TUNABLE.get(key)
            source = 'saved' if key in saved else ('file' if key in FILE_KEYS else 'default')
            one = {'key': key, 'value': value, 'default': DEFAULTS[key],
                   'name': NAMES.get(key, key), 'says': SAYS.get(key, ''),
                   'short': SAYS_SHORT.get(key, ''),
                   'secret': key in SECRET_KEYS, 'source': source,
                   'source_says': {'saved': 'saved on these pages',
                                   'file': 'from config.json',
                                   'default': 'the built-in default'}[source],
                   'in_file': key in FILE_KEYS,
                   'file': FILE_CONFIG.get(key) if key in FILE_KEYS else None,
                   'file_only': False, 'node_key': False, 'hisec': None}
            if key in written:
                one['saved_at'] = written[key]['at']
                one['saved_by'] = written[key]['by']
            if key in SECRET_KEYS:
                plain = unseal_secret(value) if key in SEALED_KEYS else value
                one['value'] = secret_shown(plain or '') if may_change else ''
                one['set'] = bool(value)
                one['file'] = None
            if isinstance(shape, tuple) and shape and isinstance(shape[0], str):
                one['choices'] = list(shape)
                if key in CHOICE_WORDS:
                    one['choice_words'] = CHOICE_WORDS[key]
            elif isinstance(shape, tuple):
                one['min'], one['max'] = shape
            out.append(one)
        return out

    def ups_words(self):
        """The UPS as the dashboard sees it, for the header of these pages."""
        u = self.ups
        if u is None:
            return {}
        try:
            with u.lock:
                snap = dict(u.snapshot or {})
            v = snap.get('vars') or {}
            return {'level': snap.get('level') or 'unknown', 'status': v.get('ups.status') or '',
                    'status_text': snap.get('status_text') or '', 'charge': v.get('battery.charge'),
                    'load': v.get('ups.load'), 'runtime': v.get('battery.runtime'),
                    'name': getattr(u, 'ups_name', '') or '', 'version': __version__}
        except Exception:                               # noqa: BLE001
            return {}

    def status(self):
        problems = list(BAD_CONFIG and ['config.json: ' + ', '.join(BAD_CONFIG)] or [])
        ev = self.store.db.value('SELECT MAX(id) AS n FROM events', (), 0) or 0
        st = web_status()
        if st.get('state') == 'failed':
            problems.append('the web server could not be given its certificate: %s'
                            % '; '.join(st.get('said') or [])[:300])
        try:
            info = cert_now(NGINX_CERT_FILES['node'])
            if info and info.get('not_after') and info['not_after'] < time.time():
                problems.append('the certificate of the web server ran out on %s' % stamp(info['not_after']))
        except Exception:                               # noqa: BLE001
            pass
        return {
            'ok': True, 'version': __version__, 'site': CONFIG.get('site_name') or short_host(),
            'host': socket.gethostname(), 'started': self.started,
            'uptime': time.time() - self.started, 'now': time.time(),
            'serial': '%s' % ev, 'problems': problems,
            'database': {'engine': 'sqlite', 'where': self.store.db.where()},
            'lang': CONFIG.get('ui_lang') or 'cs', 'php': php_state(),
            'high_security': False, 'hisec_waived': [],
            'node': node_name(), 'nodes': [{'name': node_name(), 'alive': True, 'age': 0}],
            'ups': self.ups_words(), 'trials': [],
            'accounts': int(self.store.db.value('SELECT COUNT(*) FROM accounts', (), 0) or 0),
            'maintenance': maintenance_row(self.store),
        }

    # ---- the loop -----------------------------------------------------------------
    def tick(self):
        for name, fn in (('web', lambda: web_tick(self.store)), ('acme', lambda: acme_tick(self)),
                         ('online', lambda: online_tick(self)), ('upgrade', lambda: upgrade_tick(self)),
                         ('console', lambda: console_login_tick(self)),
                         ('lockouts', lambda: lockouts_publish(self)),
                         ('time', lambda: ntp_tick(self)), ('power', lambda: power_tick(self)),
                         ('updates', lambda: osup_tick(self)), ('schedule', lambda: osup_sched_tick(self)),
                         ('backups', lambda: rb_tick(self)), ('copies', lambda: daily_copy_tick(self.store))):
            try:
                fn()
            except Exception as e:                      # noqa: BLE001
                log_sparing('tick-' + name, 'settings: %s: %s\n%s' % (name, e, traceback.format_exc()),
                            'warn', every=600)

    def loop(self):
        last_tidy = 0.0
        while not self.stopping.is_set():
            self.tick()
            if time.time() - last_tidy > 3600:
                last_tidy = time.time()
                try:
                    self.store.sessions_tidy(int(CONFIG.get('session_idle_min') or 120) * 60)
                    self.store.events_tidy()
                except Exception as e:                  # noqa: BLE001
                    log('settings: tidying: %s' % e, 'warn')
            self.stopping.wait(self.TICK_S)

    def start(self):
        maintenance_ensure(self.store)
        self.api = ApiServer(self)
        self.api.start()
        threading.Thread(target=self.loop, name='settings', daemon=True).start()
        self.store.add_event('starting and stopping', 'upsmon %s started on %s' % (__version__, node_name()))
        return self


def start(ups=None, logger=None):
    """Called by upsmon.py's daemon: the settings engine in threads of its own."""
    if logger:
        set_logger(logger)
    return Engine(ups).start()


def open_store():
    """For the command line: the database, the settings read."""
    store = Storage()
    load_config(saved=store.settings_saved())
    return store


# ---------------------------------------------------------------------------
# The command line of the settings: upsmon.py hands these flags over
# ---------------------------------------------------------------------------
def otp_argv(here=None):
    """How upsmon runs itself again (the console's commands)."""
    return [sys.executable, '-I', str(LIB_DIR / 'upsmon.py')]


def service_ids():
    try:
        import pwd
        pw = pwd.getpwnam(SERVICE_USER)
        return pw.pw_uid, pw.pw_gid
    except (KeyError, ImportError):
        return None


def cli_store():
    become_service_user()
    try:
        return open_store()
    except DbError as e:
        raise SystemExit('upsmon: %s' % e)


def add_cli_arguments(parser):
    """The flags of Settings, added to upsmon.py's parser - in OTP's groups."""
    g = parser.add_argument_group('THE ACCOUNTS OF SETTINGS')
    a = g.add_argument
    a('--users', action='store_true', help='the accounts of the settings pages')
    a('--add-user', metavar='NAME', help='make an account (the password is asked, or UPSMON_PASSWORD)')
    a('--role', choices=ROLES_ALL, help='with --add-user / --set-role: fulladmin or readonly')
    a('--note', default='', help='with --add-user: a note kept with the account')
    a('--passwd', metavar='NAME', help='set the password of an account')
    a('--set-role', metavar='NAME', help='change the role of an account (with --role)')
    a('--del-user', metavar='NAME', help='delete an account')
    a('--disable-user', metavar='NAME', help='switch an account off')
    a('--enable-user', metavar='NAME', help='switch an account on again')
    a('--lockouts', action='store_true', help='who is locked out of the pages now')
    a('--lockouts-clear', metavar='all|KIND:WHO', help='forget a lockout (as --lockouts shows it), or every one')
    g = parser.add_argument_group('THE SETTINGS')
    a = g.add_argument
    a('--settings', action='store_true', help='every setting of the pages, and where it comes from')
    a('--setting', action='append', default=[], metavar='KEY=VALUE',
      help='change a setting of the pages (KEY=- asks for a secret)')
    a('--search', default='', help='with --settings / --audit: only those with these words')
    a('--audit', action='store_true', help='the events of the settings pages: sign-ins, accounts, certificates')
    g = parser.add_argument_group('CERTIFICATES AND TLS')
    a = g.add_argument
    a('--cert', action='store_true', help='the certificate nginx has, and what upsmon keeps')
    a('--pem', action='store_true', help='with --cert: the certificate and its chain as PEM')
    a('--cert-selfsigned', metavar='NAME', help='a self-signed certificate for NAME, put in nginx')
    a('--days', type=int, default=825, help='with --cert-selfsigned: how long it lasts')
    a('--cert-export', choices=('pem', 'crt', 'der', 'pfx', 'pfx_legacy', 'pem_key', 'key'),
      help='the certificate into a file: pem, crt, der, pfx, pfx_legacy (3DES), pem_key or key - '
      'the ones with the key ask for a password (or UPSMON_PASSWORD)')
    a('--out', metavar='FILE', help='with --cert-export: the file written')
    a('--acme', action='store_true', help='the automatic certificates (ACME) and how they stand')
    a('--acme-order', nargs='?', const='all', metavar='WHICH', help='order a certificate by ACME now')
    g = parser.add_argument_group('THE DATABASE AND BACKUPS')
    a = g.add_argument
    a('--backup', action='store_true', help='a copy of both databases (history.db and upsmon.db), now')
    a('--copies', action='store_true', help='the copies kept in /var/lib/upsmon/backups')
    a('--restore', metavar='FILE', help='put a copy back (--yes); without --yes, what is in it')
    a('--restore-bundle', metavar='FILE', help='put back a backup sent to a destination '
      '(upsmon-backup-....tar.gz.enc); without --yes, what is in it')
    a('--passphrase-file', metavar='FILE', help='with --restore-bundle: the password of the backups, '
      'one line (else UPSMON_BACKUP_PASSWORD, else asked)')
    a('--rbackup-now', action='store_true', help='a backup to every destination switched on, now')
    a('--rbackup-status', action='store_true', help='the backup destinations and the last backups sent')
    a('--db-check', action='store_true', help='both databases read through (integrity check)')
    g = parser.add_argument_group('WHAT THE PAGES DO, HERE TOO')
    a = g.add_argument
    a('--time', nargs='?', const='status', choices=('status', 'sync'),
      help='the clock: how it stands (chrony), or stepped to the time servers now')
    a('--updates', choices=('status', 'check', 'start', 'cancel'), help='the updates of the operating '
      'system: how they stand, look for them now, put them in, or stop them')
    a('--reboot', choices=('ask', 'auto', 'never'), default='ask', help='with --updates start: '
      'restart when an update needs it - ask on the pages, by itself, or never')
    a('--restart-server', action='store_true', help='restart this machine now (--yes)')
    a('--poweroff-server', action='store_true', help='switch this machine off now (--yes)')
    a('--restarts', action='store_true', help='the restarts asked for, and how they went')
    g = parser.add_argument_group('MAINTENANCE AND UPGRADES')
    a = g.add_argument
    a('--upgrade-check', action='store_true', help='what is at upgrade_url, and whether it is newer')
    a('--upgrade-online', nargs='?', const='newest', metavar='VERSION',
      help='fetch the newest (or VERSION) from upgrade_url, check it and put it in')
    a('--upgrade-status', action='store_true', help='the package sent and the upgrade going on')
    a('--upgrade-follow', action='store_true', help='follow an upgrade going on')
    a('--upgrade-cancel', action='store_true', help='stop an upgrade going on')
    a('--downgrade-check', action='store_true', help='the older versions there, and which are safe')
    a('--downgrade', metavar='VERSION|FILE', help='go back to an older version (only a safe one)')
    a('--maintenance', choices=('on', 'off', 'status'), help='this server in maintenance or not')
    a('--why', default='', help='with --maintenance on: why')
    g = parser.add_argument_group('THE CONSOLE')
    a = g.add_argument
    a('--console', action='store_true', help='upsmon run by its menus, on the terminal')
    a('--console-at-login', choices=('on', 'off', 'status'),
      help='the console opens when root signs in (on), or not (off)')
    a('--console-status', action='store_true', help=argparse.SUPPRESS)
    return parser


CLI_FLAGS = ('users', 'add_user', 'passwd', 'set_role', 'del_user', 'disable_user', 'enable_user',
             'settings', 'setting', 'audit', 'cert', 'cert_selfsigned', 'acme', 'acme_order',
             'upgrade_check', 'upgrade_online', 'upgrade_status', 'upgrade_follow',
             'upgrade_cancel', 'downgrade_check', 'downgrade', 'maintenance', 'console',
             'console_at_login', 'console_status', 'lockouts', 'lockouts_clear', 'backup',
             'copies', 'restore', 'restore_bundle', 'rbackup_now', 'rbackup_status', 'db_check',
             'time', 'updates', 'restart_server', 'poweroff_server', 'restarts', 'cert_export')


def cli_wanted(args):
    return any(getattr(args, f, None) for f in CLI_FLAGS)


def cli_main(args, ups_status=None):
    """One of the flags above, done. `ups_status`: upsmon.py's word on the UPS, for
    the console's bar."""
    pal = Palette(colour_wanted(getattr(args, 'no_color', False)))
    global TABLE_PAL
    TABLE_PAL = pal
    who = 'the command line'
    as_json = bool(getattr(args, 'json', False))

    def out(data):
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))

    if args.console:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise SystemExit('upsmon: the console needs a terminal')
        return Console(pal).run()
    if args.console_at_login:
        if args.console_at_login != 'status':
            print(pal.ok_line(console_at_login_set(args.console_at_login == 'on')))
        else:
            print(pal.ok_line('the console at login is %s' % ('ON' if console_at_login()
                                                              else 'off')))
        return 0
    if args.console_status:
        got = {'node': node_name(), 'problems': [], 'maintenance': {'on': False}}
        try:
            store = cli_store()
            got['maintenance'] = maintenance_row(store)
            st = web_status()
            if st.get('state') == 'failed':
                got['problems'].append('the web server could not be given its certificate: %s'
                                       % '; '.join(st.get('said') or [])[:200])
        except SystemExit as e:
            got['problems'].append(str(e))
        except Exception as e:                          # noqa: BLE001
            got['problems'].append(str(e))
        if ups_status:
            try:
                got.update(ups_status() or {})
            except Exception:                           # noqa: BLE001
                pass
        out(got)
        return 0

    store = cli_store()
    eng = None

    def engine():
        nonlocal eng
        if eng is None:
            eng = Engine.__new__(Engine)
            eng.store, eng.ups, eng.started = store, None, time.time()
        return eng

    if args.users:
        rows = store.accounts()
        if as_json:
            out({'users': rows, 'mfa_on': False})
            return 0
        print(table([(a['name'], ROLE_WORDS.get(a['role'], a['role']),
                      'off' if a['disabled'] else 'on',
                      stamp(a['last_in']) if a['last_in'] else 'never', a['note'] or '') for a in rows],
                    ['name', 'role', 'state', 'last signed in', 'note']))
        return 0
    if args.add_user:
        pw = ask_password('a password for %s' % args.add_user, env='UPSMON_PASSWORD')
        try:
            store.add_account(args.add_user, args.role or 'readonly', pw, note=args.note)
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        store.add_event('accounts', 'the account %s was made on the command line, as %s'
                        % (args.add_user, args.role or 'readonly'), who=who)
        print(pal.ok_line('%s may now sign in to Settings, as %s' % (args.add_user, args.role or 'readonly')))
        return 0
    if args.passwd:
        pw = ask_password('a new password for %s' % args.passwd, env='UPSMON_PASSWORD')
        try:
            store.set_account(args.passwd, password=pw, must_change=0)
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                     ('admin', args.passwd.lower()))
        store.add_event('accounts', 'the password of %s was set on the command line'
                        % args.passwd, who=who)
        print(pal.ok_line('the password of %s is set' % args.passwd))
        return 0
    for flag in ('set_role', 'del_user', 'disable_user', 'enable_user'):
        name = getattr(args, flag)
        if not name:
            continue
        try:
            acc = store.account(name)
            if not acc:
                raise ValueError('there is no account called %s' % name)
            if flag == 'set_role' and not args.role:
                raise ValueError('which role? --set-role %s --role %s' % (name, '|'.join(ROLES_ALL)))
            if (flag in ('del_user', 'disable_user') or (flag == 'set_role' and args.role != 'fulladmin')) \
                    and acc.get('role') == 'fulladmin' and not store.fulladmins_left(but=name):
                raise ValueError('that is the last full administrator who can sign in')
            if flag == 'set_role':
                store.set_account(name, role=args.role)
            elif flag == 'del_user':
                store.drop_account(name)
            else:
                store.set_account(name, disabled=1 if flag == 'disable_user' else 0)
            if flag in ('set_role', 'disable_user'):
                store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                             ('admin', name.lower()))
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        store.add_event('accounts', '%s: %s on the command line' % (name, flag.replace('_', ' ')),
                        who=who)
        print(pal.ok_line('done'))
        return 0
    if args.settings:
        rows = engine().settings_state(True)
        if args.search:
            q = args.search.lower()
            rows = [r for r in rows if q in ' '.join(str(r.get(k) or '') for k in
                                                     ('key', 'name', 'short', 'says')).lower()]
        if as_json:
            out({'settings': rows})
            return 0
        for s in rows:
            print('  %-24s %-34s %s' % (s['key'], json.dumps(s['value'], ensure_ascii=False)[:34],
                                       pal.dim(s['source_says'])))
        return 0
    if args.setting:
        want = {}
        for one in args.setting:
            if '=' not in one:
                raise SystemExit('upsmon: --setting takes KEY=VALUE')
            k, v = one.split('=', 1)
            k = k.strip()
            if v in ('-', '@env'):
                env = 'UPSMON_VALUE_' + k.upper()
                v = os.environ.get(env) if v == '@env' else None
                if v is None:
                    v = ask_secret_value(k)
            want[k] = v
        try:
            said = engine().save_settings(want, by=who)
        except (BadSetting, ValueError) as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line(said['message'] + ' The running service takes it within seconds.'))
        return 0
    if args.audit:
        rows, total = store.events(int(getattr(args, 'limit', 50) or 50), 0, args.search or '')
        if as_json:
            out({'rows': rows, 'total': total})
            return 0
        print(table([(stamp(r['ts']), r['kind'], r['who'] or '', r['words']) for r in reversed(rows)],
                    ['when', 'kind', 'who', 'what'], [19, 22, 14, 90]))
        return 0
    if args.cert_export:
        prof = tls_profile(store, node_name()) or {}
        if not prof.get('cert'):
            raise SystemExit('upsmon: no certificate is kept on the pages yet')
        keyed = CERT_EXPORT[args.cert_export][3]
        pw = ''
        if keyed:
            pw = ask_password('a password for the file%s' % (' (empty: the key in the clear)'
                                                             if not args.cert_export.startswith('pfx') else ''),
                              env='UPSMON_PASSWORD')
        try:
            got = cert_export(prof, args.cert_export, pw)
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        out_ = args.out or (str((prof.get('info') or {}).get('cn') or node_name()).replace('*', '_') + got['suffix'])
        fd = os.open(out_, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if keyed else 0o644)
        with os.fdopen(fd, 'wb') as f:
            f.write(got['data'])
        store.add_event('settings', 'the certificate was exported on the command line (%s)%s'
                        % (got['words'], ' WITH its private key' if keyed else ''),
                        'warn' if keyed else 'info', who=who)
        print(pal.ok_line('%s - %s' % (out_, got['words'])))
        return 0
    if args.cert or args.cert_selfsigned:
        me = node_name()
        if args.cert_selfsigned:
            try:
                key, crt = make_selfsigned(args.cert_selfsigned.strip(), [], int(args.days or 825))
                got = cert_bundle(crt, key)
            except ValueError as e:
                raise SystemExit('upsmon: %s' % e)
            prof = tls_profile(store, me) or {}
            prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                        key=seal_secret(got['key'], 'web:tls'), info=got['info'],
                        chain_info=got['chain_info'], root_info=got['root_info'],
                        verify=got['verify'], how='self-signed, made here')
            prof.pop('pending_key', None)
            prof.pop('csr', None)
            prof.setdefault('preset', 'standard')
            prof.setdefault('dh', 'none')
            tls_save(store, me, prof, who)
            store.add_event('settings', 'a self-signed certificate for %s was made on the command line'
                            % args.cert_selfsigned, 'warn', who=who)
            print(pal.ok_line('kept; the service puts it in nginx within a few seconds'))
            return 0
        prof = tls_profile(store, me) or {}
        if args.pem:
            if not prof.get('cert'):
                raise SystemExit('upsmon: no certificate is kept on the pages yet (nginx has its own: %s)'
                                 % NGINX_CERT_FILES['node'])
            sys.stdout.write(prof['cert'] + (prof.get('chain') or ''))
            return 0
        now_ = cert_now(NGINX_CERT_FILES['node'])
        view = {'nginx': now_, 'kept': tls_view(prof), 'root_said': web_status()}
        if as_json:
            out(view)
            return 0
        print(pal.head('the certificate nginx has (%s)' % NGINX_CERT_FILES['node']))
        if now_:
            for k in ('subject', 'issuer', 'san', 'not_before', 'not_after', 'key', 'fingerprint'):
                v = now_.get(k)
                if k in ('not_before', 'not_after') and v:
                    v = stamp(v)
                print('  %-12s %s' % (k, ', '.join(v) if isinstance(v, list) else v))
        else:
            print('  ' + pal.dim('none readable here'))
        info = (prof or {}).get('info') or {}
        print(pal.head('kept on the pages') + pal.dim('  (%s)' % (prof.get('how') or 'nothing')))
        if info:
            print('  %-12s %s' % ('subject', info.get('subject')))
            print('  %-12s %s' % ('until', stamp(info.get('not_after')) if info.get('not_after') else '-'))
        st = web_status()
        if st:
            print(pal.head('root said last') + pal.dim('  (%s)' % stamp(st.get('at')) if st.get('at') else ''))
            for s in st.get('said') or []:
                print('  ' + s)
        return 0
    if args.acme:
        v = acme_view(store)
        if as_json:
            out(v)
            return 0
        print(pal.head('certificates by ACME: %s - %s, %s' % (
            'on' if v['on'] else 'off (upsmon --setting acme=1)', v['directory'] or '-', v['challenge'])))
        rows = []
        for t in v['targets']:
            st_ = t.get('state') or {}
            left = (float(t['not_after']) - time.time()) / 86400 if t.get('not_after') else None
            rows.append((t['target'], t.get('name') or '(no name)', '%.0f days' % left if left is not None
                         else '-', 'ACME' if t.get('care') else 'by hand', (
                             ('ok ' if st_.get('ok') else 'failed ') + stamp(st_.get('at')) +
                             ('' if st_.get('ok') else ': %s' % (st_.get('said') or st_.get('error') or '')))
                         if st_.get('at') else 'never ordered'))
        print(table(rows, ['for', 'name', 'left', 'looked after', 'last order'], [10, 30, 9, 12, 60]))
        return 0
    if args.acme_order:
        if not CONFIG.get('acme'):
            raise SystemExit('upsmon: certificates by ACME are off - upsmon --setting acme=1 (and acme_*) first')
        if args.acme_order == 'all':
            which = acme_targets(store)
            if not which:
                raise SystemExit('upsmon: no certificate is looked after by ACME here (upsmon --acme)')
        else:
            t = args.acme_order
            if t not in tls_targets(store):
                raise SystemExit('upsmon: there is no such certificate: %s' % ', '.join(tls_targets(store)))
            name = acme_name_of(store, t)
            if not name:
                raise SystemExit('upsmon: the name of the certificate is not known - '
                                 'upsmon --setting acme_node_name=NAME')
            acme_care_set(store, t, True, who, 'ordered by hand')
            which = [(t, name)]
        bad = 0
        for t, name in which:
            print(pal.head('%s: %s' % (t, name)))
            try:
                acme_order(store, t, name, who, lambda w: print('  ' + str(w)))
                print(pal.ok_line('the certificate of %s is made; the service puts it in within a few '
                                  'seconds' % name))
            except (AcmeError, ValueError, OSError) as e:
                bad += 1
                print(pal.bad_line(str(e)))
        return 1 if bad else 0
    if args.lockouts or args.lockouts_clear:
        rows = []
        try:
            got = json.loads(store.get_meta('lockouts:' + node_name()) or '{}')
            rows = [r for r in got.get('rows') or [] if float(r.get('forgets') or 0) > time.time()]
        except ValueError:
            rows = []
        if args.lockouts_clear:
            ask = {'all': 1, 'by': who} if args.lockouts_clear == 'all' else \
                {'key': args.lockouts_clear.split(':', 1), 'by': who}
            store.set_meta('lockouts:ask:' + node_name(), json.dumps([ask]))
            print(pal.ok_line('asked: the service forgets it within seconds'))
            return 0
        if as_json:
            out({'rows': rows})
            return 0
        print(table([(r['kind'], r['who'], '%d of %d' % (r['fails'], r['limit']),
                      'LOCKED until %s' % stamp(r['until']) if r.get('locked') else 'counted')
                     for r in rows], ['kind', 'who', 'wrong', 'state']))
        return 0
    if args.backup:
        p = make_copy(store, 'by-hand')
        copies_prune()
        store.add_event('settings', 'a copy of the databases was made on the command line: %s'
                        % p.name, who=who)
        print(pal.ok_line('%s (%s), the key beside it' % (p, human_bytes(p.stat().st_size))))
        return 0
    if args.copies:
        rows = kept_copies()
        if as_json:
            out(rows)
            return 0
        print(table([(c['name'], human_bytes(c['bytes']), stamp(c['at']), 'yes' if c['key'] else 'no')
                     for c in rows], ['copy', 'size', 'made', 'key beside it']))
        return 0
    if args.db_check:
        got = db_check(store)
        for line in got['said']:
            print((pal.ok_line if line.endswith(': ok') else pal.bad_line)(line))
        return 0 if got['ok'] else 1
    if args.restore:
        if not Path(args.restore).is_file():
            raise SystemExit('upsmon: there is no file %s' % args.restore)
        key = args.restore + '.key'
        try:
            says = copy_peek(args.restore, key)
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        if not args.yes:
            c = says['counts']
            print('%s - upsmon %s, made on %s' % (os.path.basename(args.restore), says.get('version') or '?',
                                                 (says.get('machine') or {}).get('node') or '?'))
            print('  %-24s %s' % ('samples of the UPS', c.get('samples', 0)))
            print('  %-24s %s' % ('accounts', c.get('accounts', 0)))
            print('  %-24s %s' % ('full administrators', says['admins']))
            print('  %-24s %s' % ('the key beside it', 'yes' if says['key_beside'] else 'no'))
            print('it would replace both databases here; again with --yes')
            return 0
        try:
            got = copy_restore(store, args.restore, who, key_file=key,
                               from_name=os.path.basename(args.restore))
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line('laid down to be put back; what it replaces is kept as %s; %s'
                          % (got['safety'], got['key'])))
        print('now:  systemctl restart upsmon')
        return 0
    if args.rbackup_status:
        v = rb_page(store)
        if as_json:
            out(v)
            return 0
        print('backups to the destinations: %s; %s' % (
            'on a schedule, next %s' % v['next'] if CONFIG.get('rbackup') else 'by hand only',
            'locked with the password' if v['locked'] else 'NOT LOCKED (no password set)'))
        for t_ in v['targets']:
            last = t_.get('last') or {}
            print('  %-24s %-6s %-3s %s' % (t_['name'][:24], t_['kind'], 'on' if t_.get('enabled')
                                             else 'off', ('last %s: %s' % (
                stamp(last['at']), 'sent' if last.get('ok') else last.get('error'))) if last else 'never sent'))
        for r in v['runs'][:10]:
            print('  %s  %-9s %s' % (stamp(r['at']), human_bytes(r.get('bytes') or 0),
                                     '; '.join('%s %s' % (x['name'], 'ok' if x['ok'] else 'FAILED: %s' % x.get('error'))
                                               for x in r.get('targets') or []) or r.get('error') or ''))
        return 0
    if args.rbackup_now:
        try:
            run = rb_run(store, who)
        except (RbError, ValueError) as e:
            raise SystemExit('upsmon: %s' % e)
        if run.get('error'):
            raise SystemExit('upsmon: %s' % run['error'])
        print(pal.ok_line('%s (%s, %s)' % (run.get('file'), human_bytes(run.get('bytes') or 0),
                                           'locked' if run.get('encrypted') else 'NOT locked')))
        for x in run['targets']:
            print((pal.ok_line if x['ok'] else pal.bad_line)('%s: %s' % (
                x['name'], 'sent' if x['ok'] else x.get('error'))))
        return 0 if run['ok'] else 2
    if args.restore_bundle:
        path = args.restore_bundle
        if not Path(path).is_file():
            raise SystemExit('upsmon: there is no file %s' % path)
        password = os.environ.get('UPSMON_BACKUP_PASSWORD', '')
        if args.passphrase_file:
            password = Path(args.passphrase_file).read_text().split('\n')[0]
        with open(path, 'rb') as f:
            locked = f.read(8).startswith(b'Salted__')
        if locked and not password:
            password = rb_password() or (getpass.getpass('the password of the backups: ')
                                         if sys.stdin.isatty() else '')
        if not args.yes:
            work = tempfile.mkdtemp(prefix='upsmon-peek-', dir=str(STATE_DIR))
            try:
                _top, m = rb_open(path, password, work)
            except RbError as e:
                raise SystemExit('upsmon: %s' % e)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            print('%s - every file checked against its checksum' % os.path.basename(path))
            for k, words in (('made_words', 'made'), ('site', 'installation'), ('node', 'server'),
                             ('host', 'machine'), ('upsmon', 'upsmon')):
                print('  %-13s %s' % (words, m.get(k) if m.get(k) not in (None, '') else '-'))
            print('it would replace both databases here and put its key in place; again with --yes')
            return 0
        try:
            got = rb_restore(store, path, password, who, need_admin=False)
        except (RbError, ValueError, OSError) as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line('laid down to be put back; what this machine had is kept as %s' % got.get('safety')))
        print('now:  systemctl restart upsmon')
        return 0
    if args.time:
        if args.time == 'sync':
            store.set_meta('ntp:sync:' + node_name(), repr(time.time()))
            print(pal.ok_line('asked: the service steps the clock to the time servers within seconds'))
            return 0
        v = ntp_view(store)
        if as_json:
            out(v)
            return 0
        for n in v.get('nodes') or []:
            st_ = n.get('state') or n
            print(pal.head('%s' % n.get('name', node_name())))
            for k in ('offset', 'stratum', 'source', 'leap', 'timezone', 'at'):
                if st_.get(k) not in (None, ''):
                    print('  %-10s %s' % (k, stamp(st_[k]) if k == 'at' else st_[k]))
        conf = v.get('conf') or {}
        print('  %-10s %s' % ('servers', ', '.join(conf.get('servers') or []) if conf.get('manage')
                              else 'as /etc/chrony.conf has them'))
        return 0
    if args.updates:
        if args.updates == 'status':
            v = osup_view(store)
            if as_json:
                out(v)
                return 0
            plan = v.get('plan') or {}
            print(pal.head('updates of the operating system: %s' % (
                '%s, by %s, %s' % (plan.get('state'), plan.get('by') or '-', stamp(plan.get('at')))
                if plan else 'none going on')))
            rows = []
            for n in v['nodes']:
                chk, row = n.get('check') or {}, n.get('row') or {}
                rows.append((n['name'], '%s, %s' % (chk.get('state') or '-', ('%s waiting' % chk['count'])
                                                    if chk.get('count') is not None else '') if chk else 'not looked',
                             row.get('state') or '-', 'needed' if n.get('reboot') else '-'))
            print(table(rows, ['server', 'last look', 'this update', 'restart'], [22, 26, 14, 8]))
            return 0
        try:
            if args.updates == 'check':
                osup_check_ask(store, host_nodes(store), who)
                print(pal.ok_line('looking for updates - upsmon --updates status in a minute'))
            elif args.updates == 'start':
                if not args.yes:
                    raise SystemExit('the updates of the system are put in now%s; again with --yes' % (
                        {'auto': ', restarted by itself where an update needs it', 'never': ', never restarted'}
                        .get(args.reboot, '')))
                osup_start(store, None, args.reboot, who)
                print(pal.ok_line('the update starts - upsmon --updates status'))
            else:
                osup_cancel(store, who)
                print(pal.ok_line('stopped - an update going on finishes'))
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        return 0
    if args.restart_server or args.poweroff_server:
        how = 'reboot' if args.restart_server else 'poweroff'
        if not args.yes:
            raise SystemExit('this machine is %s now; again with --yes' % (
                'restarted' if how == 'reboot' else 'switched off'))
        try:
            plan = power_ask(store, how, [node_name()], 'one', who)
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line('asked (%s): the service does it within seconds' % plan.get('id')))
        return 0
    if args.restarts:
        v = power_view(store)
        if as_json:
            out(v)
            return 0
        plan = v.get('plan') or {}
        print(pal.head('restarts: %s' % ('%s, by %s, %s' % (plan.get('how'), plan.get('by') or '-',
                                                             stamp(plan.get('at'))) if plan else 'none of late')))
        print(table([(n['name'], stamp(n.get('started')) if n.get('started') else '-',
                      (n.get('row') or {}).get('state') or '-', (n.get('row') or {}).get('said') or '')
                     for n in v['nodes']], ['server', 'started', 'restart', 'said'], [22, 20, 12, 60]))
        return 0
    if args.maintenance:
        if args.maintenance == 'status':
            m = maintenance_row(store)
            print('%s: %s' % (node_name(), 'in maintenance - %s' % m.get('why') if m.get('on')
                              else 'in service'))
            return 3 if m.get('on') else 0
        maintenance_set(store, args.maintenance == 'on', args.why or 'on the command line', who)
        print(pal.ok_line('maintenance %s' % args.maintenance))
        return 0
    if args.upgrade_cancel:
        try:
            upgrade_cancel(store, 'command line')
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line('the upgrade is stopped; the nodes not begun stay as they are'))
        return 0
    if args.upgrade_check:
        row = online_look(store, 'command line')
        if as_json:
            out(row)
            return 0 if not row.get('error') else 1
        print(pal.head('looked at %s' % row.get('url')))
        if row.get('error'):
            print(pal.bad_line(row['error']))
            return 1
        for pk in row.get('packages') or []:
            mark = pal.good('newer') if _ver_tuple(pk['version']) > _ver_tuple(__version__) \
                else pal.dim('not newer')
            print('  %-24s %s  %s' % (pk['name'], mark, pal.dim(pk['url'])))
        n = row.get('newest')
        if not n:
            print(pal.warn_line('no upsmon package there'))
        elif row.get('newer'):
            print(pal.ok_line('upsmon %s is there - this server runs %s: upsmon --upgrade-online'
                              % (n['version'], __version__)))
        else:
            print(pal.ok_line('nothing newer than %s' % __version__))
        return 0

    if args.upgrade_online:
        plan = upgrade_plan(store)
        if plan and plan['state'] == 'running':
            raise SystemExit('upsmon: an upgrade is going on - upsmon --upgrade-follow')
        row = online_look(store, 'command line')
        if row.get('error'):
            raise SystemExit('upsmon: %s: %s' % (row.get('url'), row['error']))
        want = args.upgrade_online
        pk = row.get('newest') if want == 'newest' else next(
            (x for x in row.get('packages') or [] if x['version'] == want), None)
        if not pk:
            raise SystemExit('upsmon: %s is not at %s' % (want, row.get('url')))
        if _ver_tuple(pk['version']) <= _ver_tuple(__version__):
            print(pal.ok_line('nothing newer than %s at %s' % (__version__, row.get('url'))))
            return 0
        nodes = [n['name'] for n in ha_nodes(store)] or [node_name()]
        print(pal.head('upsmon %s → %s' % (__version__, pk['version'])) + pal.dim('  from %s'
                                                                            % pk['url']))
        print('  ' + ('the nodes %s, one at a time - each in maintenance while it is upgraded'
                      % ', '.join(nodes) if len(nodes) > 1 else
                      'this server - for a minute nobody can sign in to the VPN'))
        if not args.yes:
            try:
                ok = input('  go on? (y/N) ').strip().lower() in ('y', 'yes', 'a', 'ano')
            except (EOFError, KeyboardInterrupt):
                ok = False
            if not ok:
                print('  nothing done')
                return 1
        print(pal.dim('  fetching it and checking its signature…'))
        try:
            meta = online_fetch(store, pk['version'], 'command line')
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line('upsmon %s fetched, signed by %s' % (meta['version'],
                                                             meta.get('signed_by'))))
        try:
            upgrade_start(store, 'command line')
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        return cli_upgrade_follow(store, pal)

    if args.upgrade_follow:
        return cli_upgrade_follow(store, pal)

    if args.downgrade_check:
        try:
            got = downgrade_list(store)
        except Exception as e:                          # noqa: BLE001
            raise SystemExit('upsmon: %s' % e)
        if as_json:
            out(got)
            return 0
        print(pal.head('going back from %s - looked at %s' % (__version__, got['url'])))
        print(pal.dim('  it may go back to %s or newer (set by upsmon %s; this machine allows %s)'
                      % (got['floor'], got['floor_by'], got['root_floor'] or 'nothing yet')))
        if not got['versions']:
            print(pal.ok_line('no version older than %s is there' % __version__))
        for v in got['versions']:
            if v['why']:
                print(pal.bad_line('%-10s %s' % (v['version'], '; '.join(v['why']))))
            else:
                print(pal.ok_line('%-10s may be gone back to: upsmon --downgrade %s'
                                  % (v['version'], v['version'])))
        return 0

    if args.downgrade:
        plan = upgrade_plan(store)
        if plan and plan['state'] == 'running':
            raise SystemExit('upsmon: an upgrade is going on - upsmon --upgrade-follow')
        want = args.downgrade
        is_file = want.endswith(('.tar.gz', '.tgz')) or os.path.sep in want
        if not is_file:
            why = downgrade_why_not(store, want)
            if why:
                raise SystemExit('upsmon: upsmon %s cannot be gone back to: %s' % (want, '; '.join(why)))
        nodes = [n['name'] for n in ha_nodes(store)] or [node_name()]
        print(pal.head('upsmon %s → %s (going back)' % (__version__, os.path.basename(want))))
        print('  ' + ('the nodes %s, one at a time - each in maintenance while it is done'
                      % ', '.join(nodes) if len(nodes) > 1 else
                      'this server - for a minute nobody can sign in to the VPN'))
        print('  ' + pal.dim('the database stays as it is; what came in the newer versions is '
                             'gone until you upgrade again'))
        if not args.yes:
            try:
                ok = input('  go back? (y/N) ').strip().lower() in ('y', 'yes', 'a', 'ano')
            except (EOFError, KeyboardInterrupt):
                ok = False
            if not ok:
                print('  nothing done')
                return 1
        print(pal.dim('  checking it: its signature, how far back this may go, the tables…'))
        try:
            if is_file:
                if not os.path.isfile(want):
                    raise ValueError('%s is not a file' % want)
                meta = downgrade_file(store, want, 'command line')
            else:
                meta = downgrade_fetch(store, want, 'command line')
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        print(pal.ok_line('upsmon %s checked (signed by %s) - the database can take it'
                          % (meta['version'], meta.get('signed_by'))))
        try:
            upgrade_start(store, 'command line')
        except ValueError as e:
            raise SystemExit('upsmon: %s' % e)
        return cli_upgrade_follow(store, pal)

    if args.upgrade_status:
        meta = json.loads(store.get_meta('upgrade:pkg') or 'null')
        plan = upgrade_plan(store)
        if as_json:
            out({'package': meta, 'plan': plan})
            return 0
        print('package: %s' % ('upsmon %s (%s bytes, signed by %s, sent by %s)' % (
            meta['version'], meta['bytes'], meta.get('signed_by'), meta.get('by'))
            if meta else 'none sent'))
        if not plan:
            print('no upgrade started on the pages')
            return 0
        print('upgrade to %s, started by %s: %s' % (plan['version'], plan.get('by'),
                                                     plan['state']))
        for st in plan['steps']:
            print('  %-20s %-11s %s' % (st['name'], st.get('state') or 'waiting',
                                        st.get('said') or ''))
        return 0
    raise SystemExit('upsmon: nothing to do')


HELP_EXAMPLES = [
    ('upsmon --status', 'the UPS now, every variable'),
    ('upsmon --check', 'is the whole system healthy'),
    ('upsmon --console', 'everything by its menus'),
    ('upsmon --history 7d', 'recorded samples as a table'),
    ('upsmon --exec test.battery.start.quick', 'a self test'),
    ('upsmon --plug-off', 'the socket of the plug off'),
    ('upsmon --users', 'the accounts of Settings'),
    ('upsmon --add-user novak --role fulladmin', ''),
    ('upsmon --setting acme=1 --setting acme_email=it@example.cz', ''),
    ('upsmon --acme-order', 'a certificate from Let\'s Encrypt now'),
    ('upsmon --upgrade-online', 'the newest version, checked and put in'),
    ('upsmon shelly plug info', 'the plug, by role'),
]


def colour_cli(argv):
    """The command line of upsmon in OTP's colours: (palette, parser hook)."""
    said = list(argv)
    pal = Palette(colour_wanted(any(x in ('--no-color', '--no-colour') for x in said))
                  and '--json' not in said)
    global TABLE_PAL
    TABLE_PAL = pal
    if (pal.on or sys.stdout.isatty()) and '--json' not in said and '--console' not in said \
            and said and not isinstance(sys.stdout, ColourOut):
        sys.stdout = ColourOut(sys.stdout, pal)
    return pal


# ---- a certificate exported from Certificates and TLS (4.1) ------------------------------
CERT_EXPORT = {
    'pem': ('the certificate and its chain, PEM', '.pem', 'application/x-pem-file', False),
    'crt': ('the certificate alone, PEM', '.crt', 'application/x-x509-ca-cert', False),
    'der': ('the certificate alone, DER', '.der', 'application/x-x509-ca-cert', False),
    'pem_key': ('the certificate, its chain and its private key, PEM', '-with-key.pem',
                'application/x-pem-file', True),
    'key': ('the private key alone, PEM', '.key', 'application/x-pem-file', True),
    'pfx': ('PFX / PKCS#12, AES-256', '.pfx', 'application/x-pkcs12', True),
    'pfx_legacy': ('PFX / PKCS#12, 3DES (older Windows, Java 8)', '.pfx', 'application/x-pkcs12', True),
}


def cert_export(prof, fmt, password, with_chain=True):
    """One certificate as the format asked for: {'data', 'suffix', 'mime', 'words', 'with_key'}."""
    if fmt not in CERT_EXPORT:
        raise ValueError('the format is one of %s' % ', '.join(CERT_EXPORT))
    words, suffix, mime, keyed = CERT_EXPORT[fmt]
    cert = prof['cert']
    chain = prof.get('chain') or '' if with_chain else ''
    key = ''
    if keyed:
        key = unseal_secret(prof.get('key') or '', 'web:tls') or ''
        if not key:
            raise ValueError('the private key of this certificate is not kept here - it can only '
                             'be exported without it')
    if password and (len(password) < 8 or len(password) > 200):
        raise ValueError('a password of 8 to 200 characters')
    if fmt.startswith('pfx') and not password:
        raise ValueError('a PFX file is locked with a password: give one (8 characters at least)')
    if fmt == 'pem':
        data = (cert + chain).encode()
    elif fmt == 'crt':
        data = cert.encode()
    elif fmt == 'der':
        data = _openssl(['x509', '-outform', 'DER'], cert.encode(), what='the certificate')
    else:
        work = tempfile.mkdtemp(prefix='upsmon-export-', dir=str(STATE_DIR))
        try:
            os.chmod(work, 0o700)
            kf = os.path.join(work, 'k.pem')
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(key)
            if fmt.startswith('pfx'):
                cf = os.path.join(work, 'c.pem')
                with open(cf, 'w') as f:
                    f.write(cert)
                args = ['pkcs12', '-export', '-in', cf, '-inkey', kf, '-passout', 'env:UPSMON_PFX',
                        '-name', str((prof.get('info') or {}).get('cn') or 'upsmon')]
                if chain:
                    chf = os.path.join(work, 'chain.pem')
                    with open(chf, 'w') as f:
                        f.write(chain)
                    args += ['-certfile', chf]
                if fmt == 'pfx_legacy':
                    args += ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1']
                else:
                    args += ['-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'sha256']
                try:
                    data = _openssl(args, env={'UPSMON_PFX': password}, what='the PFX file')
                except ValueError:
                    if fmt != 'pfx_legacy':
                        raise
                    data = _openssl(args + ['-legacy'], env={'UPSMON_PFX': password}, what='the PFX file')
            else:
                if password:
                    k = _openssl(['pkey', '-in', kf, '-aes256', '-passout', 'env:UPSMON_PFX'],
                                 env={'UPSMON_PFX': password}, what='the key').decode()
                else:
                    k = key if key.endswith('\n') else key + '\n'
                data = (k if fmt == 'key' else cert + chain + k).encode()
        finally:
            shutil.rmtree(work, ignore_errors=True)
    if keyed and password and fmt in ('pem_key', 'key'):
        words += ', the key locked (AES-256)'
    return {'data': data, 'suffix': suffix, 'mime': mime, 'words': words, 'with_key': keyed}
