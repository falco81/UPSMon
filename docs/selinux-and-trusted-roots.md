# SELinux a důvěryhodné kořeny systému (upsmon 4.6.0, nálezy a opravy 4.9.0)

Převzato z OTP 1.0.265 (návod „SELinux support and the system's trusted roots“) pro jeden
server bez clusteru. Obojí mění operační systém, proto to dělá root helper
(`upsmon_web.py`). Stránky a démon nikdy neběží jako root: démon zapíše požadavek
`selinux.ask` / `osroots.ask` do `/var/lib/upsmon/web/` a `upsmon-web.path` spustí helpera.
Helper znovu ověří každou hodnotu: booleany a typy portů jen ze seznamů, každý certifikát
přečte znovu `openssl`.

## SELinux: Nastavení → SELinux

Ve výchozím stavu se nic nemění. Stroj s vypnutým SELinuxem zůstane vypnutý a upsmon běží
jako dřív. Instalátor jen připraví nástroje a modul.

### Co upsmon od SELinuxu potřebuje

| Co | Proč | Jak |
|---|---|---|
| `/run/upsmon` a jeho soubory jako `httpd_var_run_t` | php-fpm (`httpd_t`) čte token a port démona (`admin-token`, `admin-port`, `api-token`). systemd složku vytváří jako `var_run_t`, kterou `httpd_t` číst nesmí. | `filecon` v modulu `upsmon_server.cil` pro `/run` i `/var/run` |
| systemd smí měnit vlastníka a práva v `/run/upsmon` | `RuntimeDirectory=` před každým příkazem jednotky (i `ExecReload`) | úzké `allow init_t httpd_var_run_t … setattr` v `optional` bloku |
| `httpd_can_network_connect` zapnutý | stránky se ptají démona na 127.0.0.1:9849 a :9848 | boolean |
| `/var/www/upsmon` jako `httpd_sys_content_t` | stránky | štítek distribuce (`semanage fcontext` + `restorecon` v install.sh) |

Vlastní procesy upsmonu (démon, helper, upgrade) běží neomezeně (`unconfined_service_t`),
jako každá služba z `/usr/local`.

### Cesta k enforcingu

**Disabled → Připravit** (config `SELINUX=permissive`, `/.autorelabel`, případně se odebere
`selinux=0` z příkazové řádky jádra, modul) → **restart, který spustíte sami** →
**Permissive → Vložit, co upsmon potřebuje** (modul, štítky, booleany) → den nebo dva běžného
provozu → **Přepnout na enforcing**.

Enforcing se odmítne, dokud něco chybí, něco bylo zamítnuto nebo neběží auditd.
**Zpět na permissive** vrátí stav okamžitě.

- Zamítnutí (`ausearch -m AVC,USER_AVC -ts boot`) se počítají jen pro programy, které se
  upsmonu týkají, a **od posledního vložení potřeb**. Čas vložení je v rootově složce
  `/var/lib/upsmon-root/selinux-applied` (0600), ne ve složce služby.
- Co dnešní politika už povoluje (`audit2why` říká „would be allowed by active policy“), se
  nepočítá.
- Když odmítnutý pokus o enforcing po cestě něco vložil, nejbližší „Vložit, co upsmon
  potřebuje“ čas zapíše, i když už nic nemění. Jinak by stará zamítnutí platila napořád.
- Porty se jen přidávají (`semanage port -a`), nikdy nepřebírají (`-m`). Port jiné služby se
  odmítne.
- `semanage`, `semodule`, `ausearch` a `audit2why` běží pod `nice` a `ionice`. Daemon se
  poprvé podívá 2 minuty po startu, pak každých 30 minut a hned, když se o krok požádá.
  Každý krok se zkouší jen jednou.

### Co SELinux odmítá, roztříděné podle toho, co to napraví (4.9.0)

Pod kontrolami je sekce **Co SELinux odmítá**. Root (helper) při každém pohledu přečte
každé `AVC`, `USER_AVC` a `SELINUX_ERR` od startu stroje (`ausearch -ts boot`) i se záznamy
jeho události (SYSCALL: program; PATH: celá cesta; port). Seskupí je podle (zdrojový typ,
cílový typ, třída, oprávnění, program, cesta nebo port), každou skupinu dá `audit2why` a zařadí
do jednoho druhu. Id nálezu je hash toho, co bylo odmítnuto (12 hex znaků) – stejné odmítnutí
má při každém pohledu stejné id.

| Druh | Význam | Co ho napraví |
|---|---|---|
| povoleno teď | nahraná politika to už povoluje | – (nepočítá se, nezobrazí se) |
| **Přepínač (boolean)** | `audit2why` jmenuje boolean | `setsebool -P NÁZEV 1` – nikdy boolean, který povoluje mnohem víc (`*exec*`, `unconfined`, `*_manage_all*`, `*_read_all*`, `ptrace`, `deny_*`…) |
| **Štítek** | soubor upsmonu nemá štítek, jaký říká `matchpathcon` | `restorecon -R -v CESTA` (jen cesty upsmonu) |
| **Port** | nginx, sshd, chronyd nebo avahi na portu upsmonu bez vlastního typu | `semanage port -a -t TYP -p PROTO PORT` – nikdy port, který patří typu jiné služby |
| **Pravidlo upsmonu** | politika to nijak nepovoluje a je bezpečné povolit přesně tohle | jedno pravidlo ve **druhém lokálním modulu** `upsmon_local`: `(optional upsmon_local_ID (allow SRC TGT (TŘÍDA (OPRÁVNĚNÍ))))` |
| **Ne na tlačítko** | patří upsmonu, ale povolit to odsud by bylo příliš | jen zobrazeno s důvodem: citlivý cíl (`shadow_t`, `security_t`, politika, `kernel_t`, klíče, audit, `sudo_*`, domovy…), spouštění a přechody (`execute`, `entrypoint`, `transition`, `ptrace`, `relabel*`…), schopnosti (`sys_admin`, `dac_override`…), nebezpečné třídy, zápis do obecných typů (`etc_t`, `usr_t`, `var_t`, `tmp_t`…), omezení politiky (constraint) |
| **Nepatří upsmonu** | jiný program stroje | jen zobrazeno, nikdy se odsud nenapravuje |

**Komu odmítnutí patří:** démonu (`unconfined_service_t`, program z `/usr/local/lib/upsmon`
nebo „upsmon“ v jeho záznamech), nástrojům, které démon spouští s `NoNewPrivileges`
(`chronyc_t`, `ifconfig_t`, `ssh_t`, `ssh_keygen_t`, `hostname_t`, `ping_t`), a omezeným službám,
se kterými upsmon pracuje (`httpd_t`, `init_t`, `logrotate_t`…) – u nich jen na cestách upsmonu
(`/var/www/upsmon`, `/run/upsmon`, `/var/lib/upsmon`, `/etc/upsmon`, jeho soubory nginx,
php-fpm, logrotate…) nebo na jeho portech; s cestou ani portem, které nejsou známé, se počítají
k upsmonu (jako dřív). Odmítnutí jiných programů enforcing neblokuje.

**Nasadit vybrané (N):**

- Všechno, co lze napravit, přijde zaškrtnuté; skupiny mají „vybrat vše“, tlačítko počítá.
- **Stránka posílá jen id.** Root nálezy najde znovu v auditním logu a každou opravu si
  odvodí sám – požadavek nikdy nenese pravidlo, cestu ani příkaz.
- Potvrzení vypíše **přesně**, co root udělá.
- Root: `setsebool -P`, `restorecon`, `semanage port`, lokální modul přepsaný ze seznamu
  a nahraný (`semodule -i`, kopie `.in-policy`); každý krok jde do Událostí; hned se znovu
  podívá. Funguje i v režimu enforcing.
- Co bylo napraveno, se zapíše s časem (`/var/lib/upsmon-root/selinux-fixed.json`):
  odmítnutí z doby předtím se už nepočítá („Právě napraveno“), odmítnutí potom se vrátí.
- **Lokální pravidla upsmonu** vypisuje každé pravidlo s tlačítkem **Odebrat**
  (`/var/lib/upsmon-root/selinux-local.json`, `upsmon_local.cil`); poslední odebrané:
  `semodule -r upsmon_local`.
- Přepnout na enforcing zůstává zamčené, dokud zbývá něco k napravení nebo „ne na tlačítko“.

`upsmon_server.cil` má od 4.9.0 navíc `nnp_transition` do domén nástrojů, které démon
spouští (`ip`, `ssh`/`sftp`/`scp`, `ssh-keygen`; i `chronyc`, `hostname`, `ping`), každý
přechod v bloku `optional` – politika bez některého typu vezme zbytek.

### Report

**Stáhnout report** nebo `upsmon --selinux-report [SOUBOR]` připraví tar.gz s obsahem:
`check.json`, zamítnutí (raw, `-i`, `audit2why`, návrh `audit2allow`), štítky souborů proti
`matchpathcon`, domény procesů, porty, booleany, moduly (i `upsmon_local`) a verze systému.
Od 4.9.0 i složka `os/` za celý stroj: každý proces s doménou, každý boolean
(`getsebool -a`), každý typ portu (`semanage port -l`), každý modul (`semodule -lfull`),
co se na stroji změnilo (`semanage boolean/port/fcontext/login/user/module/permissive -l -C`),
`semanage export` a naslouchající sokety se štítky (`ss -lntupZ`).

- Při jeho vytváření se nic nemění.
- Neobsahuje heslo, klíč ani token. Auditní log ale obsahuje příkazové řádky jiných programů,
  proto ho před odesláním projděte.
- Ze stránek se uloží zapečetěný v databázi na hodinu.

### Instalátor

Při každé instalaci i aktualizaci:

- `selinux_tools`: na dnf systémech doplní `policycoreutils`, `libselinux-utils`,
  `policycoreutils-python-utils`, `audit` a `selinux-policy-targeted`. Kde je SELinux
  zapnutý, spustí auditd.
- `selinux_module`: zkopíruje `upsmon_server.cil`. Kde je SELinux zapnutý, provede
  `semodule -i`, ale jen když se modul změnil proti `upsmon_server.cil.in-policy`. Pak
  `restorecon /run/upsmon` a kontrola `matchpathcon`.
- `--uninstall` provede `semodule -r upsmon_server` a `semodule -r upsmon_local`. Režim,
  booleany a štítky portů patří stroji a zůstanou.

### CLI

```bash
upsmon --selinux-check            # stav; exit 1, když něco chybí
upsmon --selinux-check --json
upsmon --selinux prepare          # check | prepare | apply | enforce | permissive (zeptá se; --yes)
upsmon --selinux-report [FILE]    # /root/upsmon-selinux-report-STROJ-DATUM.tar.gz
upsmon --selinux-look             # co SELinux odmítá, po druzích, s id a opravami (--json)
upsmon --selinux-fix ID... | all  # vypíše, co root udělá, zeptá se (--yes)
upsmon --selinux-rules [--take-away ID]   # lokální pravidla upsmonu
```

## Důvěryhodné kořeny systému: Nastavení → Certifikáty a TLS

Vlastní CA (kořen firmy, mezilehlá autorita) přidané do důvěry **celého systému**: curl, dnf,
LDAPS, SMTP, syslog přes TLS i vlastní spojení upsmonu.

| Rodina | Místní doplňky | Nástroj | Výsledný seznam |
|---|---|---|---|
| RHEL / Alma / Rocky | `/etc/pki/ca-trust/source/anchors/*.pem` | `update-ca-trust extract` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` |
| Debian / Ubuntu | `/usr/local/share/ca-certificates/*.crt` | `update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` |

- **Seznamu distribuce se upsmon nikdy nedotkne.** Dál přichází s aktualizacemi balíčku
  `ca-certificates`. Nástroj systému přitom vždy sloučí i místní doplňky.
- upsmon zapisuje a maže jen soubory `upsmon-<prvních 16 hex SHA-256>.pem|.crt`. Ostatní
  soubory ve složce jen ukazuje a odkazy nikdy nenásleduje.
- **Odmítne se:**
  - soukromý klíč, PKCS7 nebo TRUSTED CERTIFICATE v textu (odmítne se celý text);
  - certifikát bez `CA:TRUE` (vlastní certifikát serveru sem nepatří);
  - certifikát s `keyUsage` bez `keyCertSign`.
- **Varuje se:**
  - prošlá autorita, nebo autorita, která ještě neplatí;
  - SHA-1 nebo MD5 u mezilehlé autority, RSA klíč menší než 2048 bitů;
  - mezilehlá autorita bez svého kořene.
- Nejvýš 50 autorit, každá do 16 kB.
- Synchronizace pracuje vždy s celou sadou a je idempotentní. Nástroj systému se spustí jen
  při změně. Upsmon pak ověří, že je každá autorita opravdu ve výsledném seznamu.
- Pokud Python upsmonu nemá výchozí seznam (vlastní OpenSSL), nasměruje se `SSL_CERT_FILE`
  na seznam systému.
- Prohlížet může i účet jen pro čtení (autority nejsou tajné). Měnit může jen plný
  administrátor.

```bash
upsmon --os-roots
upsmon --os-roots-add company-root.pem        # .pem, .crt, .cer (DER); zeptá se (--yes)
upsmon --os-roots-remove 7d8401dfbd268db3     # otisk, nejméně 12 znaků
```

## Testy

- `python3 tests/selinux-osroots/t_helper.py`: root helper s falešnými nástroji SELinuxu
  a falešnou složkou certifikátů (50 kontrol).
- `CADIR=… node tests/selinux-osroots/t_ui.js`: stránky na testovací instanci. Autority se
  přidají a odeberou doopravdy (Ubuntu: systémový seznam 122 → 124 → 122).
- `node tests/selinux-osroots/t_report.js`: report ze stránky.
- `python3 tests/selinux-find/t_find.py`: třídění nálezů z fixtur skutečného výstupu
  `ausearch` (hex), opravy, lokální modul (přeložený `secilc`, je-li na stroji), odebrání
  pravidel, report (38 kontrol).
- `node tests/selinux-find/t_ui.js`: karta na testovací instanci se zástupnými nástroji
  (viz `tests/selinux-find/README.md`).
