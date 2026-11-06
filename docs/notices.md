# Co je potřeba udělat ručně (upsmon 4.5.0)

Jeden systém pro všechno, co upsmon nedokáže udělat sám a musí to udělat administrátor:

- krok, který nová verze potřebuje na příkazové řádce;
- co instalátor nechal na vás (SELinux, firewall, chybějící balíček);
- cokoli, co zjistí sám daemon.

## Kde se upozornění zobrazují

| Kde | Co tam je |
|---|---|
| **Nastavení → Aktualizace** | První karta „Je potřeba udělat ručně“. Každé upozornění je pás jako v isemonu: barva podle závažnosti, text, příkazy s tlačítkem Kopírovat, **Hotovo** (plný administrátor) a **Zkontrolovat znovu** (má-li kontrolu). Pod pásy je „Nedávno hotové“: kdo, jak a kdy. |
| **Menu Nastavení** | U položky Aktualizace je číslo s počtem otevřených upozornění, v barvě nejhoršího z nich. Je vidět i ve sbaleném menu. Nahoře nad stránkami se nic nového nezobrazuje; stávající hlášení (výpadek, PHP, problémy) zůstávají, jak byla. |
| **Dashboard** (veřejný) | Pás „Na tomto serveru je potřeba něco udělat ručně“ s odkazem do Nastavení. Jen pro úrovně `warn` a `danger`. Neříká **co**, to je jen pro přihlášené. `/api/status` a `/api/health` nesou jen `{"open": N, "level": "danger"}`. |
| **Konzole** | Nahoře řádek `TO DO BY HAND: …` (nejvýš 3, pak „… and N more“). |
| **CLI** | `upsmon --notices` vypíše všechna otevřená upozornění s příkazy (návratový kód 2, když něco je). `upsmon --notice-done ID` označí upozornění jako hotové, `upsmon --notices-check` znovu vyhodnotí kontroly. `--json` pro skripty. |
| **install.sh --upgrade** | Před instalací vypíše upozornění nové verze typu `before`. Je-li mezi nimi `confirm`, zeptá se „Read it, and go on?“ (`--yes` ho přeskočí). Po instalaci vypíše upozornění typu `after` jako **TO BE DONE BY HAND**. |
| **Události** | Kategorie „to do by hand“: vznik, kdo udělal, vyřešilo se samo, staženo rootem. |

## Odkud se berou

### 1. Z balíčku: `deploy/notices.json`

Soubor je podepsaný spolu se zbytkem balíčku. Do něj se píšou kroky pro budoucí verze:

```json
{
 "notices": [
  {
   "id": "4.6.0-php83",
   "since": "4.6.0",
   "when": "after",
   "level": "danger",
   "title": "Run the installer once more by hand",
   "text": "This version moves the pages to PHP 8.3.\nThe pages cannot do it themselves.",
   "commands": ["sudo bash install.sh --upgrade"],
   "check": {"file_exists": "/etc/php-fpm.d/upsmon-83.conf"},
   "cs": {"title": "Spusťte instalátor ještě jednou ručně",
          "text": "Tato verze přesouvá stránky na PHP 8.3.\nStránky to samy neudělají."}
  },
  {
   "id": "4.6.0-backup",
   "since": "4.6.0",
   "when": "before",
   "confirm": true,
   "level": "warn",
   "title": "Make a backup first",
   "commands": ["upsmon --backup"]
  }
 ]
}
```

| Pole | |
|---|---|
| `id` | písmena, číslice, `.` `_` `-`, nejvýš 64 znaků; jedinečné |
| `since` | verze, která upozornění přináší. Upozornění se zobrazí jen při přechodu přes ni (z verze < `since` na verzi ≥ `since`). |
| `when` | `before`: ukáže se před aktualizací (v Aktualizacích u balíčku a v CLI). `after`: vznikne, jakmile nová verze běží. `both`: obojí. |
| `confirm` | jen pro `before`. Aktualizace se ze stránek nespustí, dokud někdo upozornění nezaškrtne jako přečtené. Server to vynucuje (409); okno se ukáže i při „aktualizovat z webu jedním klikem“. |
| `level` | `danger` (červená), `warn` (oranžová), `info` (modrá) |
| `title`, `text` | anglicky; `text` může mít řádky (`\n`) |
| `cs` | `{title, text}` česky (stránky i CLI podle jazyka) |
| `commands` | nejvýš 10 příkazů; ukážou se s tlačítkem Kopírovat. **Nic se nespouští.** |
| `check` | upozornění zmizí samo, jakmile kontrola platí (viz níže) |
| `link` | volitelný odkaz `https://…` |

### 2. Od roota: `/etc/upsmon/notices.d/*.json`

Jeden soubor na upozornění, ve stejném formátu (bez `since`, `when` a `confirm`). Instalátor na to má funkce:

```bash
upsmon_notice ID LEVEL "title" "text" [command]... [--check KIND=VALUE]
upsmon_notice_clear ID
```

Příklad z install.sh: když chybí `semanage`, SELinux neudrží štítek stránek a instalátor vyvolá `selinux-label`. Když soubor zmizí, upozornění se uzavře jako „staženo“. Upozornění, které někdo označil jako hotové, se znovu neotevře, dokud se jeho obsah nezmění.

### 3. Od daemonu: `notice_raise(store, {...}, 'daemon')`

## Kontroly (`check`)

Pevná sada druhů kontrol. Ze souboru se nikdy nic nespouští:

| Druh | Platí, když |
|---|---|
| `{"selinux": "enforcing" / "permissive" / "disabled" / "not-enforcing"}` | SELinux je v daném režimu (`/sys/fs/selinux/enforce`) |
| `{"file_exists": "/cesta"}` | soubor existuje |
| `{"file_missing": "/cesta"}` | soubor neexistuje |
| `{"unit_active": "jméno"}`, `{"unit_inactive": "jméno"}` | `systemctl is-active` |
| `{"unit_enabled": "jméno"}`, `{"unit_disabled": "jméno"}` | `systemctl is-enabled` |
| `{"version_at_least": "4.6.0"}` | běží upsmon aspoň této verze |

Kontroly se vyhodnocují každou minutu, při otevření stránky a tlačítkem Zkontrolovat znovu.

## Bezpečnost

- Texty se na stránkách vkládají jako text, ne jako HTML.
- Dashboard a `/api/status` neříkají, co se má udělat.
- Označit upozornění jako hotové smí jen plný administrátor (403 pro ostatní). V událostech je jeho jméno.
- `notices.d` patří rootovi (`/etc/upsmon`). Daemon ho jen čte, nejvýš 100 souborů po 64 kB.

## Testy

- `python3 tests/notices/t_engine.py`: jádro (čtení, verze, balíček, hotovo, kontroly, root, pojistka)
- `bash tests/notices/t_install.sh`: funkce instalátoru
- `node tests/notices/t_ui.js`: stránky na testovací instanci (jako root vedle ní)
