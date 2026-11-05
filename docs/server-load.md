# Vytížení serveru v záhlaví (CPU, RAM, disky, síť): specifikace a kód k převzetí

Tento balíček popisuje, jak je v aplikaci **ai** (verze 1.0.72–1.0.76) uděláno živé vytížení serveru
v záhlaví stránky. Obsahuje i **hotový kód** k převzetí do jiného projektu:

- čtyři čísla v záhlaví (CPU, RAM, disky, síť) obnovovaná každé 3 s, ve **čtyřech vzhledech**;
- po najetí myší (na iPadu po klepnutí) **panel s podrobnostmi**: jednotlivá jádra s frekvencí
  a teplotou, čidla, jednotlivé disky, souborové systémy, síťové karty a procesy, které berou nejvíc.
  Panel je v **pěti stylech**, včetně možnosti „bez podrobností“;
- **výběr vzhledu kartami s náhledem** ve Vašem účtu. Náhledy kreslí stejný kód z ukázkových dat;
- backend jen se standardní knihovnou Pythonu. Čte `/proc` a `/sys` jen na vyžádání a nic neběží
  na pozadí.

```
server-load/
├── README.md            tento popis
├── src/
│   ├── load.py          backend: server_load(), load_detail(), load_temps(), api_load()  (spustitelný: python3 load.py)
│   ├── hload.js         frontend: záhlaví, panely, výběr vzhledu (čistý JS, bez knihoven)
│   ├── hload.css        vzhled (barvy v :root, vše ostatní)
│   ├── helpers.js       6 malých pomocníků, které hload.js používá ($, el, bytes, api, prefs …)
│   └── texts-cs.json    české texty (anglický text v kódu → český)
├── demo/index.html      samostatné demo bez serveru (ukázková data) - otevřete v prohlížeči
└── img/                 obrázky všech vzhledů a stylů
```

**Rychlé vyzkoušení:** otevřete `demo/index.html` v prohlížeči (stačí ze souboru). Běží s ukázkovými
čísly serveru s 8 jádry a čidly. Na skutečném serveru spusťte `python3 src/load.py`: vypíše, co
backend přečte (`--watch` vypisuje každé 3 s).

---

## 1. Jak to vypadá

### 1.1 Čtyři vzhledy čísel v záhlaví

| Vzhled (`hload`) | Obrázek |
|---|---|
| `graphs`, **výchozí**: s grafem posledních dvou minut | ![](img/look-graphs.png) |
| `pills`: štítky s pruhem | ![](img/look-pills.png) |
| `line`: jeden prostý řádek | ![](img/look-line.png) |
| `rings`: s kroužky | ![](img/look-rings.png) |
| `off`: nezobrazovat | (v záhlaví nic) |

- **Pevné šířky:** každé číslo má pevné místo (`ch` jednotky, `tabular-nums`), takže čipy a grafy
  **neposkakují**, ať je hodnota 0 B/s nebo 1023 kB/s. To bylo výslovné přání a je to ověřené měřením:
  pozice ani šířka čipů se při krajních hodnotách nezmění ani o pixel.
- **Barvy:**
  - zelená = v pořádku; **≥ 70 %** žlutá (`warm`), **≥ 90 %** červená (`hot`), u CPU i RAM;
  - grafy: CPU zelená, RAM fialová, disky oranžová, síť modrá.
- **Úzké okno:**
  - ≤ 1300 px: zmizí grafy u disků a sítě;
  - ≤ 1100 px: zmizí disky a síť;
  - ≤ 700 px (telefon): vytížení se nezobrazuje.

### 1.2 Pět stylů podrobností (`hpanel`)

**Dlaždice** (`tiles`, **výchozí**): karta pro každé jádro.

| CPU | RAM | Disky | Síť |
|---|---|---|---|
| ![](img/panel-tiles-cpu.png) | ![](img/panel-tiles-mem.png) | ![](img/panel-tiles-disk.png) | ![](img/panel-tiles-net.png) |

**Tabulka** (`table`): řádek pro každé jádro, jako htop. Nejlepší pro hodně jader.

| CPU | RAM | Disky | Síť |
|---|---|---|---|
| ![](img/panel-table-cpu.png) | ![](img/panel-table-mem.png) | ![](img/panel-table-disk.png) | ![](img/panel-table-net.png) |

**Mapa jader s kroužky** (`map`): jádra jako barevné čtverečky (barva = vytížení, číslo = teplota),
celé CPU a jeho teplota jako kroužky, disky jako karty a souborové systémy jako kroužky.

| CPU | RAM | Disky | Síť |
|---|---|---|---|
| ![](img/panel-map-cpu.png) | ![](img/panel-map-mem.png) | ![](img/panel-map-disk.png) | ![](img/panel-map-net.png) |

**Jeden široký panel** (`wide`): CPU, paměť, disky a síť vedle sebe, ať najedete na kterékoli číslo.
Pod 1000 px se složí do dvou sloupců.

![](img/panel-wide-cpu.png)

**Bez podrobností** (`off`): panel se neotevře a ze serveru se nic navíc nečte. Po najetí na číslo se
ukáže jen krátký popisek (`title`), například „The processor, busy over the last 3 s, all 8 core(s)
together · load 3.92 / 3.1 / 2.71“.

Na iPadu se panel otevře klepnutím a zavře klepnutím jinam:

![](img/ipad-tap.png)

### 1.3 Výběr ve Vašem účtu (karty s náhledem)

Uživatel si oba vzhledy vybírá kartami stejně jako barevná schémata terminálu. Každá karta je
**skutečně vykreslená stejným kódem** z ukázkových dat (`hpSample()`), takže přesně ukazuje výsledek.
Kliknutí volbu uloží a projeví se hned.

![](img/pickers.png)

Ve skutečné aplikaci (česky):

![](img/app-my-account-cs.png)

![](img/app-map-cs.png)

---

## 2. Jak to funguje

```
prohlížeč (každé 3 s, jen když je stránka vidět)           server
  hloadTick() ──GET /api/load──────────────────────────────▶ server_load()      /proc/stat, meminfo, diskstats, net/dev
     │        ◀── {cpu, mem_used, disk_rd, net_rx, …} ──────  (1 s cache, sdílená všemi stránkami)
     │
     │  panel otevřený?  ──GET /api/load?detail=1─────────────▶ + load_detail()   /proc/stat (cpuN), diskstats, net/dev,
     │                   ◀── {…, detail: {cores, disks, …}} ──   (1 s cache)        /proc/*/stat, /proc/mounts + statvfs,
     ▼                                                                             /sys/class/hwmon, thermal, cpufreq
  hloadDraw(): čipy + 40 hodnot historie (= 2 minuty) → grafy
  hloadPanelDraw(): panel ve zvoleném stylu
```

**Šetrnost:**
- Na serveru nic neběží na pozadí, žádné vlákno ani časovač. Čte se jen ve chvíli dotazu a drží se jen
  poslední čtení (pro výpočet rychlostí).
- Dotazy během **jedné sekundy** sdílí jedno čtení, takže deset otevřených stránek znamená jedno čtení.
  Změřeno: 200 dotazů za sebou trvá 0,35 s.
- Prohlížeč se **neptá, když je stránka schovaná** (`document.hidden`) nebo pozastavená (`LIVE.on`).
  Po návratu se zeptá hned.
- **Podrobnosti** (procesy, disky jednotlivě) jsou dražší. Čtou se **jen když je panel otevřený**. Po
  zavření se zase čte jen souhrn (ověřeno testem).
- Rychlosti (B/s, %) jsou rozdíl dvou čtení vydělený časem mezi nimi. První dotaz proto nemá rychlosti.
  Prohlížeč se zeptá znovu za 1,2 s. U podrobností server při prvním pohledu přečte dvakrát s odstupem
  0,3 s, aby panel neukazoval tečky.

---

## 3. Backend (`src/load.py`)

### 3.1 Odkud se co bere

| Údaj | Zdroj | Výpočet |
|---|---|---|
| CPU % (celkem) | `/proc/stat`, řádek `cpu` | `1 − Δ(idle+iowait) / Δ(součet prvních 8 polí)` |
| CPU % (jádro) | `/proc/stat`, řádky `cpuN` | totéž pro každé jádro |
| Frekvence jádra | `/sys/devices/system/cpu/cpuN/cpufreq/scaling_cur_freq` (kHz) | když chybí (VM), tak `cpu MHz` z `/proc/cpuinfo` |
| Model CPU | `/proc/cpuinfo`: `model name` / `Hardware` / `Model` | |
| Load | `os.getloadavg()` | 1 / 5 / 15 min |
| RAM použitá | `/proc/meminfo` | `MemTotal − MemAvailable`, tedy **bez cache**, kterou jádro vrací |
| Swap | `/proc/meminfo` | `SwapTotal − SwapFree` |
| Disky čtení/zápis | `/proc/diskstats`, pole 6 a 10 (sektory × 512) | **jen celé disky** (`/sys/block`), bez oddílů (počítaly by se dvakrát), bez `loop`, `ram`, `zram`, `sr`, `dm-` |
| Vytížení disku % | `/proc/diskstats`, pole 13 (ms strávené I/O) | `Δms / (Δt × 10)` |
| Velikost / model disku | `/sys/block/X/size` (× 512), `/sys/block/X/device/model` | |
| Souborové systémy | `/proc/mounts` + `os.statvfs()` | jen souborové systémy jádra (`LOAD_FS_KINDS`: ext2/3/4, xfs, btrfs, zfs, f2fs, exfat, ntfs3, jfs, reiserfs, nilfs2, bcachefs) – nikdy FUSE, síťová sdílení (NFS/CIFS na nedostupném serveru visí) ani FAT; každé zařízení jednou |
| Síť | `/proc/net/dev`, bajty rx (pole 1) a tx (pole 9) | **jen karty**: bez `lo`, `veth`, `docker`, `br-`, `virbr`, `podman`, `cni`, `flannel`, `tun`, `tap`, `vnet`, `ifb`, `dummy`, `lxc`, `kube`, `cali`, `vxlan`, `genev` a bez karet podřízených bondu (počítá se bond) |
| Stav / rychlost karty | `/sys/class/net/X/operstate`, `…/speed` (Mb/s) | |
| Procesy | `/proc/PID/stat`: utime+stime (pole 14+15) / `SC_CLK_TCK`, rss (pole 24) × `SC_PAGE_SIZE` | CPU % = Δčasu / Δt × 100 (víc jader = i přes 100 %) |
| Doba běhu | `/proc/uptime` | |
| Teploty | `/sys/class/hwmon/*` | viz 3.2 |

### 3.2 Teploty

Projdou se všechny `hwmon*` a `tempN_input` (m°C), s popisem z `tempN_label`:

| Čip (`name`) | Kam |
|---|---|
| `coretemp` (Intel), `k10temp`, `zenpower` (AMD), `cpu_thermal`, `soc_thermal` (ARM) | popis `Core N` → teplota **jádra N**, jinak (Package id 0, Tctl, Tdie) → **procesor** |
| `nvme` | disk podle `device/nvmeXnY` (Composite = teplota disku) |
| `drivetemp` (SATA, modul jádra) | disk podle `device/block/sdX` |
| ostatní (acpitz, pch, …) | „Další čidla“ |

Když hwmon nemá nic o procesoru, použijí se `/sys/class/thermal/thermal_zone*` (typ obsahující `cpu`,
`x86_pkg`, `soc` nebo `core` → procesor). Hodnoty mimo −40…150 °C se zahazují. **Virtuální stroj čidla
nemá**. Panel to pak napíše rovnou: „Bez teploty: tento stroj nemá čidla, která jádro čte (virtuální
stroj je nemá).“ Na SATA discích je potřeba modul `drivetemp` (`modprobe drivetemp`).

Pro testy se kořen `/sys` dá přesměrovat proměnnou `LOAD_SYS` (podvržená sada souborů).

### 3.3 API: `GET /api/load` (jen administrátor)

Vytížení prozrazuje, co server dělá, proto ho v ai vidí **jen administrátor**: čísla v záhlaví se
běžnému uživateli nevykreslí a API ho odmítne.

**Souhrn** (každé 3 s):

```json
{"at": 1762367000.1, "cores": 8, "cpu": 49.3, "load": [3.92, 3.1, 2.71], "over_s": 3.0,
 "mem_total": 33500000000, "mem_used": 9800000000, "swap_used": 0,
 "disk_rd": 190000000, "disk_wr": 48000000, "net_rx": 12600000, "net_tx": 1500000}
```

- Rychlosti jsou v **B/s** a `over_s` je, za kolik sekund jsou spočítané.
- Při prvním dotazu `cpu` a rychlosti chybí, protože není s čím počítat rozdíl.

**S podrobnostmi** (`?detail=1`, jen když je panel otevřený) přibude `detail`:

```jsonc
{"detail": {
  "model": "AMD Ryzen 7 5800X 8-Core Processor", "uptime": 1051200, "procs": 312,
  "cores": [{"n": 0, "busy": 96.0, "mhz": 3900, "temp": 71.0}, …],
  "temps": {"cpu": [["Tctl", 73.0]], "cores": {"0": 71.0}, "disks": {"nvme0n1": 44.0}, "other": [["acpitz", 41.0]]},
  "disks": [{"name": "nvme0n1", "size": 1000204886016, "model": "Samsung SSD 980 PRO 1TB",
             "rd": 190000000, "wr": 48000000, "util": 38.0, "temp": 44.0}, …],
  "filesystems": [{"mount": "/", "dev": "/dev/nvme0n1p2", "kind": "ext4", "total": …, "used": …, "free": …}, …],
  "nics": [{"name": "eno1", "state": "up", "speed": 1000, "rx": 12600000, "tx": 1500000,
            "rx_all": 812000000000, "tx_all": 96000000000}, …],
  "top_cpu": [{"pid": 1201, "name": "node", "cpu": 187.0, "rss": 2100000000}, …],   // 6 nejvíc CPU
  "top_mem": [{"pid": 1201, "name": "node", "rss": 2100000000}, …],                 // 6 nejvíc paměti
  "mem": {"total": …, "available": …, "cached": …, "buffers": …, "shared": …, "swap_total": …, "swap_free": …}}}
```

Panel nezobrazuje disky menší než 64 MB (třeba malé virtuální disky s `cidata`).

**Napojení:** `load.py` má `api_load(detail)` vracející slovník. Napojte ho na svou cestu, například:

```python
# Flask
@app.get('/api/load')
@admin_required
def load(): return jsonify(api_load(detail=bool(request.args.get('detail'))))
```

V prohlížeči `helpers.js` volá `fetch(API_BASE + 'load')` a `API_BASE + 'load&detail=1'`. Výchozí je
`'/?api='`, jak to má ai, kde PHP relay volání předává daemonu. Upravte `API_BASE`, například na
`'/api/'` s `?detail=1`, nebo nahraďte funkci `api()` vlastní.

---

## 4. Frontend (`src/hload.js`, `src/hload.css`)

### 4.1 Vložení do stránky

```html
<link rel="stylesheet" href="hload.css">
<header> … <div class="hload" id="hload" hidden aria-live="off"></div> … </header>
<script src="helpers.js"></script>   <!-- nebo vaše vlastní funkce stejných jmen -->
<script src="hload.js"></script>
<script>
  hloadLoop();                        // spustí dotazování (3 s, jen když je stránka vidět)
  hloadPickers(document.getElementById('my-account-section'));   // výběr vzhledu ve Vašem účtu
</script>
```

Element `#hload` vkládejte do stránky **jen administrátorovi**. Bez něj se nic nespustí.

### 4.2 Hlavní funkce

| Funkce | Co dělá |
|---|---|
| `hloadLoop()` | spustí dotazování: hned, za 1,2 s (první rychlost) a pak každé 3 s |
| `hloadTick(now)` | jeden dotaz. Když je otevřený panel, tak s `&detail=1`. Nic nedělá, když je stránka schovaná, `LIVE.on` je false nebo vzhled je `off` |
| `hloadDraw(d, into?, look?)` | vykreslí čipy a přidá hodnotu do historie (40 hodnot = 2 min). S `into` kreslí jen náhled (nic nemění) |
| `hloadPanelOpen(k, chip)` / `hloadPanelClose()` | otevře nebo zavře panel `k` ∈ `cpu`, `mem`, `disk`, `net` |
| `hloadPanelDraw()` | vykreslí panel ve stylu `hpStyle()`: `hpTiles`, `hpTable`, `hpMap`, `hpWide` |
| `hloadPanelPlace()` | umístí panel pod čip, v okně. `wide` od začátku čísel, šířka až 1180 px |
| `hloadPickers(host)` | dvě řady karet s náhledem ve Vašem účtu |
| `hpSample()` | ukázková data pro náhledy (8 jader s teplotami, NVMe + SATA, 2 FS, 1 karta) |

### 4.3 Chování panelu

- **Myš** (`matchMedia('(hover: hover)')`): najetí panel otevře. Odjetí ho zavře za **350 ms**, takže
  se dá přejet z čísla do panelu a panel zůstane otevřený.
- **Dotyk** (iPad): klepnutí panel otevře a druhé klepnutí nebo klepnutí jinam ho zavře. iPad s myší
  se chová jako PC.
- **Klávesnice:** čip má `tabindex=0` a `role=button`. Enter nebo mezerník panel otevře, Esc ho zavře.
- Otevřený čip má modrý rámeček (`.hl-open`). Panel se překresluje s každým novým čtením (3 s).
- Velký graf v panelu ukazuje posledních 40 čtení (2 minuty), s plochou pod křivkou. Měřítko je
  100 % u CPU a RAM, u disků a sítě maximum za tu dobu (aspoň 1 kB/s).

### 4.4 Uložení voleb

Dvě preference **účtu** (v ai se ukládají k účtu na serveru, takže platí na všech zařízeních):

| Klíč | Hodnoty | Výchozí |
|---|---|---|
| `hload` | `graphs`, `pills`, `line`, `rings`, `off` | `graphs` |
| `hpanel` | `tiles`, `table`, `map`, `wide`, `off` | `tiles` |

`helpers.js` je pro demo drží v `localStorage`. V aplikaci napojte `prefs()` a `savePrefs()` na
ukládání k účtu. Neznámá hodnota znamená výchozí.

### 4.5 Texty a jazyky

Texty v kódu jsou anglicky. ai je při vykreslení překládá podle slovníku (`src/texts-cs.json`:
52 textů a 2 vzory s `{0}`). Čísla, jména procesů, disků a karet jsou označená `noI18n()`
(`data-no-i18n`), aby je překlad nechal být. Pokud vaše aplikace překládá jinak, obalte texty ve
`hload.js` svou funkcí, například `t('The processor')`.

Desetinná čárka se řídí jazykem stránky (`numDecimal()` v `helpers.js`), takže česky je „9,8 GB“.

### 4.6 CSS

`hload.css` obsahuje barvy v `:root`, takže si je můžete přepsat svými. Dále obsahuje čipy ve čtyřech
vzhledech, panel a jeho pět stylů, karty výběru a pravidla pro úzká okna. Kromě barev nic globálního
nemění: všechny třídy začínají `hl`, `hp-` nebo `pal-`. Demo navíc definuje `.muted`, `.small`
a `.mono`, které ai má obecně.

---

## 5. Postup převzetí do jiného projektu

1. Zkopírujte `src/load.py` (nebo přepište stejné výpočty do svého jazyka podle tabulky v 3.1) a napojte
   `GET /api/load` s parametrem `detail`, **jen pro administrátora**.
2. Zkopírujte `hload.js` a `hload.css`. `helpers.js` použijte, nebo funkce stejných jmen nahraďte
   svými (`api`, `prefs`, `savePrefs`, `bytes`, `el`, `$`, `clear`, `noI18n`, `toast`, `oops`, `LIVE`).
3. Do záhlaví vložte `<div class="hload" id="hload" hidden aria-live="off"></div>` (jen pro
   administrátora) a zavolejte `hloadLoop()`.
4. Do stránky účtu vložte `hloadPickers(element)` a napojte `prefs`/`savePrefs` na ukládání k účtu.
5. Přeložte texty (`texts-cs.json`).
6. Vyzkoušejte:
   - [ ] čísla se mění pod zátěží: `stress`/`yes > /dev/null`, `dd` na disk, stahování;
   - [ ] čipy neposkakují (krajní hodnoty);
   - [ ] panel se otevře myší i klepnutím a zavře odjetím, klepnutím jinam i Esc;
   - [ ] po zavření panelu se volá jen souhrn (bez `detail=1`);
   - [ ] schovaná stránka se neptá;
   - [ ] na stroji s čidly jsou teploty (jádra, NVMe, SATA s `drivetemp`), na VM hláška;
   - [ ] všech 5 + 5 voleb ve Vašem účtu, `off` u obou;
   - [ ] úzká okna (1300/1100/700 px) a iPad na šířku i na výšku.

## Teploty jader a topologie (4.4.3)

`coretemp` dává teplotu **fyzického jádra** (`Core N`, u více pouzder `coretemp.P`). Logický procesor
`cpuN` si najde své jádro podle `devices/system/cpu/cpuN/topology/core_id` a `physical_package_id`,
takže teplotu mají i druhá vlákna při hyperthreadingu a jádra s nesouvislými čísly. Bez topologie se
použije číslo `cpuN` jako dřív.

## Vypnuto znamená nic (4.4.3)

Přepínač **O aplikaci → Vytížení serveru v záhlaví** (`load_meter`, výchozí vypnuto) vypne měřič
úplně: stránky nemají v záhlaví nic a na nic se neptají, `/api/load` odmítne (403) dřív, než by
cokoli přečetl, a daemon sám nic z `/proc` ani `/sys` pro měřič nečte.
