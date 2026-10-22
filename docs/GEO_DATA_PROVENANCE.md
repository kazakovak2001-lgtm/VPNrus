# Geo data provenance (`geoip.dat`, `geosite.dat`)

**Verdikt:** PARTIALLY ESTABLISHED — provenance established, redistribution rights unresolved

Tento dokument eviduje technický původ a integritu dvou geografických databází přibalených v Android AAR/APK a stav jejich licencí. **Není právním stanoviskem a nepotvrzuje soulad s licencemi.** Technicky doložený původ není právním potvrzením práva na redistribuci.

Datum auditu: 2026-10-22 (původ), 2026-10-22 (licenční prověrka, bod 4–9).

Značení důkazů: **PROVEN** = přímý primární dokument nebo artefakt; **INFERRED** = závěr z více primárních dokumentů, který nebyl pozorován přímo; **UNKNOWN** = nedoloženo. Hodnoty označené „aktuální“ byly čteny 2026-10-22 a **nepředstavují automaticky podmínky platné v březnu 2025**.

## 1. Identita souborů

| Soubor | Velikost | SHA-256 |
|---|---:|---|
| `geoip.dat` | 18 534 419 B | `7806115947f8a704d347fa103aa83aadc2cd531a72b82c44d991d598ac23eae9` |
| `geosite.dat` | 8 659 692 B | `725397e93d0043146973220c106eb7e53ccbfd39508a63389e9fa0f7d616c06d` |

Oba soubory jsou bajtově shodné (stejná velikost a SHA-256) s dvojicí artefaktů vydání `202503262212` projektu `Loyalsoldier/v2ray-rules-dat`.

Nuance určení vydání:

- `geoip.dat` má stejný SHA-256 ve vydáních `202503202212` až `202503262212`.
- `geosite.dat` má tento SHA-256 pouze ve vydání `202503262212`.
- Vydání lze proto jednoznačně určit pro **dvojici** souborů, nikoli pro `geoip.dat` samostatně.

## 2. Doložená cesta do AAR

| Tvrzení | Zdroj | Povaha zdroje |
|---|---|---|
| Projektový AAR `android/app/libs/libv2ray-androidlibxraylite-c634d1b-nova-b35xhttp1.aar` (SHA-256 `832dc038e3e8c50c91d9be6a8a6d9867075a6ded3b61129089257ab47a1ed28d`) obsahuje `assets/geoip.dat` a `assets/geosite.dat` s hashi v bodě 1. Stejné hashe má i starší AAR `…c634d1b.aar`. | lokální artefakt; hash AAR je v `.github/workflows/android-ci.yml:38` | lokální artefakt |
| Wrapper je připnutý na `2dust/AndroidLibXrayLite` commit `c634d1baea97e94320c0bf6a9cf637369c4f11d4`. | `third_party/xray/VERSION` | lokální artefakt |
| Strom tohoto commitu obsahuje `assets/geoip.dat` (blob SHA-1 `0d53f04e279a9ae68d9b2608025d1cd1ab4cfb07`, 18 534 419 B) a `assets/geosite.dat` (blob SHA-1 `3f09bf20534174803b89d0d3e1a10e85986c8708`, 8 659 692 B). Git blob SHA-1 spočtený z obsahu souborů v AAR se s těmito hodnotami shoduje. | https://api.github.com/repos/2dust/AndroidLibXrayLite/git/trees/c634d1baea97e94320c0bf6a9cf637369c4f11d4?recursive=1 | primární zdroj |
| Soubory naposledy změnil commit `759e3e7232` z 2025-03-27 „Geofiles: Switch to Loyalsoldier's v2ray-rules-dat (#132)“. | https://api.github.com/repos/2dust/AndroidLibXrayLite/commits/759e3e7232 a historie souborů: https://api.github.com/repos/2dust/AndroidLibXrayLite/commits?path=assets/geoip.dat&sha=c634d1baea97e94320c0bf6a9cf637369c4f11d4 | primární zdroj |
| `gen_assets.sh` stahuje `…/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat` a `geosite.dat`. | https://raw.githubusercontent.com/2dust/AndroidLibXrayLite/c634d1baea97e94320c0bf6a9cf637369c4f11d4/gen_assets.sh | primární zdroj |
| CI wrapperu v kroku Build spouští `bash gen_assets.sh download` a `cp -v data/*.dat assets/`; `.gitignore` obsahuje `assets/`. | https://raw.githubusercontent.com/2dust/AndroidLibXrayLite/c634d1baea97e94320c0bf6a9cf637369c4f11d4/.github/workflows/main.yml a `.gitignore` | primární zdroj |
| `third_party/xray/build-xray-wsl.sh` v auditované podobě geo databáze nestahuje; builduje wrapper z checkoutu pinned commitu. | `third_party/xray/build-xray-wsl.sh` | lokální artefakt |

Interpretace (viz též bod 11):

- CI wrapperu stahuje nepinnované `releases/latest`. To **neprokazuje**, že konkrétní AAR vznikl stažením aktuálního `latest`.
- Pinned AAR obsahuje historický snapshot, který odpovídá výše uvedeným hashům i blobům commitnutým ve wrapperu.
- Skutečný průběh historického buildu AAR nebyl pozorován (build probíhal mimo auditované prostředí).

Hashová shoda s vydáním `202503262212`:

- https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202503262212/geoip.dat
- https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202503262212/geosite.dat
- `.sha256sum` ke každému souboru na téže cestě s příponou `.sha256sum`
- metadata vydání: https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/tags/202503262212 (publikováno 2025-03-26T22:12:52Z)

Soubory stažené při auditu měly lokálně spočtené SHA-256 shodné s hodnotami v bodě 1.

## 3. Stav stagingu (neslučovat s dodaným stavem)

Runtime staging (`GeoDataStager`) existuje pouze na nezmergované větvi `feature/geo-phase-a-bundled-assets`, HEAD `75c4cd35fac0667c3ccd69ecdc226cbbf0725f50`. **Není součástí `main` ani produkčního buildu.**

Plánovaná cesta po případném sloučení příslušné změny:

AAR assets → APK assets → `GeoDataStager` → `noBackupFilesDir/xray-assets/geo-<id>`

Do té doby není tvrzení o stagingu dodanou vlastností produktu.

## 4. `geoip.dat`: vstupy a licence

### 4.1 Z čeho byl soubor sestaven

- `geoip.dat` se ve workflow vydání `202503262212` stahuje z vydání `Loyalsoldier/geoip` (`wget https://github.com/Loyalsoldier/geoip/raw/release/geoip.dat`) — **PROVEN**: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/.github/workflows/run.yml
- Poslední commit větve `master` projektu `Loyalsoldier/geoip` před 2025-03-21 je `fdab3dd2dea595f4aecd48bfd725b4bacf315b62` z 2025-02-01 (GitHub API, dotaz na commity s `until=2025-03-21`). Jeho `config.json` a `.github/workflows/build.yml`: https://raw.githubusercontent.com/Loyalsoldier/geoip/fdab3dd2dea595f4aecd48bfd725b4bacf315b62/config.json a https://raw.githubusercontent.com/Loyalsoldier/geoip/fdab3dd2dea595f4aecd48bfd725b4bacf315b62/.github/workflows/build.yml
  - Workflow se spouští týdně (`cron: "0 0 * * 4"`, čtvrtek; 2025-03-20 byl čtvrtek) a stahuje z `download.maxmind.com` edice `GeoLite2-Country-CSV`, `GeoLite2-ASN-CSV` (a mmdb) s licenčním klíčem z GitHub secret — **PROVEN** pro konfiguraci platnou v březnu 2025.
  - `config.json` vstupy: `maxmindGeoLite2CountryCSV`, `maxmindGeoLite2ASNCSV` (kategorie cloudflare, facebook, fastly, google, netflix, telegram, twitter), textové seznamy `cn` (`17mon/china_ip_list`, `gaoyifan/china-operator-ip` IPv4 a IPv6), `tor` (`check.torproject.org/torbulkexitlist`), `cloudflare`, `telegram`, `google` (`goog.json`, `cloud.json`), `fastly`, `cloudfront` (`ip-ranges.amazonaws.com`) a `private`; výstup `v2rayGeoIPDat`.
- Že konkrétní release soubor `geoip.dat` z 2025-03-20 byl sestaven právě touto konfigurací, **nebylo pozorováno** (větev `release` je přepisována a build logy nejsou dostupné): **INFERRED**, silně (konfigurace, týdenní cyklus a změna hashe `geoip.dat` v `202503202212` do sebe zapadají).

### 4.2 Licence repozitáře `Loyalsoldier/geoip`

- README deklaruje „CC-BY-SA-4.0 and GPL-3.0“ a „This product includes GeoLite2 data created by MaxMind, available from MaxMind“: https://raw.githubusercontent.com/Loyalsoldier/geoip/master/README.md (sekce License; čteno z aktuální větve `master`, **nikoli z historického stavu**). Texty licencí jsou v repozitáři v souborech `LICENSE` (CC BY-SA 4.0) a `LICENSE-GPL`; oba soubory existují i v commitu `fdab3dd2…` (strom commitu).
- Deklarace repozitáře neurčuje, která část výstupu `geoip.dat` pod kterou licencí je. Licence dat třetích stran (MaxMind a další vstupy v bodě 4.4) tím nejsou nahrazeny.

### 4.3 MaxMind GeoLite2 — znění platné v době vydání

- Znění archivované 2025-03-29 (tři dny po vydání `202503262212`): http://web.archive.org/web/20250329193755/https://www.maxmind.com/en/geolite2/eula — „GeoLite2 End User License Agreement, Updated on: December 7, 2020“ — **PROVEN** (archivní kopie; text byl přečten a klauzule níže z ní pocházejí).
- Aktuální znění (https://www.maxmind.com/en/geolite2/eula, „Updated on: February 12, 2026“) má v relevantních bodech stejnou věcnou strukturu (atribuce, omezení zpřístupnění, zničení starších verzí). Pro tento artefakt je rozhodující znění z roku 2020, ne to z roku 2026.

Klauzule znění z 2020-12-07 (sekce podle archivní kopie):

1. **§1 Additional policies:** „Creative Commons Corporation Attribution-ShareAlike 4.0 International License“ je zahrnuta odkazem a při rozporu má smlouva přednost.
2. **§3 Limited grant of rights:** pokud služby obsahují autorsky chráněné prvky, řídí se tyto prvky licencí Creative Commons; „You must provide attribution of your use to MaxMind (an example of attribution: "This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com .")“. Navíc je při vnitřním použití udělena nepřenosná licence „for your own internal business purposes“; nesmí se odstranit copyright ani jiná oznámení obsažená ve službách.
3. **§6 Disclosure of Services:** „Except as explicitly permitted by the Creative Commons License, you will not disclose the Services to any third party or after notifying MaxMind … and obtaining MaxMind's prior written consent“; třetí straně, které se služby zpřístupní, se ukládají stejné nebo podobné povinnosti (§3, §6, DPA a CC licence). Znění archivované kopie obsahuje „or after notifying“; zdá se jít o překlep, doslovný text se proto cituje bez interpretace.
4. **§6 Destruction:** „You shall cease use of and destroy (i) any old versions of the Services within thirty (30) days following the release of the updated GeoLite2 Databases; and (ii) all Services immediately upon termination …“.
5. **§8–10:** odškodnění, služba je zdarma a MaxMind může smlouvu změnit nebo ukončit.

Co z toho plyne, a co ne:

- Není doloženo, kdo je v řetězci „you“ (strana, která stáhla data s licenčním klíčem, je podle workflow provozovatel `Loyalsoldier/geoip`). **UNKNOWN — legal confirmation required**, zda je projekt VPNrus smluvní stranou této EULA, nebo jen příjemcem odvozeného souboru.
- **UNKNOWN — legal confirmation required**, zda odvozený `geoip.dat` spadá pod výjimku „explicitly permitted by the Creative Commons License“, a jaký má CC BY-SA 4.0 dopad na kombinované dílo (APK/AAR).
- Povinnost zničit staré verze (§6) by při doslovném výkladu pro licencovanou stranu znamenala přestat používat snapshot z března 2025, který je nyní o víc než 19 měsíců starší než aktuální vydání. Použitelnost této klauzule na VPNrus je **UNKNOWN — legal confirmation required**.
- Rozdíl mezi distribucí databáze, integrací do AAR/APK a používáním v aplikaci EULA **nerozlišuje** výslovně; konkrétní podmínky pro každý z těchto případů nelze z textu spolehlivě odvodit bez právního výkladu.

### 4.4 Ostatní vstupy `geoip.dat`

| Vstup | Licenční evidence | Stav |
|---|---|---|
| `gaoyifan/china-operator-ip` | MIT (deklarace GitHub API, aktuální); licenční soubor nebyl čten | deklarace |
| `17mon/china_ip_list` | GitHub API: bez licence („Not Found“, aktuální) | UNKNOWN |
| Tor Project `torbulkexitlist`, Cloudflare `ips-v4/v6`, Telegram `cidr.txt`, Google `goog.json`/`cloud.json`, Fastly `public-ip-list`, AWS `ip-ranges.json` | podmínky těchto veřejných seznamů nebyly zkoumány | UNKNOWN |

## 5. `geosite.dat`: vstupy a licence

### 5.1 Z čeho byl soubor sestaven (**PROVEN** z workflow vydání)

Zdroj: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/.github/workflows/run.yml (adresy proměnných prostředí a kroky buildu). Workflow:

- checkoutuje `Loyalsoldier/domain-list-custom`, `v2fly/domain-list-community` a `cokebar/gfwlist2dnsmasq` a z větve `hidden` téhož repozitáře přidává ručně vedené seznamy `proxy.txt`, `direct.txt`, `reject.txt`;
- stahuje domény z těchto adres (proměnné `*_URL`):
  - `felixonmars/dnsmasq-china-list` (`accelerated-domains.china.conf`, `google.china.conf`, `apple.china.conf`) — seznamy `cn`, `china-list`, `google-cn`, `apple-cn`;
  - `https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt`, `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt`, `https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext`, `https://someonewhocares.org/hosts/hosts` — všechny čtyři se přes `temp-reject.txt` slučují do seznamu **`category-ads-all`** (kroky „Sort and generate redundant lists“ a „Write lists to data directory“: `temp-category-ads-all.txt` → `community/data/category-ads-all`);
  - `crazy-max/WindowsSpyBlocker` (`spy.txt`, `update.txt`, `extra.txt`) — seznamy `win-spy`, `win-update`, `win-extra`;
  - `cokebar/gfwlist2dnsmasq.sh` generuje seznamy `gfw` a `greatfire` z GFWList;
- `geosite.dat` vzniká krokem `go run ./ --datapath=../community/data` z adresáře `community/data` (`v2fly/domain-list-community` doplněný výše uvedenými seznamy).

Lokální `geosite.dat` obsahuje (kódy zjištěné při dřívějším auditu) kategorie `GFW`, `GREATFIRE`, `WIN-SPY`, `WIN-UPDATE`, `WIN-EXTRA`, `CATEGORY-ADS-ALL`, `CN`, `GEOLOCATION-!CN`, což s workflow souhlasí.

### 5.2 Licenční evidence jednotlivých vstupů

„Deklarace“ = pole `license` GitHub API (aktuální). „Primární text“ = přečtený licenční soubor nebo hlavička zdroje. Sloupec „Historický“ říká, zda byl ověřen stav k březnu 2025.

| Vstup (zdroj) | Licence podle primárního textu | Povinnosti uvedené v textu | Historický stav | Stav |
|---|---|---|---|---|
| `v2fly/domain-list-community` | MIT, „Copyright (c) 2018-2019 V2Ray“ (https://raw.githubusercontent.com/v2fly/domain-list-community/master/LICENSE) | zachovat copyright a text MIT licence v kopiích | neověřen (aktuální `master`) | primární text, aktuální |
| `Loyalsoldier/domain-list-custom` | MIT, „Copyright (c) 2020 Loyalsoldier“ (https://raw.githubusercontent.com/Loyalsoldier/domain-list-custom/master/LICENSE) | totéž | neověřen | primární text, aktuální |
| `crazy-max/WindowsSpyBlocker` | MIT, „Copyright (c) 2016-2022 CrazyMax“ (https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/LICENSE) | totéž | neověřen | primární text, aktuální |
| `gaoyifan/china-operator-ip` | MIT (jen deklarace API) | — | neověřen | deklarace |
| `felixonmars/dnsmasq-china-list` | **WTFPL v2** — „This work is free. You can redistribute it and/or modify it under the terms of the Do What The Fuck You Want To Public License, Version 2“ (https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/LICENSE, README sekce License) | žádné | neověřen | primární text, aktuální (GitHub API vrací `NOASSERTION`, ale soubor `LICENSE` text WTFPL obsahuje) |
| `gfwlist/gfwlist` | **LGPL-2.1** — soubor `COPYING.txt` obsahuje „GNU LESSER GENERAL PUBLIC LICENSE Version 2.1, February 1999“ (https://raw.githubusercontent.com/gfwlist/gfwlist/master/COPYING.txt) | LGPL-2.1 | neověřen | primární text, aktuální |
| `cokebar/gfwlist2dnsmasq` | **GPL-3.0** (soubor `LICENSE`, https://raw.githubusercontent.com/cokebar/gfwlist2dnsmasq/master/LICENSE). Je to skript, který GFWList převádí; licence kódu skriptu | GPL-3.0 pro skript | neověřen | primární text, aktuální |
| `AdguardTeam/AdGuardSDNSFilter` (filtr `filter.txt`) | **GPL-3.0** — hlavička filtru: „License: https://github.com/AdguardTeam/AdguardSDNSFilter/blob/master/LICENSE“; soubor `LICENSE` obsahuje text GPL v3 (https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/LICENSE) | GPL-3.0 | neověřen (hlavička čtena 2026-10-22) | primární text, aktuální |
| EasyList China + EasyList (`easylistchina+easylist.txt`) | Hlavička: „License: https://easylist.to/pages/licence.html“. Stránka: obsah repozitáře EasyList je „unless otherwise noted“ duálně licencován **GPL-3.0-or-later a CC BY-SA 3.0 (or later)**, „‘The EasyList authors (https://easylist.to/)’ should be attributed“; souborům mimo EasyList, EasyPrivacy, EasyList Germany a EasyList Italy mohou platit jiné podmínky a „permission must be granted by the respective copyright holders“. **EasyList China ve výčtu není**; repozitář `easylist/easylistchina` neobsahuje licenční soubor (GitHub strom: `easylistchina.txt`, `.gitattributes`, `FOP-nocommit.py`, `issue_template.md`) | pro EasyList: atribuce autorů EasyList | neověřen | **UNKNOWN** pro část EasyList China; pro část EasyList duální licence podle stránky |
| Peter Lowe `adservers` | V hlavičce seznamu (aktuální) je jen „credits“ a odkaz na https://pgl.yoyo.org/adservers/policy.php; stránka policy (aktuální) obsahuje pravidla zařazování hostitelů, **žádnou licenci ani povolení k redistribuci** | — | neověřen | **UNKNOWN** (žádný licenční text nalezen) |
| Dan Pollock `hosts` | Hlavička (aktuální 2026-10-22 i archivní kopie z 2025-03-27 `http://web.archive.org/web/20250327202959/https://someonewhocares.org/hosts/hosts`, „Last updated: Thu, 20 Mar 2025“): **„You are free to copy and distribute this file for non-commercial uses, as long the original URL and attribution is included.“** (`http://someonewhocares.org/hosts/`) | **pouze nekomerční použití**; uvést původní URL a atribuci | **ověřen** archivní kopií z března 2025 | **PROVEN** omezení na nekomerční použití |
| Soubory z větve `hidden` repozitáře `Loyalsoldier/v2ray-rules-dat` (`proxy.txt`, `direct.txt`, `reject.txt`) | původ nezkoumán | — | neověřen | UNKNOWN |

### 5.3 Čtyři vrstvy, které se nesmí zaměnit

1. **Licence zdrojových dat:** viz tabulka. Pro Dana Pollocka je to primární text s omezením na nekomerční použití.
2. **Licence agregovaného výstupu `geosite.dat`:** žádný dokument ji neurčuje. `v2ray-rules-dat` deklaruje GPL-3.0 (soubor `LICENSE` v tagu `202503262212`), ale tento text se výslovně vztahuje k repozitáři; zda se vztahuje i na release artefakty, **nebylo doloženo**. Licence agregátu nesmí být odvozena z tabulky vstupů.
3. **Povinnosti při redistribuci výsledného souboru:** atribuce (MIT, Pollock, případně EasyList), případně podmínky GPL/LGPL, pokud se na odvozená data vztahují. Neznámé: viz bod 8.
4. **Povinnosti projektu VPNrus při distribuci aplikace:** zda a které z výše uvedených podmínek se na VPNrus vztahují jako na distributora APK, závisí na právním výkladu (odvozené dílo, agregace, komerční povaha distribuce). **UNKNOWN — legal confirmation required.**

Konkrétní konflikt: seznam `category-ads-all` v `geosite.dat` je odvozen mimo jiné ze seznamu s podmínkou „non-commercial uses“ (Pollock), ze seznamu s GPL-3.0 (AdGuard) a ze seznamů bez doložené licence (Peter Lowe, EasyList China). Pokud je distribuce VPNrus komerční, je nekomerční omezení Pollocka přímým rozporem, který nelze odstranit atribucí.

## 6. Licence kódu a licence dat

Xray-core je licencován MPL-2.0 a AndroidLibXrayLite LGPL-3.0 (`third_party/xray/VERSION`). Tyto licence **nejsou automaticky licencí souborů** `geoip.dat` a `geosite.dat`. Licence dat se posuzuje samostatně (body 4 a 5).

## 7. Rozhodovací matice

| Soubor | Závěr | Důkazy | Limity závěru |
|---|---|---|---|
| `geoip.dat` | **UNKNOWN — LEGAL CONFIRMATION REQUIRED** | Obsahuje data odvozená z MaxMind GeoLite2 (konfigurace a workflow v březnu 2025, bod 4.1; vydání INFERRED). EULA znění 2020-12-07 (archiv 2025-03-29, bod 4.3): atribuce, omezení zpřístupnění třetí straně bez souhlasu MaxMind kromě toho, co povoluje CC BY-SA 4.0, flow-down, zničení starších verzí do 30 dnů. Další vstupy (`17mon`) bez licence | Není doloženo, zda je VPNrus smluvní stranou EULA, zda výjimka CC pokrývá odvozený soubor v APK a jaký dopad má share-alike |
| `geosite.dat` | **REDISTRIBUTION BLOCKED PENDING SPECIFIC ACTION** (platí, pokud je distribuce VPNrus komerční) | Vstup Dan Pollock s podmínkou „non-commercial uses“ ověřen i pro březen 2025 (bod 5.2); Peter Lowe a EasyList China bez doložené licence; AdGuard GPL-3.0 | Komerční povaha distribuce VPNrus v dokumentu není stanovena. Dopad GPL/LGPL na agregát je otevřený |

Dokument nedává právní záruku. Tyto závěry říkají jen to, co jsou dostupné primární dokumenty schopny podpořit.

## 8. NOTICE — navržený obsah pouze pro doložené povinnosti

Stav: **TODO — čeká na právní posouzení.** Nic z následujícího není finální povinné oznámení a nic z toho nemá být zveřejněno, dokud není rozhodnuto, zda příslušná povinnost na VPNrus dopadá.

| Zdroj | Doložená povinnost a její zdroj | Navržený obsah (návrh, ne finální text) |
|---|---|---|
| MaxMind GeoLite2 | §3 EULA znění 2020-12-07: atribuce; příklad „This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com .“ | uvést atribuci; **text a umístění TODO** |
| Dan Pollock hosts | hlavička: uvést původní URL a atribuci, pouze nekomerční použití | „Domain list derived from Dan Pollock's hosts file, http://someonewhocares.org/hosts/“ — **použitelné jen pokud je distribuce nekomerční**; jinak viz bod 9 |
| `v2fly/domain-list-community` | MIT: zachovat „Copyright (c) 2018-2019 V2Ray“ a text MIT | **TODO** (zda se MIT vztahuje na odvozená data v binárním souboru) |
| `Loyalsoldier/domain-list-custom` | MIT: „Copyright (c) 2020 Loyalsoldier“ | **TODO** |
| `crazy-max/WindowsSpyBlocker` | MIT: „Copyright (c) 2016-2022 CrazyMax“ | **TODO** |
| `gaoyifan/china-operator-ip` | MIT (deklarace API); copyright řádek nečten | **TODO** |
| EasyList | „The EasyList authors (https://easylist.to/)“ má být uvedeno, pokud je to vyžadováno (stránka licencí) | **TODO**; EasyList China bez doložené licence |
| `AdguardTeam/AdGuardSDNSFilter` (GPL-3.0), `gfwlist` (LGPL-2.1) | licenční texty jsou doložené, vztah k distribuci odvozených dat není | **TODO — právní otázka** |
| `felixonmars/dnsmasq-china-list` | WTFPL v2: žádné povinnosti | bez oznámení |
| Peter Lowe, `17mon/china_ip_list`, ostatní IP seznamy, větev `hidden` | licence nedoložena | **TODO — bez textu** |

## 9. Blokátory distribuce a minimální kroky

| # | Blokátor | Minimální krok k odstranění |
|---|---|---|
| 1 | `geosite.dat` obsahuje data odvozená z Pollockova seznamu s podmínkou „non-commercial uses“ | (a) potvrdit, že distribuce VPNrus je nekomerční, nebo (b) písemné povolení od Dana Pollocka (hosts@someonewhocares.org dle hlavičky), nebo (c) nahradit `geosite.dat` souborem sestaveným bez tohoto seznamu |
| 2 | Peter Lowe a EasyList China bez licence | písemné potvrzení podmínek od autora (Peter Lowe — kontakt v hlavičce seznamu; EasyList China — projekt `easylist/easylistchina` a stránka licencí EasyList), nebo vyřazení vstupů z `geosite.dat` |
| 3 | GeoLite2 EULA (znění 2020) a CC BY-SA 4.0 pro odvozený `geoip.dat` | právní posouzení: je VPNrus vázán EULA, kryje distribuci v APK výjimka CC, jak se projeví share-alike, jaký je dopad povinnosti zničit staré verze; případně souhlas MaxMind nebo nahrazení `geoip.dat` souborem bez GeoLite2 dat |
| 4 | GPL-3.0/LGPL-2.1 vstupy (AdGuard, gfwlist, výstupní repozitář `v2ray-rules-dat`) | právní posouzení, zda a jak se vztahují na distribuovaná data a APK |
| 5 | Neznámé: `17mon`, ostatní IP seznamy, větev `hidden` | dohledat původ a licenci, nebo vyřadit |
| 6 | Neexistuje dokumentovaný postup aktualizace snapshotu | doplnit podle bodu 10 |

Obecná možnost pro blokátory 1–5: do doby vyřešení jednoho z uvedených kroků nepřibalovat tyto dva soubory (assety AAR nejsou pro dnešní funkce nutné — žádné `geoip:`/`geosite:` pravidlo se zatím nerenderuje, viz `XrayConfigRenderer`) nebo je nahradit souborem sestaveným výhradně z doložitelně redistribuovatelných zdrojů. Provedení kterékoli z těchto změn vyžaduje samostatné rozhodnutí a není součástí tohoto dokumentu.

## 10. Kontrolovaný postup aktualizace

1. Vybrat a explicitně připnout release tag. Neomezené `latest` nesmí být jediným záznamem původu.
2. Získat oficiální `.sha256sum` a ověřit, že odpovídá správnému artefaktu a vydání.
3. Nezávisle spočítat SHA-256 obou souborů.
4. Zaznamenat přesný tag, datum, URL, hashe, zdrojové vstupy (včetně adres z `run.yml` a `config.json` daného vydání) a jejich licence.
5. Před začleněním ověřit změny licencí, nové zdroje a podmínky redistribuce — **včetně verze EULA MaxMind platné pro dané vydání** (archivní kopie nebo datum).
6. Zkontrolovat povinné attribution, copyright a NOTICE.
7. Aktualizovat AAR a tento dokument až po technickém a licenčním schválení.

Ověření integrity (kroky 2–3) není ověřením licence (kroky 4–6).

## 11. Evidence a odkazy

| Odkaz / dokument | Povaha |
|---|---|
| https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202503262212/geoip.dat a `geosite.dat` (+ `.sha256sum`) | primární zdroj |
| https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/tags/202503262212 | primární zdroj |
| https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/.github/workflows/run.yml a `LICENSE` | primární zdroj (stav k tagu) |
| https://api.github.com/repos/2dust/AndroidLibXrayLite/git/trees/c634d1baea97e94320c0bf6a9cf637369c4f11d4?recursive=1 | primární zdroj |
| https://api.github.com/repos/2dust/AndroidLibXrayLite/commits/759e3e7232 | primární zdroj |
| `gen_assets.sh`, `.github/workflows/main.yml` na commitu `c634d1b…` (URL v bodě 2) | primární zdroj |
| https://raw.githubusercontent.com/Loyalsoldier/geoip/fdab3dd2dea595f4aecd48bfd725b4bacf315b62/config.json a `…/.github/workflows/build.yml` | primární zdroj (stav k 2025-02-01, platný v březnu 2025) |
| https://raw.githubusercontent.com/Loyalsoldier/geoip/master/README.md, https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/master/README.md | primární zdroj (aktuální stav větve, ne historický) |
| http://web.archive.org/web/20250329193755/https://www.maxmind.com/en/geolite2/eula | archivní kopie primárního zdroje (EULA, Updated on: December 7, 2020) |
| https://www.maxmind.com/en/geolite2/eula | primární zdroj (aktuální, Updated on: February 12, 2026) |
| http://web.archive.org/web/20250327202959/https://someonewhocares.org/hosts/hosts | archivní kopie primárního zdroje (hlavička s omezením na nekomerční použití) |
| https://someonewhocares.org/hosts/hosts, https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext, https://pgl.yoyo.org/adservers/policy.php, https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt, https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt, https://easylist.to/pages/licence.html | primární zdroje (aktuální hlavičky a stránky, čteno 2026-10-22) |
| licenční soubory: `v2fly/domain-list-community`, `Loyalsoldier/domain-list-custom`, `crazy-max/WindowsSpyBlocker`, `felixonmars/dnsmasq-china-list`, `cokebar/gfwlist2dnsmasq`, `AdguardTeam/AdGuardSDNSFilter` (každý `…/master/LICENSE`) a `gfwlist/gfwlist` (`…/master/COPYING.txt`) na `https://raw.githubusercontent.com/<vlastník>/<repozitář>/master/` | primární zdroje (aktuální `master`) |
| `https://api.github.com/repos/<vlastník>/<repozitář>/license` | primární zdroj (jen deklarace) |
| `android/app/libs/libv2ray-androidlibxraylite-c634d1b-nova-b35xhttp1.aar`, `third_party/xray/VERSION`, `third_party/xray/build-xray-wsl.sh`, `.github/workflows/android-ci.yml` | lokální artefakty |
| Archiv `RUN-20261022-025849` (lokální cesta, bez veřejného odkazu) | výsledek experimentu |

Experimentální evidence (pět případů `RUN` v debug balíčku `net.pocvpn.client.geoexp`, Xray-core v26.7.28) dokládá, že Xray načetl a použil databáze. **Nedokládá licenci ani právo na redistribuci.**

## 12. Závěr

PARTIALLY ESTABLISHED — provenance established, redistribution rights unresolved.

- Identita a původ dvojice souborů jsou technicky doložené, včetně vstupů obou souborů pro vydání z března 2025.
- Právo na redistribuci v APK/AAR není prokázáno. `geoip.dat`: UNKNOWN — legal confirmation required. `geosite.dat`: blokováno do vyřešení konkrétních kroků v bodě 9 (zejména nekomerční podmínka Pollocka).
- Licenční posouzení je otevřené (body 4, 5, 7 a 9).
- Dokument není právním stanoviskem.
