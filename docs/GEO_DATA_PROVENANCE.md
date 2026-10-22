# Geo data provenance (`geoip.dat`, `geosite.dat`)

**Verdikt:** PARTIALLY ESTABLISHED — provenance established, redistribution rights unresolved

Tento dokument eviduje technický původ a integritu dvou geografických databází přibalených v Android AAR/APK a stav jejich licencí. **Není právním stanoviskem a nepotvrzuje soulad s licencemi.** Technicky doložený původ není právním potvrzením práva na redistribuci.

Datum auditu: 2026-10-22.

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

Interpretace (viz též bod 9):

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

## 4. `geoip.dat`

- Upstream artefakt: `Loyalsoldier/v2ray-rules-dat`, vydání `202503262212` (určeno dvojicí souborů).
- Podle workflow vydání se `geoip.dat` bere z vydání projektu `Loyalsoldier/geoip` (příkaz `wget https://github.com/Loyalsoldier/geoip/raw/release/geoip.dat`): https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/.github/workflows/run.yml
- README `Loyalsoldier/geoip` deklaruje licence „CC-BY-SA-4.0 and GPL-3.0“ a uvádí „This product includes GeoLite2 data created by MaxMind, available from MaxMind“: https://raw.githubusercontent.com/Loyalsoldier/geoip/master/README.md (sekce License; čteno 2026-10-22 z větve `master`, nikoli z historického stavu).
- README téhož projektu uvádí, že výchozím vstupem je MaxMind GeoLite2 Country CSV.
- Přesná provenience dat **konkrétního historického artefaktu** (které vstupy se do něj skutečně dostaly) není doložena jeho build konfigurací a zůstává částečně odvozená z README.
- Licence repozitáře sama o sobě nemusí dokazovat úplné distribuční podmínky všech zahrnutých dat.

### MaxMind GeoLite

Primární zdroj: https://www.maxmind.com/en/geolite2/eula

Auditované znění uvádělo „Updated on: February 12, 2026“. Shrnutí relevantních klauzulí:

1. Povinná atribuce, například „This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com“.
2. Zpřístupnění třetí straně je omezeno: kromě toho, co výslovně dovoluje příslušná Creative Commons licence, je třeba oznámení MaxMind a jeho předchozí písemný souhlas. Třetí straně se ukládají stejné nebo podobné smluvní povinnosti.
3. Klauzule o aktualizacích: starší verze se mají přestat používat a zničit do 30 dnů po vydání aktualizované databáze.

**Znění z roku 2026 se nepředkládá jako prokázané znění platné pro data z března 2025.** Historické znění podmínek nebylo ověřeno a použitelnost těchto klauzulí pro tento artefakt vyžaduje posouzení.

**Otevřená otázka:** povinnost zničit starší verze se může týkat produkčního AAR, protože obsahuje snapshot z března 2025.

## 5. `geosite.dat`

- Upstream artefakt: `Loyalsoldier/v2ray-rules-dat`, vydání `202503262212`.
- Repozitář `v2ray-rules-dat` deklaruje GPL-3.0: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/LICENSE (tag vydání).
- Workflow vydání zahrnuje kroky pro `Loyalsoldier/domain-list-custom`, `v2fly/domain-list-community` a `cokebar/gfwlist2dnsmasq` a dále pracuje s adresami označenými proměnnými `CHINA_DOMAINS_URL`, `EASYLISTCHINA_EASYLIST_REJECT_URL`, `ADGUARD_DNS_REJECT_URL`, `PETERLOWE_REJECT_URL`, `DANPOLLOCK_REJECT_URL` a `WIN_SPY`/`WIN_UPDATE`/`WIN_EXTRA`: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/.github/workflows/run.yml
- Přiřazení těchto vstupů ke konkrétním repozitářům a stránkám vychází z poděkování v README: https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/master/README.md. Konkrétní hodnoty URL proměnných nebyly při auditu čteny.

### Vstupy a jejich licenční stav

| Zdroj | Deklarace (GitHub API, 2026-10-22) | Ověření konkrétního artefaktu | Právní závěr o redistribuci |
|---|---|---|---|
| `v2fly/domain-list-community` | MIT | neprovedeno | neposouzeno |
| `Loyalsoldier/domain-list-custom` | MIT | neprovedeno | neposouzeno |
| `gaoyifan/china-operator-ip` | MIT | neprovedeno | neposouzeno |
| `crazy-max/WindowsSpyBlocker` | MIT | neprovedeno | neposouzeno |
| `gfwlist/gfwlist` | LGPL-2.1 | neprovedeno | neposouzeno |
| `cokebar/gfwlist2dnsmasq` | GPL-3.0 | neprovedeno | neposouzeno |
| `AdguardTeam/AdGuardSDNSFilter` | GPL-3.0 | neprovedeno | neposouzeno |
| `felixonmars/dnsmasq-china-list` | GitHub API: `NOASSERTION` („Other“) | licence neověřena | UNKNOWN |
| EasyList China | licence neověřena (API dotaz na `easylist/easylist` vrátil „Not Found“) | neověřeno | UNKNOWN |
| Peter Lowe adservers | licence/podmínky neověřeny | neověřeno | UNKNOWN |
| Dan Pollock hosts | licence/podmínky neověřeny | neověřeno | UNKNOWN |

Zdroj dat deklarací: `https://api.github.com/repos/<vlastník>/<repozitář>/license`.

Tři věci v tabulce nejsou totožné: (a) deklarace upstream projektu nebo API, (b) ověření licenčních podmínek konkrétního artefaktu v daném vydání, (c) právní závěr o redistribuci. V tomto dokumentu je splněno nejvýše (a). Licenci výsledného agregátu **nelze** odvodit pouze z tabulky jednotlivých vstupů.

## 6. Licence kódu a licence dat

Xray-core je licencován MPL-2.0 a AndroidLibXrayLite LGPL-3.0 (`third_party/xray/VERSION`). Tyto licence **nejsou automaticky licencí souborů** `geoip.dat` a `geosite.dat`. Licence dat se posuzuje samostatně (body 4 a 5).

## 7. NOTICE — TODO, čeká na právní posouzení

Stav: **TODO — čeká na právní posouzení.** Nic z následujícího není finální povinné oznámení.

- Atribuce MaxMind: čeká se na potvrzení použitelnosti klauzulí a jejich znění pro tento artefakt. Příklad uvedený v EULA je pouze příkladem.
- Copyright a licenční texty vyžadované u jednotlivých zdrojů z bodu 5: doplnit po ověření.
- Případná další povinná oznámení: doplnit.

## 8. Kontrolovaný postup aktualizace

1. Vybrat a explicitně připnout release tag. Neomezené `latest` nesmí být jediným záznamem původu.
2. Získat oficiální `.sha256sum` a ověřit, že odpovídá správnému artefaktu a vydání.
3. Nezávisle spočítat SHA-256 obou souborů.
4. Zaznamenat přesný tag, datum, URL, hashe, zdrojové vstupy a jejich licence.
5. Před začleněním ověřit změny licencí, nové zdroje a podmínky redistribuce.
6. Zkontrolovat povinné attribution, copyright a NOTICE.
7. Aktualizovat AAR a tento dokument až po technickém a licenčním schválení.

Ověření integrity (kroky 2–3) není ověřením licence (kroky 4–6).

## 9. Evidence a odkazy

| Odkaz / dokument | Povaha |
|---|---|
| https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202503262212/geoip.dat a `geosite.dat` (+ `.sha256sum`) | primární zdroj |
| https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases/tags/202503262212 | primární zdroj |
| https://api.github.com/repos/2dust/AndroidLibXrayLite/git/trees/c634d1baea97e94320c0bf6a9cf637369c4f11d4?recursive=1 | primární zdroj |
| https://api.github.com/repos/2dust/AndroidLibXrayLite/commits/759e3e7232 | primární zdroj |
| `gen_assets.sh`, `.github/workflows/main.yml` na commitu `c634d1b…` (URL v bodě 2) | primární zdroj |
| https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/202503262212/.github/workflows/run.yml a `LICENSE` | primární zdroj |
| https://raw.githubusercontent.com/Loyalsoldier/geoip/master/README.md, https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/master/README.md | primární zdroj (aktuální stav větve, ne historický) |
| `https://api.github.com/repos/<vlastník>/<repozitář>/license` | primární zdroj (deklarace) |
| https://www.maxmind.com/en/geolite2/eula | primární zdroj (znění k 2026-10-22) |
| `android/app/libs/libv2ray-androidlibxraylite-c634d1b-nova-b35xhttp1.aar`, `third_party/xray/VERSION`, `third_party/xray/build-xray-wsl.sh`, `.github/workflows/android-ci.yml` | lokální artefakty |
| Archiv `RUN-20261022-025849` (lokální cesta, bez veřejného odkazu) | výsledek experimentu |

Experimentální evidence (pět případů `RUN` v debug balíčku `net.pocvpn.client.geoexp`, Xray-core v26.7.28) dokládá, že Xray načetl a použil databáze. **Nedokládá licenci ani právo na redistribuci.**

## 10. Závěr

PARTIALLY ESTABLISHED — provenance established, redistribution rights unresolved.

- Identita a původ dvojice souborů jsou technicky doložené.
- Právo na redistribuci v APK/AAR není prokázáno.
- Licenční posouzení je otevřené (bod 4, 5 a 7).
- Dokument není právním stanoviskem.
