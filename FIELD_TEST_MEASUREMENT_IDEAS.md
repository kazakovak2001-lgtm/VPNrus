# Field test – návrh dalších měření (pro budoucí práci)

Stav k `3d6908b` + lokální změna „FULL/MONITOR v release“ (necommitnuto).
Nic z níže uvedeného není implementováno. Pořadí odpovídá přínosu pro RU vydání.

## P1 – přímo potřebné pro RU rozhodnutí

| Měření | Co přesně | Proč |
|---|---|---|
| **Čas obnovy po změně sítě** | MONITOR zaznamená přechod Wi-Fi ↔ mobilní data a změří dobu do prvního úspěšného probe přes tunel. Do reportu se zapíše hodnota `recoveryMs` a transport, který se po obnově použil. | Ve fyzickém testu trvala obnova asi 130 s. Měření ukáže, jestli jde o problém transportu, Smart Connect nebo sítě. |
| **Detekce ořezu TCP po ~16 KB a jiného zahazování** | V tunelu stáhnout postupně 16 KB, 64 KB, 256 KB a 1 MB. U každé velikosti zaznamenat `stalledAtBytes` a čas do prvního bajtu. | Ruské DPI často ořízne spojení po prvních desítkách kB a samotné „připojeno“ to neodhalí. |
| **Dlouhodobé zahazování podle délky spojení** | MONITOR na 30, 60 a 120 minut s procentem dostupnosti po časových oknech, ne jen jedním celkovým číslem. | Některé ruské sítě nechají spojení projít, ale po 5–15 minutách ho zablokují. |
| **SNI a TLS fingerprint test bez VPN** | Handshake na stejnou IP s různými SNI (doména pp.ua, „neutrální“ doména, SNI z REALITY profilu). Vyhodnotit, zda je výsledkem RST, timeout, nebo průchod. | Field test už ukázal blokaci pp.ua podle SNI. Měření ukáže, které SNI pro REALITY projde. |
| **UDP dostupnost podle portu** | Krátký UDP echo nebo handshake na porty AWG a Hysteria2 a na pár běžných portů (443, 53, 500/4500). | AWG v Rusku vypršelo. Měření odliší blokaci UDP obecně od blokace konkrétního portu. |
| **Úspěšnost transportu podle operátora** | Do souhrnu reportu přidat ASN a operátora a ke každému transportu výsledek OK nebo FAIL. Bez IP adres. | Umožní spojit výsledky od více testerů (MTS, Beeline, MegaFon, Tele2). |

## P2 – kvalita a bezpečnost

| Měření | Co přesně |
|---|---|
| **Kill-switch při pádu aplikace** | Výpis, zda je zapnuté Always-on a lockdown (`VpnManager`, `isAlwaysOn`/`isLockdownEnabled`, pokud je to bez práv dostupné). Report pak řekne, jestli by pád aplikace vedl k úniku. |
| **Únik WebRTC/STUN** | STUN dotaz mimo tunel i v něm a porovnání viditelné IP. |
| **Únik přes Private DNS (DoT)** | Zaznamenat, zda je Private DNS zapnuté a kam vede (na testovacím telefonu je `dns.adguard.com`), a ověřit, že DoT jde přes tunel. |
| **MTU a fragmentace** | V tunelu poslat HTTPS s velkými hlavičkami nebo zvolit MTU podle odpovědi, aby se odhalil „black hole“ při velkých paketech. |
| **Latence a jitter na transport** | 10× malý dotaz přes tunel a zaznamenat medián a p95, ne jen jednu hodnotu. |
| **Spotřeba baterie a dat** | V MONITOR zaznamenat procento baterie na začátku a na konci a přenesené bajty (TrafficStats podle UID). |

## P3 – provoz a diagnostika

| Měření | Co přesně |
|---|---|
| **Relay běhy i v release** | Zavést release-bezpečné vynucení relay cesty, jen pro field test a jednorázově. Dnes se v release relay běhy přeskakují, protože `DebugPathOverride` je tam prázdná funkce. Je to architektonická změna, vyžaduje review. |
| **Stáří a podpis manifestu** | Do reportu přidat verzi manifestu, klíč, kterým je podepsaný, a jeho stáří. |
| **Porovnání času** | Rozdíl hodin telefonu proti času serveru, protože REALITY a TLS jsou citlivé na posun hodin. |
| **Automatické shrnutí pro testera** | Na konci jedna věta: „funguje: X, Y; blokováno: Z“. |

## Zásady pro všechna nová měření
- Do reportu nikdy neukládat vlastní IP zařízení ani credentialy (stejně jako u stávajícího `physicalReference`).
- Měřit jen síť a cíle, které už field test zná. Žádné nové externí služby bez review.
- Každé měření musí mít výsledek NOT_OBSERVED. Chybějící data nesmí vypadat jako PASS.
