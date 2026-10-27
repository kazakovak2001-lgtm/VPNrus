# Nova VPN 0.1.0-beta1 — interní beta

- Revize: `3d6908b` (merge PR #192)
- APK: `NovaVPN-0.1.0-beta1-internal.apk`, versionCode 2, minSdk 26, targetSdk 35
- SHA-256 APK: `1bfa876d173e9d9aa8b1d1c3a4cd8129157e6c782adc988189fd73c81be19439`
- SHA-256 podpisového certifikátu: `c47fb35a215a2daf2e4b08b082ec5396b7d881f1db50191f46338fb81f02bca9`

## Instalace
1. Pokud máš starší testovací verzi (B37 nebo debug build), **nejdřív ji odinstaluj**. Má jiný podpis, takže aktualizace nepůjde. Odinstalací se smažou lokální data a aktivace.
2. Nainstaluj APK a zkontroluj, že jeho SHA-256 odpovídá hodnotě výše.
3. Aktivuj aplikaci pomocí credentialu, který dostaneš (QR kód, soubor nebo ruční vložení).
4. Doporučení: v Androidu otevři Nastavení → VPN → Nova VPN a zapni „Always-on VPN“ a „Block connections without VPN“.

## Ověřeno (2026-10-27)
- Build a 2888 unit testů (0 selhání)
- Podpis release klíčem (schéma v2)
- Čistá instalace na Android 14, připojení přes Frankfurt
- Bez úniku IPv4, IPv6 a DNS
- Při vypnutí Wi-Fi (jeden test) nešel žádný provoz mimo tunel.

## Známá omezení
- V jednom testu trvala obnova tunelu po přepnutí z Wi-Fi na mobilní data zhruba 130 s. Po tu dobu není internet.
- **Na ruských mobilních sítích zatím netestováno.**
- Pád aplikace bez zapnutého Always-on VPN nebyl testován. Android v takovém případě pustí provoz mimo VPN.
