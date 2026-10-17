# ioBroker.spc-edp

ioBroker-Adapter für **Vanderbilt SPC** Einbruchmeldezentralen über das native
**EDP-Protokoll (Version 2)**. Kein Gateway nötig: Die Zentrale verbindet sich
direkt per TCP mit ioBroker.

- Bereiche: Scharfschaltzustand, Alarm ausgelöst
- Zonen: offen/geschlossen, Eingangszustand (inkl. Sabotage/Störung), Typ, Bereich
- Zonenereignisse kommen **sofort** (Push), zusätzlich regelmäßiges Abfragen
- Optional: Scharf-/Unscharfschalten aus ioBroker
- Optional: AES-Verschlüsselung (EDP-Schlüssel)

Die Protokollimplementierung basiert auf [spcedp](https://github.com/imduffy15/spcedp)
von Ian Duffy (MIT), getestet dort mit einer SPC4300 / Firmware 3.15.0.

## Einrichtung an der Zentrale

Im Webinterface der SPC (Errichter-/Engineer-Modus): **Kommunikation → Berichte → EDP**

**1. Einstellungen (EDP global aktivieren)**

| Einstellung | Wert |
| --- | --- |
| Aktivieren | ✔ |
| EDP Zentralen-ID | bestehende ID behalten, z. B. `1000` |
| Zentralen-Port | `50000` |
| Paketgrößenlimit | `1440` |
| Ereignis-Timeout / Wiederholungen | `10` s / `10` |

**2. Empfänger hinzufügen**

| Einstellung | Wert |
| --- | --- |
| Empfänger-ID | wie im Adapter, z. B. `1001` |
| Protokollversion | Version 2 |
| Befehle aktivieren / Netzwerk aktivieren | ✔ |
| Netzwerkprotokoll | TCP/IP |
| Empfänger IP-Adresse | IP des ioBroker-Servers |
| Empfänger IP-Port | Port im Adapter, Standard `50000` |
| Immer verbunden / Primärer Empfänger | ✔ |
| Abfrageintervall (Polling) | `10` s |
| Verschlüsselung | wie im Adapter (gleicher 32-stelliger Hex-Schlüssel) |

**3. Ereignisfilter:** *Zonenstatus*, *Scharfschaltungen*, *Alarme* und
*Bestätigte Alarme* aktivieren und die Bereiche auswählen.

Danach den Engineer-Modus verlassen. Im Engineer-Modus lehnt die Zentrale
Schaltbefehle ab.

Die Menübezeichnungen können je nach Firmware/Sprache leicht abweichen. Siehe auch
[Vanderbilt EDP Setup](https://doc.vanderbiltindustries.com/docs/Intrusion/SPC/SPCPanel/v_3.11/InstallAndConfig_OLH/EN/Content/Topics/EDP_Setup.htm).

## Datenpunkte

| Datenpunkt | Bedeutung |
| --- | --- |
| `info.connection` | Zentrale verbunden |
| `info.panelType`, `info.firmware`, `info.serial`, `info.panelId` | Zentralen-Infos |
| `info.lastCommandResult` | Ergebnis des letzten Schaltbefehls |
| `areas.<id>.mode` | 0 = unscharf, 1 = teilscharf A, 2 = teilscharf B, 3 = vollscharf |
| `areas.<id>.armed` | scharf (beliebiger Modus) |
| `areas.<id>.triggered` | Alarm ausgelöst (wird beim Unscharfschalten zurückgesetzt) |
| `areas.<id>.setMode` | **schreibbar** (nur wenn erlaubt): 0/1/2/3 wie `mode` |
| `zones.<id>.open` | Zone offen (`null` bei Störung/Sabotage) |
| `zones.<id>.input` | 0 zu, 1 offen, 2 Kurzschluss, 3 Unterbrechung, 4 maskiert, 5 DC-Substitution, 6 Sensor fehlt, 7 offline |
| `zones.<id>.type`, `zones.<id>.area` | Zonentyp, zugehöriger Bereich |
| `events.*` | letztes SIA-Ereignis (Code, Adresse, Text, Zeit, JSON) |

## Sicherheit

- EDP hat **keine Nachrichtenauthentifizierung**, auch nicht verschlüsselt (AES-128-ECB).
  Nur in einem vertrauenswürdigen Netz (z. B. eigenes VLAN) betreiben und den Port
  nicht ins Internet freigeben.
- Das Scharf-/Unscharfschalten ist standardmäßig **deaktiviert**. Wenn du es aktivierst,
  kann jeder mit Schreibrechten in ioBroker (Skripte, VIS, Apps) die Anlage unscharf schalten.
- Bei VdS-/versicherungsrelevanten Anlagen die Änderung mit dem Errichter abstimmen.

## Installation (lokal, ohne npm-Registry)

```bash
# Paket auf den ioBroker-Server kopieren, dann:
cd /opt/iobroker
npm install /pfad/zu/iobroker.spc-edp-0.1.0.tgz
iobroker upload spc-edp
iobroker add spc-edp
```

Alternativ das Projekt in ein GitHub-Repo legen und im Admin über
*Adapter → Installieren aus eigener URL* installieren.

## Entwicklung

```bash
npm install
npm test
```

Die Tests prüfen Prüfsumme und Kodierung gegen echte, mitgeschnittene SPC-Frames
und lassen den Adapter gegen eine simulierte Zentrale laufen (unverschlüsselt und verschlüsselt).

## Lizenz

MIT
