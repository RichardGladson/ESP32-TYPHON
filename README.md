# ESP32-TYPHON

Handheld **Wi‑Fi and Bluetooth research toolkit** for the classic **ESP32-WROOM**, with a 1.8″ ST7735 TFT and analog joystick. Designed for lab use on networks and devices you own or have explicit permission to test.

> **Educational / authorized testing only.** Unauthorized interference with wireless networks or devices is illegal in most jurisdictions. The authors assume no liability for misuse.

---

## Hardware

| Component | Details |
|-----------|---------|
| MCU | ESP32-WROOM-32 (classic dual-core, shared 2.4 GHz radio) |
| Display | ST7735 Blacktab **160×128**, landscape (rotation 3) |
| Input | HW-504 joystick — VRX **GPIO34**, VRY **GPIO35**, SW **GPIO32** |
| Status | Onboard LED **GPIO2**, BOOT **GPIO0** |
| SPI TFT | MOSI **23**, SCLK **18**, CS **5**, DC **16**, RST **17** |

CPU is locked at **240 MHz**. Flash layout uses **`huge_app.csv`** so Bluedroid + TFT + tools fit.

---

## Quick start

### Requirements

- [PlatformIO](https://platformio.org/) (VS Code / CLI)
- USB data cable for the DevKit

### Build & flash

```bash
pio run -t upload
pio device monitor -b 115200
```

Project defaults (`platformio.ini`):

- Board: `esp32dev`
- Framework: Arduino
- Partition: `huge_app.csv`
- Library: `bodmer/TFT_eSPI`
- Linker wrap: `ieee80211_raw_frame_sanity_check` (raw 802.11 TX)

### First boot

1. Power the board; TFT shows the main menu.
2. Navigate with the joystick (up/down, short press = select, long press / back as mapped).
3. Prefer **handheld** mode for off-channel Wi‑Fi tools. Soft-AP **web mode** pins TX/RX to channel 1 for UI stability.

---

## Feature overview

```
Main
├── Wi-Fi Tools
│   ├── Wi-Fi Scanner
│   ├── Packet Monitor
│   ├── Beacon Spammer
│   ├── Deauth Attack
│   ├── Client Sniffer
│   ├── Deauth Detector
│   ├── Probe Flood
│   ├── Karma
│   ├── WiFi Jammer (flood modes)
│   ├── EAPOL Capture
│   ├── Captive Portal
│   └── War Mode
├── Bluetooth Tools
│   ├── BLE Scanner
│   ├── BLE Sniffer
│   ├── BLE Spoofer
│   ├── Sour Apple
│   │   ├── Continuity alerts
│   │   └── Device-style ads
│   ├── BLE Jammer
│   └── AirTag Tools (detect / spoof)
└── Stop All Tools
```

---

## Wi‑Fi tools

### Wi‑Fi Scanner
- Full 2.4 GHz scan into a shared AP list (`wifiNets[]`).
- Other tools reuse this list (same source as the scanner).

### Packet Monitor
- Promiscuous RX on a chosen channel (optional hop).
- Live activity on the TFT footer / UI.

### Beacon Spammer
- Synthetic or clone-style beacons for channel noise / lab demos.
- Modes include pool fill from scanned SSIDs (safe SSID string copy).

### Deauth Attack
- Single-AP or **attack-all** (cycles known APs).
- Spec-sized frames (**26 bytes**).
- Broadcast deauth/disassoc + unicast to **sniffed** clients.
- STA→AP direction uses **real client MACs** only (not random).
- Cross-core safe snapshots (no mid-TX use of a stopped target index).
- Does **not** call a full rescan mid-attack (avoids self-abort).

### Client Sniffer
- Nightshade-style association of stations to an AP.
- Queue drained under a mutex so deauth and UI do not corrupt the list.

### Deauth Detector
- Listens for deauthentication frames (defensive / awareness).

### Probe Flood
- Directed probe-request stress toward a selected AP.

### Karma
- Learns SSIDs from probe requests; answers with beacons / probe responses.
- ISR → main handoff protected with `karmaMux`.

### WiFi Jammer (flood)
- Multiple flood modes (RTS/CTS/auth-style noise).
- **CTS** RA set to the **AP BSSID** (correct NAV target).
- Bounds checks use live `wifiCount`.

### EAPOL Capture
- Promiscuous capture of EAPOL (`0x888E`).
- Optional PMKID flag only via structured **RSN IE** heuristics (no “random non-zero bytes” false positives).
- Appends hits to SPIFFS `/eapol.log`.

### Captive Portal
- Soft-AP + DNS sinkhole + simple login page.
- Credentials buffered (64 chars) and appended to SPIFFS `/captive.log`.
- Cleared from RAM on portal stop.

### War Mode
- Hands more of the radio to attack paths (minimal Soft-AP for `80211_tx` when needed).
- Avoids trivial hidden-SSID fingerprints for the auxiliary AP.

---

## Bluetooth tools

Stack: **Bluedroid** via Arduino `BLEDevice` on classic WROOM (not NimBLE / C3-only paths).

### BLE Scanner
- Active scan, duplicate filter off.
- GAP results queued; parsing on the main path (`bleRxDrain`).
- ADV + scan-response length considered where available.

### BLE Sniffer
- Focused advertising observation for research logging.

### BLE Spoofer
- Clone / name-based advertising from scan results.

### Sour Apple
Category menu:

| Branch | Behavior |
|--------|----------|
| **Continuity alerts** | RapierXbox-style Continuity *Nearby Action* spam (popup-style research packets). Select action type (Setup New Phone, AppleTV Connecting, etc.). |
| **Device-style ads** | Complete Local Name advertisements (AirPods, Watch, iPhone, …) for scanner visibility. **Clone BLE scan…** opens the BLE Spoofer. |

Not a full Apple accessory stack — Continuity and name ads are distinct research TX paths.

### BLE Jammer
- Dense advertising noise for lab coexistence tests.

### AirTag Tools
- **Detect:** Apple Offline Finding–style ADV classifiers; track by payload fingerprint as well as MAC (rotation-aware).
- **Spoof:** advertisement **replay** research (RANDOM addr + captured payload, nyanBOX-aligned timing/power).  
  Not certified AirTag hardware or guaranteed Find My cloud recognition.

---

## System architecture (current)

### Shared 2.4 GHz radio
Classic ESP32 has **one** RF path for Wi‑Fi and BLE. Ownership is global:

- Wi‑Fi scan/TX and BLE scan/ADV are **mutually exclusive**.
- Cross-domain acquire force-idles the other subsystem before claim.
- Dual-core workers **skip** work while the other domain owns the radio.

### Dual-core workers
- Core 0: Wi‑Fi TX / attack loop  
- Core 1: BLE ADV workers  
- `wifiAttackLive` / `bleAttackLive` actually pause the loops when cleared.

### UI
- Dirty-flag redraw; activity footer (temperature / attacking / scanning / idle style status).
- Soft-AP **web UI** optional (HTTP only — no TLS on Soft-AP in this build).

### Storage
- SPIFFS: `/eapol.log`, `/captive.log`

---

## Web UI notes

- Soft-AP web mode is **HTTP plaintext**.
- While web mode is active, many Wi‑Fi attacks stay on **channel 1** so the UI remains reachable.
- Treat the Soft-AP network as untrusted: anyone associated can hit the API if they know the key.

---

## Project layout

```
ESP32-TYPHON/
├── platformio.ini
├── include/
│   ├── BoardConfig.h    # pins, colors, feature flags
│   ├── Joystick.h
│   ├── Theme.h
│   └── UI.h             # screen enum
└── src/
    ├── main.cpp
    ├── ui.cpp           # tools + UI (monolith)
    ├── Joystick.cpp
    └── Theme.cpp
```

---

## Configuration tips

| Goal | Action |
|------|--------|
| Fit Bluedroid binary | Keep `board_build.partitions = huge_app.csv` |
| Off-channel deauth / sniff | Use handheld, not web-safe Soft-AP mode |
| Deauth unicast clients | Run **Client Sniffer** on that AP first |
| BLE scan empty | Stop Wi‑Fi tools; let the radio arbiter give BLE exclusive access |
| Captive / EAPOL logs | Read SPIFFS after session (`/captive.log`, `/eapol.log`) |

---

## Limitations

- **No HTTPS** Soft-AP; credentials and API traffic are plaintext on air.
- **No UWB** — AirTag precision ranging is impossible on ESP32.
- AirTag “spoof” is **ADV replay**, not a full Find My identity.
- Sour Apple Continuity does **not** impersonate a specific paired device you scanned.
- 802.11w (PMF) APs may ignore unauthenticated management frames by design.
- ESP32 radio is half-duplex shared Wi‑Fi/BLE — concurrent use is arbitrated, not parallel.

---

## Credits & lineage

- Original TYPHON concept: [RichardGladson/ESP32-TYPHON](https://github.com/RichardGladson/ESP32-TYPHON)
- Client sniffer logic influenced by [ESP32-Nightshade](https://github.com/RichardGladson/ESP32-Nightshade)
- Sour Apple Continuity packet logic: [RapierXbox/ESP32-Sour-Apple](https://github.com/RapierXbox/ESP32-Sour-Apple)
- AirTag-style timing / clone patterns referenced from community tools (e.g. nyanBOX-style ADV cycles)
- BLE stack patterns aligned with Espressif Bluedroid examples

---

## License / ethics

Use only on systems and spectrum you are authorized to test. Respect local law, venue policies, and human privacy. This firmware is a research instrument, not a product for disruption of third-party networks.
