### **Do not use this Project for any illegal purpose.**

# **🚫Do not be a [_skid_](https://www.google.com/search?q=skid+meaning+in+programming+slang).**

# ESP32 TYPHON

ESP32-based Wi‑Fi and Bluetooth research toolkit with a small on-device UI (ST7735 + joystick) and a full Soft‑AP web control panel.

This project is intended for **education**, **lab practice**, and **authorized security research** only. You are responsible for how you use it.

> **Legal / ethics notice**  
> Read **[DISCLAIMER.md](DISCLAIMER.md)** before building or running anything.  
> Only operate against networks and devices you own or have explicit permission to test.

---

## What it is

**ESP32 TYPHON** is a PlatformIO / Arduino firmware port focused on:

- **ESP32-WROOM** (classic ESP32)
- **1.8″ ST7735** display (160×128)
- **HW-504** analog joystick
- Local menu UI on the screen
- **Soft‑AP web UI** for phone/laptop control

It exposes a set of 2.4 GHz Wi‑Fi and BLE utilities commonly used in classroom demos and defensive labs (scanning, monitoring, frame experiments, BLE advertising demos).

---

## Hardware

| Part | Notes |
|------|--------|
| ESP32 DevKit (WROOM) | GPIO0 = BOOT, GPIO2 = status LED (typical) |
| ST7735 1.8″ (Black Tab) | 160×128 |
| Joystick (HW-504) | VRX / VRY / SW |

### Default pin map

| Function | GPIO |
|----------|------|
| TFT SCK | 18 |
| TFT MOSI | 23 |
| TFT CS | 5 |
| TFT DC | 16 |
| TFT RST | 17 |
| Joystick VRX | 34 |
| Joystick VRY | 35 |
| Joystick SW | 32 |
| BOOT button | 0 |
| Status LED | 2 |

Pins are set in `platformio.ini` (TFT_eSPI) and `include/BoardConfig.h`.

---

## Features

### On-device (joystick UI)

**Wi‑Fi**

- Scanner  
- Packet monitor  
- Beacon spammer (built-in funny list / clone scanned SSIDs)  
- Deauth (lab/demo)  
- Deauth detector  
- Probe flood  
- Captive portal demo  

**Bluetooth**

- BLE scanner / sniffer  
- BLE name spoofer  
- Sour Apple–style Continuity demos  
- BLE jammer-style noise advertising  
- AirTag-style Find My advertising demo  

### Soft‑AP web UI

Hold **BOOT (GPIO0) for ~2 seconds** to enter or leave web mode.

| Setting | Value |
|---------|--------|
| SSID | `ESP32-1` |
| Password | `rgisking` |
| URL | `http://192.168.4.1` |

Web UI includes:

- Hierarchical Wi‑Fi / Bluetooth menus  
- Live status: **Idle / Scanning / Attacking / Defending**  
- Chip temperature  
- Toggle start/stop for tools  
- Wi‑Fi list with encryption + RSSI colouring  
- **Custom beacon SSID list (1–10 names)** — web only  
- Stop-all controls  

Display shows connection info while web mode is active; the blue LED (GPIO2) is on.

Captive portal is **not** offered in the web UI (radio/AP conflict).

---

## Controls (local UI)

| Input | Action |
|-------|--------|
| Up / Down | Navigate |
| Short press | Select / Start / Stop |
| Long press | Back |

---

## Build & flash

### Requirements

- [PlatformIO](https://platformio.org/) (CLI or VS Code / Cursor extension)
- USB data cable

### Build

```bash
cd ESP32-TYPHON
pio run
```

### Upload

```bash
pio run -t upload
```

### Serial monitor

```bash
pio device monitor -b 115200
```

### Notes

- Linker flag `-Wl,--wrap=ieee80211_raw_frame_sanity_check` is required for raw 802.11 TX on many Arduino-ESP32 cores.
- TFT_eSPI may warn that `TOUCH_CS` is undefined; that is expected if you have no touch panel.
- After changing core/platform versions, do a clean build: `pio run -t clean && pio run`.

---

## Project layout

```
ESP32-TYPHON/
├── platformio.ini
├── README.md
├── DISCLAIMER.md
├── include/
│   ├── BoardConfig.h
│   ├── Joystick.h
│   ├── Theme.h
│   └── UI.h
└── src/
    ├── main.cpp
    ├── Joystick.cpp
    ├── Theme.cpp
    └── UI.cpp          # screens + Wi-Fi/BLE tools + web UI
```

Most tool logic and the embedded web app live in `src/UI.cpp`.

---

## Beacon spammer (reference)

- **Built-in funny SSID list:** `beaconSSIDs[]` in `src/UI.cpp`  
- **Transmit loop:** `beaconUpdate()` in `src/UI.cpp` (~25 ms between bursts, 2 frames per burst)  
- **Modes:**  
  - `0` — funny list  
  - `1` — clone last Wi‑Fi scan  
  - `2` — custom list from web UI (1–10 SSIDs)

---

## Safety & responsibility

This firmware can interfere with nearby wireless networks and devices.

- Do **not** use it in public spaces, airports, schools, or against third-party networks.  
- Do **not** use it to harass, disrupt, or gain unauthorized access.  
- Prefer a shielded lab, Faraday bag, or isolated test AP.  
- You accept full responsibility for compliance with local law.

Full text: **[DISCLAIMER.md](DISCLAIMER.md)**

---

## Credits

Inspired by educational ESP32 wireless tooling in the community (including projects such as ESP32-DIV–style ports). This tree is a ST7735 + joystick + Soft‑AP web control rewrite for lab use.

---

## License

Use, modify, and share for learning and authorized research. The authors and contributors provide **no warranty** and accept **no liability** for misuse or damage. See [DISCLAIMER.md](DISCLAIMER.md).

---

## **Do not use this Project for any illegal purpose.**

# **🚫Do not be a [_skid_](https://www.google.com/search?q=skid+meaning+in+programming+slang).**
