# ESP32 TYPHON

**ESP32-based penetration testing tool** for authorized Wi‑Fi (802.11) and Bluetooth Low Energy (BLE) security assessment on the 2.4 GHz band.

### **Do not use this Project for any illegal purpose.**

# **🚫Do not be a [_skid_](https://www.google.com/search?q=skid+meaning+in+programming+slang).**

Hardware: ESP32 + ST7735 (128×160) + joystick. Control via **handheld UI** or **Soft-AP web UI**.

---

## Controls

| Mode | How |
|------|-----|
| **Handheld** | Joystick menus; max RF when Soft-AP is off / War Mode on |
| **Web UI** | Hold **BOOT 2 seconds** → Soft-AP `ESP32-TYPHON` / password `rgisking` → open `http://192.168.4.1` · API key same as password |
| **Exit web** | Hold BOOT 2s again |

**Web-safe mode (default while Soft-AP is up):** Wi‑Fi TX stays on channel 1 so the phone stays connected. Off-channel Wi‑Fi attacks and promiscuous tools need **handheld**. BLE tools remain available in web mode.

---

## Wi‑Fi / 802.11

1. **Wi‑Fi Scanner** — nearby APs, SSID, BSSID, channel, RSSI, encryption  
2. **Packet Monitor** — management / data / control / deauth counters  
3. **Beacon Spammer** — funny SSIDs, clone scanned SSIDs, web-only custom SSID list (1–10)  
4. **Deauth** — single AP or all; broadcast + unicast to sniffed clients; reason rotation  
5. **Client Sniffer** — STA MACs on a selected AP (feeds deauth)  
6. **Deauth Detector** — detects deauth activity  
7. **Probe Flood** — directed probe stress-test against a selected AP  
8. **Karma** — learn probe SSIDs; beacon + probe-response  
9. **Airtime Flood** — RTS / CTS / Auth / mix against a selected AP  
10. **EAPOL / PMKID capture** — promiscuous capture + SPIFFS log (handheld)  
11. **Captive Portal** — lab portal on Soft-AP (handheld-oriented)  
12. **War Mode** — max radio path; no Soft-AP (handheld)  

---

## Bluetooth Low Energy (BLE)

1. **BLE Scanner** — nearby advertisers  
2. **BLE Sniffer** — device list; handheld highlight  
3. **BLE Spoofer** — Apple / Samsung / Google / name templates; **clone selected device** (handheld)  
4. **Sour Apple** — Continuity model / action advertising (selectable)  
5. **BLE ADV Flood** — multi-template advertising noise  
6. **AirTag Detector** — Find My / AirTag-style ADV detection  
7. **AirTag Spoofer** — clone selected or rotate detected payloads  

---

## System

- CPU **240 MHz**  
- Dual-core workers for active Wi‑Fi TX / BLE ADV  
- Radio ownership mutex (scan / Wi‑Fi TX / BLE scan / BLE ADV)  
- Max Wi‑Fi / BLE TX helpers  
- Chip temperature, heap, war/webSafe, radio owner in web status  
- **Stop All Tools** (handheld main menu + web)  
- Web API auth (`X-TYPHON-KEY` / `key=rgisking`)  
- Slim `/api/status` + on-demand `/api/wifi`, `/api/ble`, `/api/clients`, `/api/air`  

---

## Build

- PlatformIO · board `esp32dev`  
- TFT_eSPI configured for your ST7735 wiring  
- Linker wrap for raw 802.11 TX as required by the project `platformio.ini`  
- Flash `src/` + `include/` as shipped  

---

## Limits

- 2.4 GHz only  
- One radio: Soft-AP stability and max off-channel TX are opposing goals  
- ADV flood / airtime flood are **not** spectrum jammers  
- PMF, modern OS mitigations, and range still apply  
- Use only on networks and devices you own or are explicitly authorized to test  

---

## Disclaimer

See `DISCLAIMER.md`. Unauthorized access to computer networks or interference with communications may be illegal. You are responsible for lawful use.

### **Do not use this Project for any illegal purpose.**

## **🚫Do not be a [_skid_](https://www.google.com/search?q=skid+meaning+in+programming+slang).**
