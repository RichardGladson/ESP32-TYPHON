#include <Arduino.h>
#include <WiFi.h>
#include "config.h"

namespace WifiCore {

static constexpr uint8_t MAX_WIFI_NETWORKS = 40;

struct NetworkRecord {
    String ssid;
    int32_t rssi;
    uint8_t channel;
    wifi_auth_mode_t auth;
    bool hidden;
    uint8_t bssid[6];
};

static NetworkRecord networkCache[MAX_WIFI_NETWORKS];
static uint8_t cachedNetworkCount = 0;

static bool initialized = false;
static bool scanRunning = false;
static bool scanFailed = false;

static uint32_t scanStartedAt = 0;
static uint32_t lastCompletedScanAt = 0;

static uint32_t scanTimeoutMs = 15000;

static void clearNetworkRecord(NetworkRecord& record) {
    record.ssid = "";
    record.rssi = 0;
    record.channel = 0;
    record.auth = WIFI_AUTH_OPEN;
    record.hidden = false;
    memset(record.bssid, 0, sizeof(record.bssid));
}

static void clearCacheInternal() {
    for (uint8_t i = 0; i < MAX_WIFI_NETWORKS; ++i) {
        clearNetworkRecord(networkCache[i]);
    }

    cachedNetworkCount = 0;
}

static void copyBssid(uint8_t destination[6], const uint8_t source[6]) {
    if (source == nullptr) {
        memset(destination, 0, 6);
        return;
    }

    memcpy(destination, source, 6);
}

static void populateCache(int resultCount) {
    clearCacheInternal();

    if (resultCount <= 0) {
        return;
    }

    const int count = min(resultCount, static_cast<int>(MAX_WIFI_NETWORKS));

    for (int i = 0; i < count; ++i) {
        NetworkRecord& record = networkCache[i];

        record.ssid = WiFi.SSID(i);
        record.rssi = WiFi.RSSI(i);
        record.channel = WiFi.channel(i);
        record.auth = WiFi.encryptionType(i);
        record.hidden = record.ssid.isEmpty();

        const uint8_t* bssid = WiFi.BSSID(i);
        copyBssid(record.bssid, bssid);
    }

    cachedNetworkCount = static_cast<uint8_t>(count);
}

const char* authName(wifi_auth_mode_t auth) {
    switch (auth) {
        case WIFI_AUTH_OPEN:
            return "OPEN";

        case WIFI_AUTH_WEP:
            return "WEP";

        case WIFI_AUTH_WPA_PSK:
            return "WPA";

        case WIFI_AUTH_WPA2_PSK:
            return "WPA2";

        case WIFI_AUTH_WPA_WPA2_PSK:
            return "WPA/WPA2";

        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2-ENT";

        case WIFI_AUTH_WPA3_PSK:
            return "WPA3";

        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2/WPA3";

        default:
            return "OTHER";
    }
}

uint8_t rssiLevel(int32_t rssi) {
    if (rssi >= -50) {
        return 4;
    }

    if (rssi >= -60) {
        return 3;
    }

    if (rssi >= -70) {
        return 2;
    }

    return 1;
}

void begin() {
    if (initialized) {
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.disconnect(false, false);

    clearCacheInternal();

    initialized = true;
    scanRunning = false;
    scanFailed = false;
    scanStartedAt = 0;
    lastCompletedScanAt = 0;
}

void end() {
    if (!initialized) {
        return;
    }

    stopScan();

    WiFi.scanDelete();
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_OFF);

    clearCacheInternal();

    initialized = false;
}

bool isInitialized() {
    return initialized;
}

bool isScanning() {
    return scanRunning;
}

bool lastScanFailed() {
    return scanFailed;
}

uint32_t scanAgeMs() {
    if (lastCompletedScanAt == 0) {
        return UINT32_MAX;
    }

    return millis() - lastCompletedScanAt;
}

void setScanTimeout(uint32_t timeoutMs) {
    scanTimeoutMs = max<uint32_t>(1000, timeoutMs);
}

uint32_t getScanTimeout() {
    return scanTimeoutMs;
}

bool startScan(bool showHidden, bool passive) {
    if (!initialized) {
        begin();
    }

    if (scanRunning) {
        return false;
    }

    clearCacheInternal();
    scanFailed = false;

    WiFi.scanDelete();

    const int result = WiFi.scanNetworks(true, showHidden);

    if (result == WIFI_SCAN_FAILED) {
        scanFailed = true;
        return false;
    }

    if (!passive) {
        scanStartedAt = millis();
        scanRunning = true;
        return true;
    }

    scanStartedAt = millis();
    scanRunning = true;
    return true;
}

bool updateScan() {
    if (!scanRunning) {
        return false;
    }

    const int result = WiFi.scanComplete();

    if (result >= 0) {
        populateCache(result);

        WiFi.scanDelete();

        scanRunning = false;
        scanFailed = false;
        lastCompletedScanAt = millis();

        return true;
    }

    if (result == WIFI_SCAN_FAILED ||
        millis() - scanStartedAt >= scanTimeoutMs) {
        WiFi.scanDelete();

        scanRunning = false;
        scanFailed = true;
        lastCompletedScanAt = millis();

        clearCacheInternal();

        return true;
    }

    return false;
}

void stopScan() {
    if (!scanRunning) {
        return;
    }

    WiFi.scanDelete();

    scanRunning = false;
    scanFailed = false;

    clearCacheInternal();
}

uint8_t networkCount() {
    return cachedNetworkCount;
}

const NetworkRecord* network(uint8_t index) {
    if (index >= cachedNetworkCount) {
        return nullptr;
    }

    return &networkCache[index];
}

const NetworkRecord* networks() {
    return networkCache;
}

bool copyNetwork(uint8_t index, NetworkRecord& destination) {
    if (index >= cachedNetworkCount) {
        clearNetworkRecord(destination);
        return false;
    }

    destination = networkCache[index];
    return true;
}

int8_t strongestNetworkIndex() {
    if (cachedNetworkCount == 0) {
        return -1;
    }

    uint8_t strongestIndex = 0;

    for (uint8_t i = 1; i < cachedNetworkCount; ++i) {
        if (networkCache[i].rssi > networkCache[strongestIndex].rssi) {
            strongestIndex = i;
        }
    }

    return static_cast<int8_t>(strongestIndex);
}

int8_t findBySsid(const String& ssid) {
    for (uint8_t i = 0; i < cachedNetworkCount; ++i) {
        if (networkCache[i].ssid == ssid) {
            return static_cast<int8_t>(i);
        }
    }

    return -1;
}

int8_t findByBssid(const uint8_t bssid[6]) {
    if (bssid == nullptr) {
        return -1;
    }

    for (uint8_t i = 0; i < cachedNetworkCount; ++i) {
        if (memcmp(networkCache[i].bssid, bssid, 6) == 0) {
            return static_cast<int8_t>(i);
        }
    }

    return -1;
}

bool selectChannel(uint8_t channel) {
    if (channel < 1 || channel > 14) {
        return false;
    }

    esp_err_t result = esp_wifi_set_channel(
        channel,
        WIFI_SECOND_CHAN_NONE
    );

    return result == ESP_OK;
}

uint8_t currentChannel() {
    uint8_t primary = 0;
    wifi_second_chan_t secondary = WIFI_SECOND_CHAN_NONE;

    if (esp_wifi_get_channel(&primary, &secondary) != ESP_OK) {
        return 0;
    }

    return primary;
}

bool copyMacString(const uint8_t mac[6], char* output, size_t outputSize) {
    if (mac == nullptr || output == nullptr || outputSize < 18) {
        return false;
    }

    snprintf(
        output,
        outputSize,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    return true;
}

} // namespace WifiCore
