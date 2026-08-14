#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>
#include "config.h"

// ui.cpp interface
void uiInvalidate();
void uiClear(uint16_t color = BLACK);
void uiHeader(const char* title, uint16_t color = LBLUE);
void uiFooter(const char* text, uint16_t color = GRAY);
void uiText(int16_t x, int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiMenuRow(int16_t y, const char* text, bool selected, uint16_t accent = LBLUE);

// wifi_core.cpp interface
namespace WifiCore {

struct NetworkRecord {
    String ssid;
    int32_t rssi;
    uint8_t channel;
    wifi_auth_mode_t auth;
    bool hidden;
    uint8_t bssid[6];
};

void begin();
bool isScanning();
bool startScan(bool showHidden, bool passive);
bool updateScan();
void stopScan();
uint8_t networkCount();
const NetworkRecord* network(uint8_t index);
const char* authName(wifi_auth_mode_t auth);

} // namespace WifiCore

namespace WifiDeauthDetect {

static constexpr uint8_t MAX_TRACKED_NETWORKS = 40;
static constexpr uint8_t VISIBLE_ROWS = 5;
static constexpr uint32_t LISTEN_INTERVAL_MS = 5000;
static constexpr uint32_t RESCAN_INTERVAL_MS = 10000;
static constexpr uint32_t ALERT_WINDOW_MS = 1500;

struct NetworkState {
    String ssid;
    uint8_t bssid[6];
    uint8_t channel;
    int32_t rssi;
    uint32_t deauthCount;
    bool hidden;
};

static NetworkState networks[MAX_TRACKED_NETWORKS];
static uint8_t networkCountValue = 0;

static volatile uint32_t totalDeauthFrames = 0;
static volatile int16_t lastRssi = -127;
static volatile uint8_t lastChannel = 0;
static volatile int16_t lastNetworkIndex = -1;

static uint32_t lastDeauthAt = 0;
static uint32_t listenStartedAt = 0;
static uint32_t lastScanAt = 0;

static bool active = false;
static bool radioActive = false;
static bool scanRunning = false;
static bool screenDirty = true;
static bool detailsVisible = false;

static int16_t selectedIndex = 0;
static int16_t listOffset = 0;

static void markDirty() {
    screenDirty = true;
    uiInvalidate();
}

static void clearNetworkState(NetworkState& state) {
    state.ssid = "";
    memset(state.bssid, 0, sizeof(state.bssid));
    state.channel = 0;
    state.rssi = -127;
    state.deauthCount = 0;
    state.hidden = false;
}

static void clearNetworks() {
    for (uint8_t i = 0; i < MAX_TRACKED_NETWORKS; ++i) {
        clearNetworkState(networks[i]);
    }

    networkCountValue = 0;
    selectedIndex = 0;
    listOffset = 0;
}

static bool sameBssid(const uint8_t a[6], const uint8_t b[6]) {
    return a != nullptr && b != nullptr && memcmp(a, b, 6) == 0;
}

static int16_t findNetworkByBssid(const uint8_t bssid[6]) {
    if (bssid == nullptr) {
        return -1;
    }

    for (uint8_t i = 0; i < networkCountValue; ++i) {
        if (sameBssid(networks[i].bssid, bssid)) {
            return static_cast<int16_t>(i);
        }
    }

    return -1;
}

static void populateNetworks() {
    clearNetworks();

    const uint8_t count = WifiCore::networkCount();

    for (uint8_t i = 0; i < count && i < MAX_TRACKED_NETWORKS; ++i) {
        const WifiCore::NetworkRecord* source = WifiCore::network(i);

        if (source == nullptr) {
            continue;
        }

        networks[networkCountValue].ssid = source->ssid;
        memcpy(networks[networkCountValue].bssid, source->bssid, 6);
        networks[networkCountValue].channel = source->channel;
        networks[networkCountValue].rssi = source->rssi;
        networks[networkCountValue].deauthCount = 0;
        networks[networkCountValue].hidden = source->hidden;

        ++networkCountValue;
    }
}

static void stopPromiscuous() {
    if (!radioActive) {
        return;
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    radioActive = false;
}

static void deauthSnifferCallback(void* buffer, wifi_promiscuous_pkt_type_t type) {
    if (!active || buffer == nullptr || type != WIFI_PKT_MGMT) {
        return;
    }

    const wifi_promiscuous_pkt_t* packet =
        static_cast<const wifi_promiscuous_pkt_t*>(buffer);

    if (packet->rx_ctrl.sig_len < 24) {
        return;
    }

    const uint8_t* payload = packet->payload;

    // management frame subtype 0xC0 is deauthentication
    if ((payload[0] & 0xF0U) != 0xC0U) {
        return;
    }

    const uint8_t* sourceBssid = payload + 10;

    ++totalDeauthFrames;
    lastRssi = packet->rx_ctrl.rssi;
    lastChannel = packet->rx_ctrl.channel;
    lastDeauthAt = millis();

    const int16_t index = findNetworkByBssid(sourceBssid);

    if (index >= 0) {
        ++networks[index].deauthCount;
        lastNetworkIndex = index;
    } else {
        lastNetworkIndex = -1;
    }
}

static void startPromiscuous() {
    if (radioActive) {
        return;
    }

    WiFi.mode(WIFI_MODE_NULL);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&deauthSnifferCallback);
    esp_wifi_set_promiscuous(true);

    radioActive = true;
    listenStartedAt = millis();
}

static void performScan() {
    if (!active || scanRunning) {
        return;
    }

    stopPromiscuous();

    if (!WifiCore::startScan(true, true)) {
        startPromiscuous();
        return;
    }

    scanRunning = true;
}

static void finishScan() {
    const bool updated = WifiCore::updateScan();

    if (!updated) {
        return;
    }

    scanRunning = false;
    populateNetworks();
    lastScanAt = millis();

    startPromiscuous();
    clampSelection();

    markDirty();
}

static void updateScanner() {
    if (scanRunning) {
        finishScan();
        return;
    }

    if (millis() - lastScanAt >= RESCAN_INTERVAL_MS) {
        performScan();
        return;
    }

    if (radioActive &&
        millis() - listenStartedAt >= LISTEN_INTERVAL_MS) {
        listenStartedAt = millis();
        markDirty();
    }
}

static void clampSelection() {
    if (networkCountValue == 0) {
        selectedIndex = 0;
        listOffset = 0;
        return;
    }

    selectedIndex = constrain(
        selectedIndex,
        0,
        static_cast<int16_t>(networkCountValue - 1)
    );

    const int16_t maxOffset =
        max<int16_t>(0, static_cast<int16_t>(networkCountValue) - VISIBLE_ROWS);

    if (selectedIndex < listOffset) {
        listOffset = selectedIndex;
    }

    if (selectedIndex >= listOffset + VISIBLE_ROWS) {
        listOffset = selectedIndex - VISIBLE_ROWS + 1;
    }

    listOffset = constrain(listOffset, 0, maxOffset);
}

static uint16_t statusColor(uint32_t count) {
    if (count == 0) {
        return GRAY;
    }

    if (count <= 5) {
        return YELLOW;
    }

    return RED;
}

static void drawOverview() {
    uiClear(BLACK);
    uiHeader("DEAUTH DETECT", RED);

    char buffer[32];

    uint32_t total;
    int16_t rssi;
    uint8_t channel;

    noInterrupts();
    total = totalDeauthFrames;
    rssi = lastRssi;
    channel = lastChannel;
    interrupts();

    snprintf(
        buffer,
        sizeof(buffer),
        "TOTAL %lu",
        static_cast<unsigned long>(total)
    );
    uiText(4, 18, buffer, statusColor(total));

    snprintf(
        buffer,
        sizeof(buffer),
        "CH %u",
        static_cast<unsigned>(channel)
    );
    uiText(105, 18, buffer, YELLOW);

    if (networkCountValue == 0) {
        uiCenteredText(48, "NO AP DATA", GRAY);
        uiCenteredText(64, "SELECT = SCAN", WHITE);
        uiFooter("SELECT SCAN  BACK");
        return;
    }

    clampSelection();

    const uint8_t rows =
        min<uint8_t>(VISIBLE_ROWS, networkCountValue);

    for (uint8_t row = 0; row < rows; ++row) {
        const uint8_t index =
            static_cast<uint8_t>(listOffset + row);

        NetworkState& network = networks[index];

        String label = network.ssid;

        if (label.isEmpty()) {
            label = "<hidden>";
        }

        if (label.length() > 13) {
            label = label.substring(0, 12);
            label += "~";
        }

        const bool selected = index == selectedIndex;

        uiMenuRow(
            34 + row * 15,
            label.c_str(),
            selected,
            RED
        );

        snprintf(
            buffer,
            sizeof(buffer),
            "%lu",
            static_cast<unsigned long>(network.deauthCount)
        );

        uiText(
            116,
            37 + row * 15,
            buffer,
            selected ? BLACK : statusColor(network.deauthCount),
            selected ? RED : BLACK
        );

        snprintf(
            buffer,
            sizeof(buffer),
            "C%u",
            static_cast<unsigned>(network.channel)
        );

        uiText(
            138,
            37 + row * 15,
            buffer,
            selected ? BLACK : YELLOW,
            selected ? RED : BLACK
        );
    }

    uiFooter("SEL DETAIL  L/R  BACK");
}

static void drawDetails() {
    uiClear(BLACK);
    uiHeader("DEAUTH ALERT", RED);

    if (selectedIndex < 0 ||
        selectedIndex >= networkCountValue) {
        uiCenteredText(50, "NETWORK UNAVAILABLE", RED);
        uiFooter("RELEASE = BACK");
        return;
    }

    const NetworkState& network =
        networks[selectedIndex];

    String label = network.ssid;

    if (label.isEmpty()) {
        label = "<hidden>";
    }

    if (label.length() > 22) {
        label = label.substring(0, 21);
        label += "~";
    }

    uiText(4, 20, "SSID", GRAY);
    uiText(34, 20, label.c_str(), WHITE);

    char buffer[40];

    snprintf(
        buffer,
        sizeof(buffer),
        "%lu",
        static_cast<unsigned long>(network.deauthCount)
    );

    uiText(4, 38, "DEAUTH", GRAY);
    uiText(
        52,
        38,
        buffer,
        statusColor(network.deauthCount)
    );

    snprintf(
        buffer,
        sizeof(buffer),
        "%d dBm",
        static_cast<int>(network.rssi)
    );

    uiText(4, 54, "RSSI", GRAY);
    uiText(52, 54, buffer, LGREEN);

    snprintf(
        buffer,
        sizeof(buffer),
        "%u",
        static_cast<unsigned>(network.channel)
    );

    uiText(4, 70, "CHANNEL", GRAY);
    uiText(52, 70, buffer, YELLOW);

    snprintf(
        buffer,
        sizeof(buffer),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        network.bssid[0],
        network.bssid[1],
        network.bssid[2],
        network.bssid[3],
        network.bssid[4],
        network.bssid[5]
    );

    uiText(4, 86, "BSSID", GRAY);
    uiText(4, 101, buffer, WHITE);

    uiFooter("RELEASE = BACK");
}

void begin() {
    WifiCore::begin();

    active = false;
    radioActive = false;
    scanRunning = false;
    detailsVisible = false;
    screenDirty = true;

    clearNetworks();

    noInterrupts();
    totalDeauthFrames = 0;
    lastRssi = -127;
    lastChannel = 0;
    lastNetworkIndex = -1;
    interrupts();

    lastDeauthAt = 0;
    listenStartedAt = 0;
    lastScanAt = 0;
}

void enter() {
    active = true;
    detailsVisible = false;

    clearNetworks();

    noInterrupts();
    totalDeauthFrames = 0;
    lastRssi = -127;
    lastChannel = 0;
    lastNetworkIndex = -1;
    interrupts();

    lastDeauthAt = 0;
    lastScanAt = millis() - RESCAN_INTERVAL_MS;

    performScan();
    markDirty();
}

void exit() {
    active = false;
    detailsVisible = false;
    scanRunning = false;

    stopPromiscuous();
    WifiCore::stopScan();

    screenDirty = true;
}

void update() {
    if (!active) {
        return;
    }

    updateScanner();

    if (lastDeauthAt != 0 &&
        millis() - lastDeauthAt < ALERT_WINDOW_MS) {
        markDirty();
    }
}

void handleInput(uint8_t event) {
    if (!active) {
        return;
    }

    switch (event) {
        case 1: // up
            if (!detailsVisible && selectedIndex > 0) {
                --selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case 2: // down
            if (!detailsVisible &&
                selectedIndex + 1 < networkCountValue) {
                ++selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case 3: // left
        case 9: // gesture left
            if (detailsVisible) {
                detailsVisible = false;
                markDirty();
            } else {
                exit();
            }
            break;

        case 4: // right
            if (!detailsVisible && !scanRunning) {
                performScan();
            }
            break;

        case 5: // select
            if (detailsVisible) {
                detailsVisible = false;
            } else if (networkCountValue > 0) {
                detailsVisible = true;
            } else if (!scanRunning) {
                performScan();
            }

            markDirty();
            break;

        case 6: // back
            exit();
            break;

        default:
            break;
    }
}

void render() {
    if (!active) {
        return;
    }

    if (detailsVisible) {
        drawDetails();
    } else {
        drawOverview();
    }

    screenDirty = false;
}

bool needsRedraw() {
    return screenDirty;
}

uint32_t totalDetected() {
    uint32_t value;

    noInterrupts();
    value = totalDeauthFrames;
    interrupts();

    return value;
}

int16_t lastRssi() {
    int16_t value;

    noInterrupts();
    value = WifiDeauthDetect::lastRssi;
    interrupts();

    return value;
}

uint8_t lastChannel() {
    uint8_t value;

    noInterrupts();
    value = WifiDeauthDetect::lastChannel;
    interrupts();

    return value;
}

} // namespace WifiDeauthDetect

void wifiDeauthDetectBegin() {
    WifiDeauthDetect::begin();
}

void wifiDeauthDetectEnter() {
    WifiDeauthDetect::enter();
}

void wifiDeauthDetectExit() {
    WifiDeauthDetect::exit();
}

void wifiDeauthDetectUpdate() {
    WifiDeauthDetect::update();
}

void wifiDeauthDetectHandleInput(uint8_t event) {
    WifiDeauthDetect::handleInput(event);
}

void wifiDeauthDetectRender() {
    WifiDeauthDetect::render();
}

bool wifiDeauthDetectNeedsRedraw() {
    return WifiDeauthDetect::needsRedraw();
}

uint32_t wifiDeauthDetectTotal() {
    return WifiDeauthDetect::totalDetected();
}

int16_t wifiDeauthDetectLastRssi() {
    return WifiDeauthDetect::lastRssi();
}

uint8_t wifiDeauthDetectLastChannel() {
    return WifiDeauthDetect::lastChannel();
}
