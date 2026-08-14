#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "config.h"

// ui.cpp interface
void uiInvalidate();
void uiClear(uint16_t color = BLACK);
void uiHeader(const char* title, uint16_t color = LBLUE);
void uiFooter(const char* text, uint16_t color = GRAY);
void uiText(int16_t x, int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiMenuRow(int16_t y, const char* text, bool selected, uint16_t accent = LBLUE);
void uiScrollbar(int16_t x, int16_t y, int16_t height, uint16_t totalItems, uint16_t visibleItems, uint16_t selectedItem);

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
uint8_t rssiLevel(int32_t rssi);

} // namespace WifiCore

namespace WifiBeacon {

static constexpr uint8_t VISIBLE_BEACONS = 6;
static constexpr uint8_t MAX_CHANNEL = 13;
static constexpr uint32_t REFRESH_INTERVAL_MS = 3000;

static bool active = false;
static bool details = false;
static bool screenDirty = true;

static int16_t selectedIndex = 0;
static int16_t listOffset = 0;

static uint32_t lastRefresh = 0;
static uint32_t beaconCount = 0;

struct BeaconStats {
    uint32_t observedNetworks;
    uint32_t hiddenNetworks;
    int32_t strongestRssi;
    uint32_t channelUse[MAX_CHANNEL + 1];
};

static BeaconStats stats = {};

static void markDirty() {
    screenDirty = true;
    uiInvalidate();
}

static void resetStats() {
    stats.observedNetworks = 0;
    stats.hiddenNetworks = 0;
    stats.strongestRssi = -127;

    for (uint8_t i = 0; i <= MAX_CHANNEL; ++i) {
        stats.channelUse[i] = 0;
    }
}

static void updateStats() {
    resetStats();

    const uint8_t count = WifiCore::networkCount();

    for (uint8_t i = 0; i < count; ++i) {
        const WifiCore::NetworkRecord* network = WifiCore::network(i);

        if (network == nullptr) {
            continue;
        }

        ++stats.observedNetworks;

        if (network->hidden) {
            ++stats.hiddenNetworks;
        }

        if (network->rssi > stats.strongestRssi) {
            stats.strongestRssi = network->rssi;
        }

        if (network->channel >= 1 && network->channel <= MAX_CHANNEL) {
            ++stats.channelUse[network->channel];
        }
    }

    beaconCount = stats.observedNetworks;
}

static void requestScan() {
    if (WifiCore::isScanning()) {
        return;
    }

    WifiCore::startScan(true, true);
    lastRefresh = millis();

    markDirty();
}

static void updateScan() {
    if (WifiCore::isScanning()) {
        if (WifiCore::updateScan()) {
            updateStats();
            markDirty();
        }

        return;
    }

    if (millis() - lastRefresh >= REFRESH_INTERVAL_MS) {
        requestScan();
    }
}

static void clampSelection() {
    const int16_t count = WifiCore::networkCount();

    if (count <= 0) {
        selectedIndex = 0;
        listOffset = 0;
        return;
    }

    selectedIndex = constrain(selectedIndex, 0, count - 1);

    const int16_t maxOffset = max<int16_t>(0, count - VISIBLE_BEACONS);

    if (selectedIndex < listOffset) {
        listOffset = selectedIndex;
    }

    if (selectedIndex >= listOffset + VISIBLE_BEACONS) {
        listOffset = selectedIndex - VISIBLE_BEACONS + 1;
    }

    listOffset = constrain(listOffset, 0, maxOffset);
}

static uint16_t signalColor(int32_t rssi) {
    if (rssi >= -55) {
        return GREEN;
    }

    if (rssi >= -70) {
        return YELLOW;
    }

    return RED;
}

static void drawBeaconList() {
    const uint8_t count = WifiCore::networkCount();

    if (count == 0) {
        if (WifiCore::isScanning()) {
            uiCenteredText(46, "LISTENING...", YELLOW);
            uiCenteredText(62, "BEACONS", GRAY);
        } else {
            uiCenteredText(46, "NO BEACONS", GRAY);
            uiCenteredText(62, "SELECT = SCAN", WHITE);
        }

        return;
    }

    clampSelection();

    const uint8_t rows = min<uint8_t>(VISIBLE_BEACONS, count);

    for (uint8_t row = 0; row < rows; ++row) {
        const uint8_t index = static_cast<uint8_t>(listOffset + row);
        const WifiCore::NetworkRecord* network = WifiCore::network(index);

        if (network == nullptr) {
            continue;
        }

        String name = network->ssid;

        if (name.isEmpty()) {
            name = "<hidden>";
        }

        if (name.length() > 16) {
            name = name.substring(0, 15);
            name += "~";
        }

        const int16_t y = 18 + row * 15;

        uiMenuRow(
            y,
            name.c_str(),
            index == selectedIndex,
            AQUA
        );

        char channelText[8];
        snprintf(
            channelText,
            sizeof(channelText),
            "C%u",
            static_cast<unsigned>(network->channel)
        );

        uiText(
            112,
            y + 3,
            channelText,
            index == selectedIndex ? BLACK : YELLOW,
            index == selectedIndex ? AQUA : BLACK
        );

        char rssiText[8];
        snprintf(
            rssiText,
            sizeof(rssiText),
            "%d",
            static_cast<int>(network->rssi)
        );

        uiText(
            136,
            y + 3,
            rssiText,
            index == selectedIndex ? BLACK : signalColor(network->rssi),
            index == selectedIndex ? AQUA : BLACK
        );
    }

    uiScrollbar(
        154,
        18,
        90,
        count,
        VISIBLE_BEACONS,
        static_cast<uint16_t>(selectedIndex)
    );
}

static void drawOverview() {
    uiClear(BLACK);
    uiHeader("BEACON ANALYZER", AQUA);

    if (WifiCore::isScanning()) {
        uiText(120, 4, "SCAN", BLACK, AQUA);
    } else {
        char countText[8];
        snprintf(
            countText,
            sizeof(countText),
            "%lu",
            static_cast<unsigned long>(beaconCount)
        );
        uiText(141, 4, countText, BLACK, AQUA);
    }

    drawBeaconList();

    char footer[32];

    snprintf(
        footer,
        sizeof(footer),
        "H:%lu  MAX:%d",
        static_cast<unsigned long>(stats.hiddenNetworks),
        static_cast<int>(stats.strongestRssi)
    );

    uiFooter(footer);
}

static void drawDetails() {
    uiClear(BLACK);
    uiHeader("BEACON DETAILS", AQUA);

    const WifiCore::NetworkRecord* network =
        WifiCore::network(static_cast<uint8_t>(selectedIndex));

    if (network == nullptr) {
        uiCenteredText(50, "BEACON UNAVAILABLE", RED);
        uiFooter("RELEASE = BACK");
        return;
    }

    String ssid = network->ssid;

    if (ssid.isEmpty()) {
        ssid = "<hidden>";
    }

    if (ssid.length() > 22) {
        ssid = ssid.substring(0, 21);
        ssid += "~";
    }

    uiText(4, 20, "SSID", GRAY);
    uiText(34, 20, ssid.c_str(), WHITE);

    char line[32];

    snprintf(
        line,
        sizeof(line),
        "%d dBm",
        static_cast<int>(network->rssi)
    );
    uiText(4, 37, "RSSI", GRAY);
    uiText(34, 37, line, signalColor(network->rssi));

    snprintf(
        line,
        sizeof(line),
        "%u",
        static_cast<unsigned>(network->channel)
    );
    uiText(4, 52, "CHANNEL", GRAY);
    uiText(58, 52, line, YELLOW);

    uiText(4, 67, "SECURITY", GRAY);
    uiText(58, 67, WifiCore::authName(network->auth), AQUA);

    snprintf(
        line,
        sizeof(line),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        network->bssid[0],
        network->bssid[1],
        network->bssid[2],
        network->bssid[3],
        network->bssid[4],
        network->bssid[5]
    );

    uiText(4, 82, "BSSID", GRAY);
    uiText(4, 97, line, WHITE);

    uiFooter("RELEASE = BACK");
}

void begin() {
    WifiCore::begin();

    active = false;
    details = false;
    selectedIndex = 0;
    listOffset = 0;
    lastRefresh = 0;

    resetStats();
    markDirty();
}

void enter() {
    active = true;
    details = false;
    selectedIndex = 0;
    listOffset = 0;

    requestScan();
    markDirty();
}

void exit() {
    active = false;
    details = false;

    WifiCore::stopScan();

    screenDirty = true;
}

void update() {
    if (!active) {
        return;
    }

    updateScan();
}

void handleInput(uint8_t event) {
    if (!active) {
        return;
    }

    switch (event) {
        case 1: // up
            if (!details && selectedIndex > 0) {
                --selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case 2: // down
            if (!details &&
                selectedIndex + 1 < WifiCore::networkCount()) {
                ++selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case 3: // left
            if (details) {
                details = false;
                markDirty();
            } else {
                exit();
            }
            break;

        case 4: // right
            if (!details && !WifiCore::isScanning()) {
                requestScan();
            }
            break;

        case 5: // select
            if (details) {
                details = false;
            } else if (WifiCore::networkCount() > 0) {
                details = true;
            } else if (!WifiCore::isScanning()) {
                requestScan();
            }

            markDirty();
            break;

        case 6: // back
            exit();
            break;

        case 9: // gesture left
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

    if (details) {
        drawDetails();
    } else {
        drawOverview();
    }

    screenDirty = false;
}

bool needsRedraw() {
    return screenDirty;
}

uint32_t observedBeaconCount() {
    return stats.observedNetworks;
}

uint32_t hiddenBeaconCount() {
    return stats.hiddenNetworks;
}

int32_t strongestBeaconRssi() {
    return stats.strongestRssi;
}

uint32_t channelBeaconCount(uint8_t channel) {
    if (channel > MAX_CHANNEL) {
        return 0;
    }

    return stats.channelUse[channel];
}

} // namespace WifiBeacon

void wifiBeaconBegin() {
    WifiBeacon::begin();
}

void wifiBeaconEnter() {
    WifiBeacon::enter();
}

void wifiBeaconExit() {
    WifiBeacon::exit();
}

void wifiBeaconUpdate() {
    WifiBeacon::update();
}

void wifiBeaconHandleInput(uint8_t event) {
    WifiBeacon::handleInput(event);
}

void wifiBeaconRender() {
    WifiBeacon::render();
}

bool wifiBeaconNeedsRedraw() {
    return WifiBeacon::needsRedraw();
}

uint32_t wifiBeaconObservedCount() {
    return WifiBeacon::observedBeaconCount();
}

uint32_t wifiBeaconHiddenCount() {
    return WifiBeacon::hiddenBeaconCount();
}

int32_t wifiBeaconStrongestRssi() {
    return WifiBeacon::strongestBeaconRssi();
}

uint32_t wifiBeaconChannelCount(uint8_t channel) {
    return WifiBeacon::channelBeaconCount(channel);
}
