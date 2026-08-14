#include <Arduino.h>
#include <WiFi.h>
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

} // namespace WifiCore

namespace WifiHiddenSsid {

static constexpr uint8_t VISIBLE_ROWS = 6;
static constexpr uint32_t REFRESH_INTERVAL_MS = 5000;

static bool active = false;
static bool details = false;
static bool screenDirty = true;

static int16_t selectedIndex = 0;
static int16_t listOffset = 0;
static uint32_t lastScanRequest = 0;

struct HiddenNetwork {
    uint8_t originalIndex;
    String bssid;
    int32_t rssi;
    uint8_t channel;
    wifi_auth_mode_t auth;
};

static HiddenNetwork hiddenNetworks[40];
static uint8_t hiddenCount = 0;

static void markDirty() {
    screenDirty = true;
    uiInvalidate();
}

static void clearResults() {
    for (uint8_t i = 0; i < 40; ++i) {
        hiddenNetworks[i].originalIndex = 0;
        hiddenNetworks[i].bssid = "";
        hiddenNetworks[i].rssi = -127;
        hiddenNetworks[i].channel = 0;
        hiddenNetworks[i].auth = WIFI_AUTH_OPEN;
    }

    hiddenCount = 0;
    selectedIndex = 0;
    listOffset = 0;
}

static void collectHiddenNetworks() {
    clearResults();

    const uint8_t count = WifiCore::networkCount();

    for (uint8_t i = 0; i < count && hiddenCount < 40; ++i) {
        const WifiCore::NetworkRecord* network = WifiCore::network(i);

        if (network == nullptr || !network->hidden) {
            continue;
        }

        HiddenNetwork& target = hiddenNetworks[hiddenCount];

        target.originalIndex = i;
        target.rssi = network->rssi;
        target.channel = network->channel;
        target.auth = network->auth;

        char mac[20];

        snprintf(
            mac,
            sizeof(mac),
            "%02X:%02X:%02X:%02X:%02X:%02X",
            network->bssid[0],
            network->bssid[1],
            network->bssid[2],
            network->bssid[3],
            network->bssid[4],
            network->bssid[5]
        );

        target.bssid = mac;

        ++hiddenCount;
    }
}

static void requestScan() {
    if (WifiCore::isScanning()) {
        return;
    }

    if (WifiCore::startScan(true, true)) {
        lastScanRequest = millis();
    }

    markDirty();
}

static void updateScan() {
    if (WifiCore::isScanning()) {
        if (WifiCore::updateScan()) {
            collectHiddenNetworks();
            markDirty();
        }

        return;
    }

    if (millis() - lastScanRequest >= REFRESH_INTERVAL_MS) {
        requestScan();
    }
}

static void clampSelection() {
    if (hiddenCount == 0) {
        selectedIndex = 0;
        listOffset = 0;
        return;
    }

    selectedIndex = constrain(
        selectedIndex,
        0,
        static_cast<int16_t>(hiddenCount - 1)
    );

    const int16_t maxOffset =
        max<int16_t>(0, static_cast<int16_t>(hiddenCount) - VISIBLE_ROWS);

    if (selectedIndex < listOffset) {
        listOffset = selectedIndex;
    }

    if (selectedIndex >= listOffset + VISIBLE_ROWS) {
        listOffset = selectedIndex - VISIBLE_ROWS + 1;
    }

    listOffset = constrain(listOffset, 0, maxOffset);
}

static uint16_t rssiColor(int32_t rssi) {
    if (rssi >= -55) {
        return GREEN;
    }

    if (rssi >= -70) {
        return YELLOW;
    }

    return RED;
}

static void drawList() {
    if (WifiCore::isScanning()) {
        uiCenteredText(46, "SCANNING...", YELLOW);
        uiCenteredText(62, "HIDDEN SSIDs", GRAY);
        return;
    }

    if (hiddenCount == 0) {
        uiCenteredText(44, "NONE FOUND", GREEN);
        uiCenteredText(60, "SELECT = RESCAN", WHITE);
        return;
    }

    clampSelection();

    for (uint8_t row = 0; row < min<uint8_t>(VISIBLE_ROWS, hiddenCount); ++row) {
        const uint8_t index =
            static_cast<uint8_t>(listOffset + row);

        const HiddenNetwork& network = hiddenNetworks[index];
        const bool selected = index == selectedIndex;

        char label[20];

        snprintf(
            label,
            sizeof(label),
            "HIDDEN %u",
            static_cast<unsigned>(index + 1)
        );

        const int16_t y = 18 + row * 16;

        uiMenuRow(
            y,
            label,
            selected,
            PURPLE
        );

        char channel[8];

        snprintf(
            channel,
            sizeof(channel),
            "C%u",
            static_cast<unsigned>(network.channel)
        );

        uiText(
            92,
            y + 3,
            channel,
            selected ? BLACK : YELLOW,
            selected ? PURPLE : BLACK
        );

        char rssi[10];

        snprintf(
            rssi,
            sizeof(rssi),
            "%d",
            static_cast<int>(network.rssi)
        );

        uiText(
            120,
            y + 3,
            rssi,
            selected ? BLACK : rssiColor(network.rssi),
            selected ? PURPLE : BLACK
        );
    }

    uiScrollbar(
        154,
        18,
        96,
        hiddenCount,
        VISIBLE_ROWS,
        static_cast<uint16_t>(selectedIndex)
    );
}

static void drawDetails() {
    uiClear(BLACK);
    uiHeader("HIDDEN NETWORK", PURPLE);

    if (selectedIndex < 0 || selectedIndex >= hiddenCount) {
        uiCenteredText(50, "NETWORK UNAVAILABLE", RED);
        uiFooter("RELEASE = BACK");
        return;
    }

    const HiddenNetwork& network = hiddenNetworks[selectedIndex];

    uiText(4, 20, "SSID", GRAY);
    uiText(40, 20, "<hidden>", WHITE);

    char buffer[32];

    uiText(4, 37, "BSSID", GRAY);
    uiText(4, 52, network.bssid.c_str(), WHITE);

    snprintf(
        buffer,
        sizeof(buffer),
        "%d dBm",
        static_cast<int>(network.rssi)
    );
    uiText(4, 70, "RSSI", GRAY);
    uiText(40, 70, buffer, rssiColor(network.rssi));

    snprintf(
        buffer,
        sizeof(buffer),
        "%u",
        static_cast<unsigned>(network.channel)
    );
    uiText(4, 85, "CHANNEL", GRAY);
    uiText(52, 85, buffer, YELLOW);

    uiText(4, 100, "SEC", GRAY);
    uiText(40, 100, WifiCore::authName(network.auth), AQUA);

    uiFooter("RELEASE = BACK");
}

void begin() {
    WifiCore::begin();

    active = false;
    details = false;
    selectedIndex = 0;
    listOffset = 0;
    lastScanRequest = 0;

    clearResults();
    screenDirty = true;
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
    uiInvalidate();
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
            if (!details && selectedIndex + 1 < hiddenCount) {
                ++selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case 3: // left
        case 9: // gesture left
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
            } else if (hiddenCount > 0) {
                details = true;
            } else if (!WifiCore::isScanning()) {
                requestScan();
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

    if (details) {
        drawDetails();
    } else {
        uiClear(BLACK);
        uiHeader("HIDDEN SSIDs", PURPLE);
        drawList();

        char footer[28];

        snprintf(
            footer,
            sizeof(footer),
            "FOUND %u",
            static_cast<unsigned>(hiddenCount)
        );

        uiFooter(footer);
    }

    screenDirty = false;
}

bool needsRedraw() {
    return screenDirty;
}

uint8_t count() {
    return hiddenCount;
}

} // namespace WifiHiddenSsid

void wifiHiddenSsidBegin() {
    WifiHiddenSsid::begin();
}

void wifiHiddenSsidEnter() {
    WifiHiddenSsid::enter();
}

void wifiHiddenSsidExit() {
    WifiHiddenSsid::exit();
}

void wifiHiddenSsidUpdate() {
    WifiHiddenSsid::update();
}

void wifiHiddenSsidHandleInput(uint8_t event) {
    WifiHiddenSsid::handleInput(event);
}

void wifiHiddenSsidRender() {
    WifiHiddenSsid::render();
}

bool wifiHiddenSsidNeedsRedraw() {
    return WifiHiddenSsid::needsRedraw();
}

uint8_t wifiHiddenSsidCount() {
    return WifiHiddenSsid::count();
}
