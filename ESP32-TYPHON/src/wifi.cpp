#include <Arduino.h>
#include <WiFi.h>
#include <TFT_eSPI.h>
#include "config.h"

// hardware.cpp
TFT_eSPI& hardwareDisplay();

// input.cpp
void inputBegin();
void inputUpdate();
uint8_t inputGetEvent();

// ui.cpp
void uiInvalidate();
bool uiNeedsRedraw();
void uiMarkClean();
void uiClear(uint16_t color = BLACK);
void uiHeader(const char* title, uint16_t color = LBLUE);
void uiFooter(const char* text, uint16_t color = GRAY);
void uiText(int16_t x, int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiMenuRow(int16_t y, const char* text, bool selected, uint16_t accent = LBLUE);
void uiScrollbar(int16_t x, int16_t y, int16_t height, uint16_t totalItems, uint16_t visibleItems, uint16_t selectedItem);
void uiProgressBar(int16_t x, int16_t y, int16_t width, int16_t height, uint8_t percent, uint16_t fillColor = GREEN);

enum WifiInputEvent : uint8_t {
    WIFI_INPUT_NONE = 0,
    WIFI_INPUT_UP = 1,
    WIFI_INPUT_DOWN = 2,
    WIFI_INPUT_LEFT = 3,
    WIFI_INPUT_RIGHT = 4,
    WIFI_INPUT_SELECT = 5,
    WIFI_INPUT_BACK = 6,
    WIFI_INPUT_GESTURE_UP = 7,
    WIFI_INPUT_GESTURE_DOWN = 8,
    WIFI_INPUT_GESTURE_LEFT = 9,
    WIFI_INPUT_GESTURE_RIGHT = 10
};

namespace WifiTool {

static constexpr uint8_t MAX_VISIBLE_NETWORKS = 6;
static constexpr uint32_t SCAN_REFRESH_MS = 5000;
static constexpr uint32_t SCAN_TIMEOUT_MS = 15000;

struct NetworkRecord {
    String ssid;
    int32_t rssi;
    int32_t channel;
    wifi_auth_mode_t auth;
    bool hidden;
};

static NetworkRecord networks[40];
static uint8_t networkCount = 0;
static int16_t selectedNetwork = 0;
static int16_t listOffset = 0;

static bool initialized = false;
static bool scanRunning = false;
static bool scanRequested = false;
static bool detailsVisible = false;
static uint32_t scanStartedAt = 0;
static uint32_t lastScanAt = 0;

static bool screenDirty = true;

static const char* authName(wifi_auth_mode_t auth) {
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

static void requestRedraw() {
    screenDirty = true;
    uiInvalidate();
}

static void clearScanResults() {
    for (uint8_t i = 0; i < networkCount; ++i) {
        networks[i].ssid = "";
        networks[i].rssi = 0;
        networks[i].channel = 0;
        networks[i].auth = WIFI_AUTH_OPEN;
        networks[i].hidden = false;
    }

    networkCount = 0;
    selectedNetwork = 0;
    listOffset = 0;
}

static void startScan() {
    if (scanRunning) {
        return;
    }

    clearScanResults();

    WiFi.scanDelete();
    WiFi.scanNetworks(true, true);

    scanRunning = true;
    scanRequested = true;
    scanStartedAt = millis();

    requestRedraw();
}

static void finishScan(int resultCount) {
    scanRunning = false;
    scanRequested = false;
    lastScanAt = millis();

    if (resultCount < 0) {
        clearScanResults();
        requestRedraw();
        return;
    }

    const int storedCount = min(resultCount, static_cast<int>(sizeof(networks) / sizeof(networks[0])));

    for (int i = 0; i < storedCount; ++i) {
        networks[i].ssid = WiFi.SSID(i);
        networks[i].rssi = WiFi.RSSI(i);
        networks[i].channel = WiFi.channel(i);
        networks[i].auth = WiFi.encryptionType(i);
        networks[i].hidden = networks[i].ssid.isEmpty();
    }

    networkCount = static_cast<uint8_t>(storedCount);

    if (selectedNetwork >= networkCount) {
        selectedNetwork = networkCount > 0 ? networkCount - 1 : 0;
    }

    const int16_t maxOffset = max<int16_t>(0, static_cast<int16_t>(networkCount) - MAX_VISIBLE_NETWORKS);

    if (listOffset > maxOffset) {
        listOffset = maxOffset;
    }

    WiFi.scanDelete();
    requestRedraw();
}

static void updateScan() {
    if (!scanRunning) {
        if (millis() - lastScanAt >= SCAN_REFRESH_MS) {
            startScan();
        }
        return;
    }

    const int result = WiFi.scanComplete();

    if (result >= 0) {
        finishScan(result);
        return;
    }

    if (result == WIFI_SCAN_FAILED || millis() - scanStartedAt >= SCAN_TIMEOUT_MS) {
        WiFi.scanDelete();
        finishScan(-1);
    }
}

static void drawSignalBars(int16_t x, int16_t y, int32_t rssi, uint16_t color) {
    TFT_eSPI& tft = hardwareDisplay();

    uint8_t bars = 1;

    if (rssi >= -70) {
        bars = 2;
    }

    if (rssi >= -60) {
        bars = 3;
    }

    if (rssi >= -50) {
        bars = 4;
    }

    for (uint8_t i = 0; i < 4; ++i) {
        const int16_t barHeight = 3 + (i * 2);
        const int16_t barX = x + static_cast<int16_t>(i * 4);
        const int16_t barY = y + 9 - barHeight;

        tft.fillRect(barX, barY, 3, barHeight, i < bars ? color : GRAY);
    }
}

static void drawNetworkRow(uint8_t visibleIndex, uint8_t networkIndex, bool selected) {
    const int16_t y = 18 + static_cast<int16_t>(visibleIndex) * 14;
    const NetworkRecord& network = networks[networkIndex];

    uiMenuRow(y, network.ssid.isEmpty() ? "<hidden>" : network.ssid.c_str(), selected, AQUA);

    drawSignalBars(137, y + 2, network.rssi, selected ? BLACK : LGREEN);
}

static void drawScanner() {
    uiClear(BLACK);
    uiHeader("WIFI SCANNER", LBLUE);

    if (scanRunning) {
        uiCenteredText(48, "SCANNING...", YELLOW);
        uiCenteredText(65, "PLEASE WAIT", GRAY);
        uiProgressBar(30, 84, 100, 8, static_cast<uint8_t>(min<uint32_t>(
            100,
            ((millis() - scanStartedAt) * 100) / SCAN_TIMEOUT_MS)), AQUA);
        uiFooter("RELEASE = BACK");
        return;
    }

    if (networkCount == 0) {
        uiCenteredText(44, "NO NETWORKS", WHITE);
        uiCenteredText(59, "SCANNING...", GRAY);
        uiFooter("SELECT = SCAN");
        return;
    }

    const uint8_t visibleCount = min<uint8_t>(networkCount, MAX_VISIBLE_NETWORKS);

    for (uint8_t i = 0; i < visibleCount; ++i) {
        const uint8_t networkIndex = static_cast<uint8_t>(listOffset + i);
        drawNetworkRow(i, networkIndex, networkIndex == selectedNetwork);
    }

    uiScrollbar(
        154,
        18,
        84,
        networkCount,
        MAX_VISIBLE_NETWORKS,
        static_cast<uint16_t>(selectedNetwork)
    );

    char footer[32];
    snprintf(footer, sizeof(footer), "%u NETS  SELECT=DETAILS", networkCount);
    uiFooter(footer);
}

static void drawDetails() {
    uiClear(BLACK);
    uiHeader("NETWORK DETAILS", AQUA);

    if (selectedNetwork < 0 || selectedNetwork >= networkCount) {
        uiCenteredText(48, "NO NETWORK", RED);
        uiFooter("RELEASE = BACK");
        return;
    }

    const NetworkRecord& network = networks[selectedNetwork];

    char line[40];

    uiText(4, 20, "SSID:", GRAY);
    uiText(42, 20, network.ssid.isEmpty() ? "<hidden>" : network.ssid.c_str(), WHITE);

    snprintf(line, sizeof(line), "RSSI: %ld dBm", static_cast<long>(network.rssi));
    uiText(4, 37, line, LGREEN);

    snprintf(line, sizeof(line), "CHANNEL: %ld", static_cast<long>(network.channel));
    uiText(4, 52, line, YELLOW);

    snprintf(line, sizeof(line), "SECURITY: %s", authName(network.auth));
    uiText(4, 67, line, AQUA);

    snprintf(line, sizeof(line), "INDEX: %d/%d", selectedNetwork + 1, networkCount);
    uiText(4, 82, line, GRAY);

    uiFooter("RELEASE = BACK");
}

static void renderDisabledFeature(const char* title) {
    uiClear(BLACK);
    uiHeader(title, RED);
    uiCenteredText(42, "FEATURE DISABLED", RED);
    uiCenteredText(58, "IN THIS BUILD", WHITE);
    uiCenteredText(76, "FOR SAFETY", GRAY);
    uiFooter("RELEASE = BACK");
}

void begin() {
    if (initialized) {
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);

    initialized = true;
    scanRequested = false;
    scanRunning = false;
    detailsVisible = false;
    lastScanAt = 0;

    requestRedraw();
}

void enter() {
    begin();
    detailsVisible = false;
    startScan();
}

void exit() {
    if (scanRunning) {
        WiFi.scanDelete();
        scanRunning = false;
        scanRequested = false;
    }
}

void handleInput(uint8_t event) {
    switch (event) {
        case WIFI_INPUT_UP:
            if (!detailsVisible && selectedNetwork > 0) {
                --selectedNetwork;

                if (selectedNetwork < listOffset) {
                    listOffset = selectedNetwork;
                }

                requestRedraw();
            }
            break;

        case WIFI_INPUT_DOWN:
            if (!detailsVisible && selectedNetwork + 1 < networkCount) {
                ++selectedNetwork;

                if (selectedNetwork >= listOffset + MAX_VISIBLE_NETWORKS) {
                    listOffset = selectedNetwork - MAX_VISIBLE_NETWORKS + 1;
                }

                requestRedraw();
            }
            break;

        case WIFI_INPUT_SELECT:
            if (detailsVisible) {
                detailsVisible = false;
            } else if (networkCount > 0) {
                detailsVisible = true;
            } else if (!scanRunning) {
                startScan();
            }

            requestRedraw();
            break;

        case WIFI_INPUT_BACK:
        case WIFI_INPUT_GESTURE_LEFT:
            if (detailsVisible) {
                detailsVisible = false;
                requestRedraw();
            } else {
                exit();
            }
            break;

        case WIFI_INPUT_RIGHT:
        case WIFI_INPUT_GESTURE_RIGHT:
            if (!detailsVisible && !scanRunning) {
                startScan();
            }
            break;

        default:
            break;
    }
}

void update() {
    updateScan();
}

void render() {
    if (detailsVisible) {
        drawDetails();
    } else {
        drawScanner();
    }
}

} // namespace WifiTool

// Public tool entry points.
void wifiBegin() {
    WifiTool::begin();
}

void wifiEnter() {
    WifiTool::enter();
}

void wifiExit() {
    WifiTool::exit();
}

void wifiHandleInput(uint8_t event) {
    WifiTool::handleInput(event);
}

void wifiUpdate() {
    WifiTool::update();
}

void wifiRender() {
    WifiTool::render();
}
