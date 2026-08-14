#include <Arduino.h>
#include "config.h"

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
bool lastScanFailed();
bool startScan(bool showHidden, bool passive);
bool updateScan();
void stopScan();
uint8_t networkCount();
const NetworkRecord* network(uint8_t index);
int8_t strongestNetworkIndex();
const char* authName(wifi_auth_mode_t auth);
uint8_t rssiLevel(int32_t rssi);

} // namespace WifiCore

// ui.cpp interface
void uiInvalidate();
void uiClear(uint16_t color = BLACK);
void uiHeader(const char* title, uint16_t color = LBLUE);
void uiFooter(const char* text, uint16_t color = GRAY);
void uiText(int16_t x, int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiMenuRow(int16_t y, const char* text, bool selected, uint16_t accent = LBLUE);
void uiScrollbar(int16_t x, int16_t y, int16_t height, uint16_t totalItems, uint16_t visibleItems, uint16_t selectedItem);
void uiProgressBar(int16_t x, int16_t y, int16_t width, int16_t height, uint8_t percent, uint16_t fillColor = GREEN);

// hardware.cpp interface
class TFT_eSPI;
TFT_eSPI& hardwareDisplay();

enum ScannerEvent : uint8_t {
    SCANNER_NONE = 0,
    SCANNER_UP,
    SCANNER_DOWN,
    SCANNER_LEFT,
    SCANNER_RIGHT,
    SCANNER_SELECT,
    SCANNER_BACK,
    SCANNER_GESTURE_UP,
    SCANNER_GESTURE_DOWN,
    SCANNER_GESTURE_LEFT,
    SCANNER_GESTURE_RIGHT
};

namespace WifiScanner {

static constexpr uint8_t VISIBLE_ROWS = 6;
static constexpr uint8_t MAX_SELECTION = 39;

static bool active = false;
static bool details = false;
static bool includeHidden = true;
static bool passiveScan = false;
static bool screenDirty = true;

static int16_t selectedIndex = 0;
static int16_t listOffset = 0;

static uint32_t lastRefreshRequest = 0;
static uint32_t refreshIntervalMs = 5000;

static void markDirty() {
    screenDirty = true;
    uiInvalidate();
}

static uint8_t visibleNetworkCount() {
    const uint8_t count = WifiCore::networkCount();
    return count > VISIBLE_ROWS ? VISIBLE_ROWS : count;
}

static void clampSelection() {
    const int16_t count = static_cast<int16_t>(WifiCore::networkCount());

    if (count <= 0) {
        selectedIndex = 0;
        listOffset = 0;
        return;
    }

    if (selectedIndex < 0) {
        selectedIndex = 0;
    }

    if (selectedIndex >= count) {
        selectedIndex = count - 1;
    }

    const int16_t maxOffset = max<int16_t>(0, count - VISIBLE_ROWS);

    if (listOffset > maxOffset) {
        listOffset = maxOffset;
    }

    if (listOffset < 0) {
        listOffset = 0;
    }

    if (selectedIndex < listOffset) {
        listOffset = selectedIndex;
    }

    if (selectedIndex >= listOffset + VISIBLE_ROWS) {
        listOffset = selectedIndex - VISIBLE_ROWS + 1;
    }

    if (listOffset > maxOffset) {
        listOffset = maxOffset;
    }
}

static void requestScan() {
    if (WifiCore::isScanning()) {
        return;
    }

    if (WifiCore::startScan(includeHidden, passiveScan)) {
        lastRefreshRequest = millis();
        markDirty();
    } else {
        markDirty();
    }
}

static void updateScanState() {
    if (!active) {
        return;
    }

    if (WifiCore::isScanning()) {
        if (WifiCore::updateScan()) {
            clampSelection();
            markDirty();
        }

        return;
    }

    if (millis() - lastRefreshRequest >= refreshIntervalMs) {
        requestScan();
    }
}

static uint16_t securityColor(const WifiCore::NetworkRecord& network) {
    switch (network.auth) {
        case WIFI_AUTH_OPEN:
            return RED;

        case WIFI_AUTH_WEP:
            return ORANGE;

        case WIFI_AUTH_WPA_PSK:
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK:
            return YELLOW;

        case WIFI_AUTH_WPA3_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return GREEN;

        default:
            return AQUA;
    }
}

static void drawSignalIndicator(int16_t x, int16_t y, int32_t rssi, uint16_t color) {
    const uint8_t level = WifiCore::rssiLevel(rssi);

    for (uint8_t bar = 0; bar < 4; ++bar) {
        const int16_t height = 3 + (bar * 2);
        const int16_t barX = x + static_cast<int16_t>(bar * 4);
        const int16_t barY = y + 10 - height;

        const uint16_t barColor = bar < level ? color : GRAY;

        // use the generic display interface through ui primitives only
        uiText(barX, barY, " ", barColor, barColor);
    }
}

static void drawNetworkRow(uint8_t row, uint8_t networkIndex, bool selected) {
    const WifiCore::NetworkRecord* network = WifiCore::network(networkIndex);

    if (network == nullptr) {
        return;
    }

    const int16_t y = 18 + static_cast<int16_t>(row) * 16;
    const uint16_t accent = selected ? AQUA : LBLUE;

    String label = network->ssid;

    if (label.isEmpty()) {
        label = "<hidden>";
    }

    const size_t maxChars = 17;

    if (label.length() > maxChars) {
        label = label.substring(0, maxChars - 1);
        label += "~";
    }

    uiMenuRow(y, label.c_str(), selected, accent);

    char rssiText[12];
    snprintf(
        rssiText,
        sizeof(rssiText),
        "%ld",
        static_cast<long>(network->rssi)
    );

    uiText(
        108,
        y + 3,
        rssiText,
        selected ? BLACK : LGREEN,
        selected ? AQUA : BLACK
    );

    const uint16_t secColor = selected ? BLACK : securityColor(*network);

    uiText(
        135,
        y + 3,
        network->hidden ? "H" : "S",
        secColor,
        selected ? AQUA : BLACK
    );
}

static void drawHeaderStatus() {
    if (WifiCore::isScanning()) {
        uiText(118, 3, "SCAN", YELLOW, LBLUE);
        return;
    }

    const uint8_t count = WifiCore::networkCount();

    char countText[8];
    snprintf(countText, sizeof(countText), "%u", count);

    uiText(142, 3, countText, BLACK, LBLUE);
}

static void drawScannerScreen() {
    uiClear(BLACK);
    uiHeader("WIFI SCANNER", LBLUE);
    drawHeaderStatus();

    if (WifiCore::isScanning()) {
        uiCenteredText(43, "SCANNING", YELLOW);
        uiCenteredText(59, "PLEASE WAIT", GRAY);

        const uint32_t elapsed = millis() - lastRefreshRequest;
        const uint8_t progress = static_cast<uint8_t>(
            min<uint32_t>(95, (elapsed * 95UL) / 5000UL)
        );

        uiProgressBar(
            28,
            78,
            104,
            8,
            progress,
            AQUA
        );

        uiFooter("RELEASE = BACK");
        return;
    }

    const uint8_t count = WifiCore::networkCount();

    if (count == 0) {
        if (WifiCore::lastScanFailed()) {
            uiCenteredText(43, "SCAN FAILED", RED);
            uiCenteredText(59, "SELECT = RETRY", WHITE);
        } else {
            uiCenteredText(43, "NO NETWORKS", GRAY);
            uiCenteredText(59, "SELECT = SCAN", WHITE);
        }

        uiFooter("SELECT  SCAN");
        return;
    }

    clampSelection();

    const uint8_t rows = visibleNetworkCount();

    for (uint8_t row = 0; row < rows; ++row) {
        const uint8_t index = static_cast<uint8_t>(listOffset + row);

        drawNetworkRow(
            row,
            index,
            index == selectedIndex
        );
    }

    uiScrollbar(
        154,
        18,
        96,
        count,
        VISIBLE_ROWS,
        static_cast<uint16_t>(selectedIndex)
    );

    char footer[32];
    snprintf(
        footer,
        sizeof(footer),
        "%d/%u  SEL=DETAIL",
        selectedIndex + 1,
        count
    );

    uiFooter(footer);
}

static void drawDetailsScreen() {
    uiClear(BLACK);
    uiHeader("NETWORK", AQUA);

    const WifiCore::NetworkRecord* network =
        WifiCore::network(static_cast<uint8_t>(selectedIndex));

    if (network == nullptr) {
        uiCenteredText(50, "NETWORK UNAVAILABLE", RED);
        uiFooter("RELEASE = BACK");
        return;
    }

    String ssid = network->ssid;

    if (ssid.isEmpty()) {
        ssid = "<hidden>";
    }

    if (ssid.length() > 24) {
        ssid = ssid.substring(0, 23);
        ssid += "~";
    }

    uiText(4, 20, "SSID", GRAY);
    uiText(34, 20, ssid.c_str(), WHITE);

    char buffer[32];

    snprintf(
        buffer,
        sizeof(buffer),
        "%ld dBm",
        static_cast<long>(network->rssi)
    );
    uiText(4, 37, "RSSI", GRAY);
    uiText(34, 37, buffer, LGREEN);

    snprintf(
        buffer,
        sizeof(buffer),
        "%u",
        static_cast<unsigned>(network->channel)
    );
    uiText(4, 52, "CH", GRAY);
    uiText(34, 52, buffer, YELLOW);

    uiText(4, 67, "SEC", GRAY);
    uiText(34, 67, WifiCore::authName(network->auth), securityColor(*network));

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

    uiText(4, 82, "BSSID", GRAY);
    uiText(34, 82, mac, WHITE);

    uiText(4, 100, "SIGNAL", GRAY);

    const uint8_t level = WifiCore::rssiLevel(network->rssi);

    for (uint8_t i = 0; i < 4; ++i) {
        const uint16_t color = i < level ? LGREEN : GRAY;
        const int16_t x = 40 + static_cast<int16_t>(i * 20);

        uiText(
            x,
            98 - static_cast<int16_t>(i * 4),
            "#",
            color
        );
    }

    uiFooter("RELEASE = BACK");
}

void begin() {
    WifiCore::begin();

    active = false;
    details = false;
    selectedIndex = 0;
    listOffset = 0;
    lastRefreshRequest = millis();

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
}

void update() {
    if (!active) {
        return;
    }

    updateScanState();
}

void handleInput(uint8_t event) {
    if (!active) {
        return;
    }

    switch (event) {
        case SCANNER_UP:
            if (!details && selectedIndex > 0) {
                --selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case SCANNER_DOWN:
            if (!details &&
                selectedIndex + 1 < WifiCore::networkCount()) {
                ++selectedIndex;
                clampSelection();
                markDirty();
            }
            break;

        case SCANNER_LEFT:
        case SCANNER_GESTURE_LEFT:
            if (details) {
                details = false;
                markDirty();
            } else {
                exit();
            }
            break;

        case SCANNER_RIGHT:
        case SCANNER_GESTURE_RIGHT:
            if (!details && !WifiCore::isScanning()) {
                requestScan();
            }
            break;

        case SCANNER_SELECT:
            if (details) {
                details = false;
            } else if (WifiCore::networkCount() > 0) {
                details = true;
            } else if (!WifiCore::isScanning()) {
                requestScan();
            }

            markDirty();
            break;

        case SCANNER_BACK:
        case SCANNER_GESTURE_UP:
        case SCANNER_GESTURE_DOWN:
            if (details) {
                details = false;
                markDirty();
            } else {
                exit();
            }
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
        drawDetailsScreen();
    } else {
        drawScannerScreen();
    }

    screenDirty = false;
}

bool needsRedraw() {
    return screenDirty;
}

void setIncludeHidden(bool enabled) {
    if (includeHidden != enabled) {
        includeHidden = enabled;
        markDirty();
    }
}

bool getIncludeHidden() {
    return includeHidden;
}

void setPassiveScan(bool enabled) {
    if (passiveScan != enabled) {
        passiveScan = enabled;
        markDirty();
    }
}

bool getPassiveScan() {
    return passiveScan;
}

void setRefreshInterval(uint32_t intervalMs) {
    refreshIntervalMs = max<uint32_t>(1000, intervalMs);
}

uint32_t getRefreshInterval() {
    return refreshIntervalMs;
}

} // namespace WifiScanner

void wifiScannerBegin() {
    WifiScanner::begin();
}

void wifiScannerEnter() {
    WifiScanner::enter();
}

void wifiScannerExit() {
    WifiScanner::exit();
}

void wifiScannerUpdate() {
    WifiScanner::update();
}

void wifiScannerHandleInput(uint8_t event) {
    WifiScanner::handleInput(event);
}

void wifiScannerRender() {
    WifiScanner::render();
}

bool wifiScannerNeedsRedraw() {
    return WifiScanner::needsRedraw();
}

void wifiScannerSetIncludeHidden(bool enabled) {
    WifiScanner::setIncludeHidden(enabled);
}

bool wifiScannerGetIncludeHidden() {
    return WifiScanner::getIncludeHidden();
}

void wifiScannerSetPassiveScan(bool enabled) {
    WifiScanner::setPassiveScan(enabled);
}

bool wifiScannerGetPassiveScan() {
    return WifiScanner::getPassiveScan();
}
