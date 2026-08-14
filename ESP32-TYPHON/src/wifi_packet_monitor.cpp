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

// hardware.cpp interface
class TFT_eSPI;
TFT_eSPI& hardwareDisplay();

namespace WifiPacketMonitor {

static constexpr uint8_t MAX_CHANNEL = 13;
static constexpr uint8_t GRAPH_WIDTH = 150;
static constexpr uint16_t SAMPLE_INTERVAL_MS = 250;
static constexpr uint16_t CHANNEL_HOLD_MS = 1800;

static volatile uint32_t packetCount = 0;
static volatile uint32_t managementCount = 0;
static volatile uint32_t controlCount = 0;
static volatile uint32_t dataCount = 0;
static volatile uint32_t deauthCount = 0;
static volatile int32_t rssiTotal = 0;
static volatile uint32_t rssiSamples = 0;

static uint32_t lastSampleMs = 0;
static uint32_t lastPacketCount = 0;
static uint32_t lastDeauthCount = 0;

static uint16_t packetsPerSecond = 0;
static int16_t averageRssi = -127;
static uint8_t currentChannel = 1;

static uint16_t packetHistory[GRAPH_WIDTH] = {};
static int16_t rssiHistory[GRAPH_WIDTH] = {};

static bool active = false;
static bool radioReady = false;
static bool screenDirty = true;

static void markDirty() {
    screenDirty = true;
    uiInvalidate();
}

static void pushHistory(uint16_t packetRate, int16_t rssi) {
    for (uint8_t i = 1; i < GRAPH_WIDTH; ++i) {
        packetHistory[i - 1] = packetHistory[i];
        rssiHistory[i - 1] = rssiHistory[i];
    }

    packetHistory[GRAPH_WIDTH - 1] = packetRate;
    rssiHistory[GRAPH_WIDTH - 1] = rssi;
}

static uint16_t graphPeak() {
    uint16_t peak = 10;

    for (uint8_t i = 0; i < GRAPH_WIDTH; ++i) {
        peak = max<uint16_t>(peak, packetHistory[i]);
    }

    return peak;
}

static void promiscuousCallback(void* buffer, wifi_promiscuous_pkt_type_t type) {
    if (buffer == nullptr) {
        return;
    }

    const wifi_promiscuous_pkt_t* packet =
        reinterpret_cast<const wifi_promiscuous_pkt_t*>(buffer);

    const uint16_t length = packet->rx_ctrl.sig_len;

    if (length == 0) {
        return;
    }

    ++packetCount;

    if (type == WIFI_PKT_MGMT) {
        ++managementCount;

        const uint8_t frameSubtype = packet->payload[0] & 0xF0;

        if (frameSubtype == 0xC0 || frameSubtype == 0xA0) {
            ++deauthCount;
        }
    } else if (type == WIFI_PKT_CTRL) {
        ++controlCount;
    } else if (type == WIFI_PKT_DATA) {
        ++dataCount;
    }

    rssiTotal += packet->rx_ctrl.rssi;
    ++rssiSamples;
}

static bool setMonitorChannel(uint8_t channel) {
    if (channel < 1 || channel > MAX_CHANNEL) {
        return false;
    }

    const esp_err_t result =
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    if (result != ESP_OK) {
        return false;
    }

    currentChannel = channel;
    return true;
}

static void startRadio() {
    WiFi.mode(WIFI_MODE_NULL);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);

    setMonitorChannel(currentChannel);

    esp_wifi_set_promiscuous(true);

    radioReady = true;
}

static void stopRadio() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);

    radioReady = false;
}

static void resetCounters() {
    noInterrupts();

    packetCount = 0;
    managementCount = 0;
    controlCount = 0;
    dataCount = 0;
    deauthCount = 0;
    rssiTotal = 0;
    rssiSamples = 0;

    interrupts();

    lastSampleMs = millis();
    lastPacketCount = 0;
    lastDeauthCount = 0;

    packetsPerSecond = 0;
    averageRssi = -127;

    memset(packetHistory, 0, sizeof(packetHistory));
    memset(rssiHistory, 0, sizeof(rssiHistory));
}

static void updateStatistics() {
    const uint32_t now = millis();

    if (now - lastSampleMs < SAMPLE_INTERVAL_MS) {
        return;
    }

    const uint32_t elapsed = now - lastSampleMs;

    uint32_t packets;
    uint32_t deauths;
    int32_t rssiSum;
    uint32_t rssiCount;

    noInterrupts();

    packets = packetCount;
    deauths = deauthCount;
    rssiSum = rssiTotal;
    rssiCount = rssiSamples;

    interrupts();

    const uint32_t packetDelta = packets - lastPacketCount;
    const uint32_t deauthDelta = deauths - lastDeauthCount;

    packetsPerSecond = static_cast<uint16_t>(
        min<uint32_t>(65535UL, (packetDelta * 1000UL) / elapsed)
    );

    if (rssiCount > 0) {
        averageRssi = static_cast<int16_t>(rssiSum / static_cast<int32_t>(rssiCount));
    } else {
        averageRssi = -127;
    }

    pushHistory(packetsPerSecond, averageRssi);

    lastPacketCount = packets;
    lastDeauthCount = deauths;
    lastSampleMs = now;

    markDirty();

    (void)deauthDelta;
}

static void drawGraph() {
    TFT_eSPI& tft = hardwareDisplay();

    const int16_t x = 5;
    const int16_t y = 47;
    const int16_t width = 150;
    const int16_t height = 55;

    tft.drawRect(x, y, width, height, GRAY);

    const uint16_t peak = graphPeak();

    for (uint8_t i = 1; i < GRAPH_WIDTH; ++i) {
        const uint16_t previous = packetHistory[i - 1];
        const uint16_t current = packetHistory[i];

        const int16_t previousY =
            y + height - 2 -
            static_cast<int16_t>((previous * (height - 4)) / peak);

        const int16_t currentY =
            y + height - 2 -
            static_cast<int16_t>((current * (height - 4)) / peak);

        tft.drawLine(
            x + i - 1,
            previousY,
            x + i,
            currentY,
            LAQUA
        );
    }
}

static void drawDashboard() {
    uiClear(BLACK);
    uiHeader("PACKET MONITOR", PURPLE);

    char buffer[24];

    snprintf(
        buffer,
        sizeof(buffer),
        "CH:%u",
        static_cast<unsigned>(currentChannel)
    );
    uiText(104, 4, buffer, BLACK, PURPLE);

    snprintf(
        buffer,
        sizeof(buffer),
        "%u p/s",
        static_cast<unsigned>(packetsPerSecond)
    );
    uiText(5, 18, buffer, LAQUA);

    snprintf(
        buffer,
        sizeof(buffer),
        "RSSI %d",
        static_cast<int>(averageRssi)
    );
    uiText(65, 18, buffer, LGREEN);

    uint32_t totalPackets;
    uint32_t totalMgmt;
    uint32_t totalControl;
    uint32_t totalData;
    uint32_t totalDeauth;

    noInterrupts();

    totalPackets = packetCount;
    totalMgmt = managementCount;
    totalControl = controlCount;
    totalData = dataCount;
    totalDeauth = deauthCount;

    interrupts();

    snprintf(
        buffer,
        sizeof(buffer),
        "P %lu",
        static_cast<unsigned long>(totalPackets)
    );
    uiText(5, 34, buffer, WHITE);

    snprintf(
        buffer,
        sizeof(buffer),
        "M %lu",
        static_cast<unsigned long>(totalMgmt)
    );
    uiText(40, 34, buffer, AQUA);

    snprintf(
        buffer,
        sizeof(buffer),
        "C %lu",
        static_cast<unsigned long>(totalControl)
    );
    uiText(75, 34, buffer, YELLOW);

    snprintf(
        buffer,
        sizeof(buffer),
        "D %lu",
        static_cast<unsigned long>(totalData)
    );
    uiText(110, 34, buffer, LGREEN);

    drawGraph();

    snprintf(
        buffer,
        sizeof(buffer),
        "DEAUTH %lu",
        static_cast<unsigned long>(totalDeauth)
    );

    const uint16_t deauthColor = totalDeauth > 0 ? RED : GRAY;
    uiText(5, 105, buffer, deauthColor);

    uiText(92, 105, "L/R CH", GRAY);
    uiFooter("SEL RESET  BACK EXIT");
}

void begin() {
    if (active) {
        return;
    }

    currentChannel = 1;
    resetCounters();
    startRadio();

    active = true;
    markDirty();
}

void enter() {
    begin();
}

void exit() {
    if (!active) {
        return;
    }

    stopRadio();
    active = false;
    screenDirty = false;
}

void update() {
    if (!active) {
        return;
    }

    if (!radioReady) {
        startRadio();
    }

    updateStatistics();

    if (millis() - lastSampleMs >= CHANNEL_HOLD_MS) {
        // intentionally remain on the selected channel until the user changes it
    }
}

void handleInput(uint8_t event) {
    if (!active) {
        return;
    }

    switch (event) {
        case 3: // left
            if (currentChannel > 1) {
                --currentChannel;
                setMonitorChannel(currentChannel);
                markDirty();
            }
            break;

        case 4: // right
            if (currentChannel < MAX_CHANNEL) {
                ++currentChannel;
                setMonitorChannel(currentChannel);
                markDirty();
            }
            break;

        case 5: // select
            resetCounters();
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

    drawDashboard();
    screenDirty = false;
}

bool needsRedraw() {
    return screenDirty;
}

uint8_t channel() {
    return currentChannel;
}

uint32_t packets() {
    uint32_t value;

    noInterrupts();
    value = packetCount;
    interrupts();

    return value;
}

uint32_t managementPackets() {
    uint32_t value;

    noInterrupts();
    value = managementCount;
    interrupts();

    return value;
}

uint32_t controlPackets() {
    uint32_t value;

    noInterrupts();
    value = controlCount;
    interrupts();

    return value;
}

uint32_t dataPackets() {
    uint32_t value;

    noInterrupts();
    value = dataCount;
    interrupts();

    return value;
}

uint32_t deauthenticationFrames() {
    uint32_t value;

    noInterrupts();
    value = deauthCount;
    interrupts();

    return value;
}

int16_t averageRssiValue() {
    return averageRssi;
}

} // namespace WifiPacketMonitor

void wifiPacketMonitorBegin() {
    WifiPacketMonitor::begin();
}

void wifiPacketMonitorEnter() {
    WifiPacketMonitor::enter();
}

void wifiPacketMonitorExit() {
    WifiPacketMonitor::exit();
}

void wifiPacketMonitorUpdate() {
    WifiPacketMonitor::update();
}

void wifiPacketMonitorHandleInput(uint8_t event) {
    WifiPacketMonitor::handleInput(event);
}

void wifiPacketMonitorRender() {
    WifiPacketMonitor::render();
}

bool wifiPacketMonitorNeedsRedraw() {
    return WifiPacketMonitor::needsRedraw();
}

uint8_t wifiPacketMonitorChannel() {
    return WifiPacketMonitor::channel();
}

uint32_t wifiPacketMonitorPackets() {
    return WifiPacketMonitor::packets();
}

uint32_t wifiPacketMonitorManagementPackets() {
    return WifiPacketMonitor::managementPackets();
}

uint32_t wifiPacketMonitorControlPackets() {
    return WifiPacketMonitor::controlPackets();
}

uint32_t wifiPacketMonitorDataPackets() {
    return WifiPacketMonitor::dataPackets();
}

uint32_t wifiPacketMonitorDeauthenticationFrames() {
    return WifiPacketMonitor::deauthenticationFrames();
}

int16_t wifiPacketMonitorAverageRssi() {
    return WifiPacketMonitor::averageRssiValue();
}
