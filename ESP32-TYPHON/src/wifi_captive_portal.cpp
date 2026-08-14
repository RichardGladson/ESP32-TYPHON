#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include "config.h"

// ui.cpp interface
void uiInvalidate();
void uiClear(uint16_t color = BLACK);
void uiHeader(const char* title, uint16_t color = LBLUE);
void uiFooter(const char* text, uint16_t color = GRAY);
void uiText(int16_t x, int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);
void uiMenuRow(int16_t y, const char* text, bool selected, uint16_t accent = LBLUE);

namespace WifiCaptivePortal {

static constexpr uint16_t HTTP_PORT = 80;
static constexpr uint16_t DNS_PORT = 53;
static constexpr uint32_t UI_REFRESH_MS = 500;

static const char* DEFAULT_SSID = "ESP32DIV_AP";

static WebServer server(HTTP_PORT);
static DNSServer dnsServer;

static bool initialized = false;
static bool active = false;
static bool serverRunning = false;
static bool screenDirty = true;

static char accessPointSsid[33] = "ESP32DIV_AP";
static uint8_t accessPointChannel = 1;

static uint32_t requestCount = 0;
static uint32_t lastRequestAt = 0;
static uint32_t lastUiRefresh = 0;

static String portalPage() {
    String page;
    page.reserve(1200);

    page += F("<!doctype html><html><head>");
    page += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
    page += F("<title>ESP32-DIV</title>");
    page += F("<style>");
    page += F("body{font-family:Arial,sans-serif;background:#101010;color:#f7f7f7;margin:0;padding:24px}");
    page += F(".box{max-width:520px;margin:auto;border:1px solid #555;padding:20px}");
    page += F("h1{font-size:22px;margin-top:0}");
    page += F(".item{margin:10px 0;padding:10px;background:#1d1d1d}");
    page += F("</style></head><body><div class='box'>");
    page += F("<h1>ESP32-DIV Captive Portal</h1>");
    page += F("<div class='item'>Network: ");
    page += accessPointSsid;
    page += F("</div>");
    page += F("<div class='item'>Channel: ");
    page += String(accessPointChannel);
    page += F("</div>");
    page += F("<div class='item'>Requests handled: ");
    page += String(requestCount);
    page += F("</div>");
    page += F("<p>This local portal is running for testing and device-hosted web content.</p>");
    page += F("</div></body></html>");

    return page;
}

static void recordRequest() {
    ++requestCount;
    lastRequestAt = millis();
}

static void sendPortalPage() {
    recordRequest();
    server.send(200, "text/html", portalPage());
    screenDirty = true;
    uiInvalidate();
}

static void sendProbeSuccess() {
    recordRequest();
    server.send(200, "text/html",
                "<!doctype html><html><body>Success</body></html>");
}

static void redirectToPortal() {
    recordRequest();
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
}

static void handleNotFound() {
    redirectToPortal();
}

static void registerRoutes() {
    server.on("/", HTTP_GET, sendPortalPage);
    server.on("/login.html", HTTP_GET, sendPortalPage);

    server.on("/generate_204", HTTP_GET, sendPortalPage);
    server.on("/hotspot-detect.html", HTTP_GET, sendPortalPage);
    server.on("/captive.apple.com", HTTP_GET, sendProbeSuccess);
    server.on("/ncsi.txt", HTTP_GET, sendProbeSuccess);
    server.on("/connecttest.txt", HTTP_GET, sendProbeSuccess);

    server.onNotFound(handleNotFound);
}

static void stopWebServer() {
    if (!serverRunning) {
        return;
    }

    server.stop();
    dnsServer.stop();

    serverRunning = false;
}

static bool startWebServer() {
    if (serverRunning) {
        return true;
    }

    registerRoutes();

    server.begin();
    dnsServer.start(
        DNS_PORT,
        "*",
        WiFi.softAPIP()
    );

    serverRunning = true;
    return true;
}

static void stopAccessPoint() {
    stopWebServer();
    WiFi.softAPdisconnect(true);
}

static bool startAccessPoint() {
    stopAccessPoint();

    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(
        IPAddress(192, 168, 4, 1),
        IPAddress(192, 168, 4, 1),
        IPAddress(255, 255, 255, 0)
    );

    const bool started = WiFi.softAP(
        accessPointSsid,
        nullptr,
        accessPointChannel,
        false,
        4
    );

    if (!started) {
        return false;
    }

    return startWebServer();
}

static void updateServer() {
    if (!active || !serverRunning) {
        return;
    }

    dnsServer.processNextRequest();
    server.handleClient();
}

static void drawScreen() {
    uiClear(BLACK);
    uiHeader("CAPTIVE PORTAL", AQUA);

    uiText(4, 20, "SSID", GRAY);
    uiText(38, 20, accessPointSsid, WHITE);

    char buffer[32];

    snprintf(
        buffer,
        sizeof(buffer),
        "CHANNEL %u",
        static_cast<unsigned>(accessPointChannel)
    );
    uiText(4, 37, buffer, YELLOW);

    uiText(4, 53, "STATUS", GRAY);
    uiText(
        50,
        53,
        active ? "ACTIVE" : "STOPPED",
        active ? GREEN : RED
    );

    if (active) {
        IPAddress address = WiFi.softAPIP();

        snprintf(
            buffer,
            sizeof(buffer),
            "%u.%u.%u.%u",
            address[0],
            address[1],
            address[2],
            address[3]
        );

        uiText(4, 69, "IP", GRAY);
        uiText(50, 69, buffer, LAQUA);
    }

    snprintf(
        buffer,
        sizeof(buffer),
        "REQUESTS %lu",
        static_cast<unsigned long>(requestCount)
    );
    uiText(4, 85, buffer, WHITE);

    if (lastRequestAt != 0) {
        const uint32_t age = millis() - lastRequestAt;

        snprintf(
            buffer,
            sizeof(buffer),
            "LAST %lus",
            static_cast<unsigned long>(age / 1000UL)
        );

        uiText(4, 101, buffer, GRAY);
    }

    uiFooter(active ? "SEL STOP  L/R CH  BACK" : "SEL START  BACK");
    screenDirty = false;
}

void begin() {
    if (initialized) {
        return;
    }

    strncpy(
        accessPointSsid,
        DEFAULT_SSID,
        sizeof(accessPointSsid) - 1
    );
    accessPointSsid[sizeof(accessPointSsid) - 1] = '\0';

    accessPointChannel = 1;
    requestCount = 0;
    lastRequestAt = 0;
    lastUiRefresh = 0;

    active = false;
    serverRunning = false;
    screenDirty = true;
    initialized = true;
}

void enter() {
    if (!initialized) {
        begin();
    }

    active = true;

    if (!startAccessPoint()) {
        active = false;
    }

    lastUiRefresh = millis();
    screenDirty = true;
    uiInvalidate();
}

void exit() {
    active = false;
    stopAccessPoint();

    screenDirty = true;
    uiInvalidate();
}

void update() {
    if (!active) {
        return;
    }

    updateServer();

    if (millis() - lastUiRefresh >= UI_REFRESH_MS) {
        lastUiRefresh = millis();
        screenDirty = true;
        uiInvalidate();
    }
}

void handleInput(uint8_t event) {
    if (!active) {
        return;
    }

    switch (event) {
        case 3: // left
            if (accessPointChannel > 1) {
                --accessPointChannel;
                startAccessPoint();
                screenDirty = true;
                uiInvalidate();
            }
            break;

        case 4: // right
            if (accessPointChannel < 13) {
                ++accessPointChannel;
                startAccessPoint();
                screenDirty = true;
                uiInvalidate();
            }
            break;

        case 5: // select
            exit();
            break;

        case 6: // back
        case 9: // gesture left
            exit();
            break;

        case 10: // gesture right
            if (!active) {
                enter();
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

    drawScreen();
}

bool needsRedraw() {
    return screenDirty;
}

bool isActive() {
    return active;
}

uint8_t channel() {
    return accessPointChannel;
}

const char* ssid() {
    return accessPointSsid;
}

uint32_t requests() {
    return requestCount;
}

void setSsid(const char* newSsid) {
    if (newSsid == nullptr || *newSsid == '\0') {
        return;
    }

    strncpy(
        accessPointSsid,
        newSsid,
        sizeof(accessPointSsid) - 1
    );
    accessPointSsid[sizeof(accessPointSsid) - 1] = '\0';

    if (active) {
        startAccessPoint();
    }

    screenDirty = true;
    uiInvalidate();
}

} // namespace WifiCaptivePortal

void wifiCaptivePortalBegin() {
    WifiCaptivePortal::begin();
}

void wifiCaptivePortalEnter() {
    WifiCaptivePortal::enter();
}

void wifiCaptivePortalExit() {
    WifiCaptivePortal::exit();
}

void wifiCaptivePortalUpdate() {
    WifiCaptivePortal::update();
}

void wifiCaptivePortalHandleInput(uint8_t event) {
    WifiCaptivePortal::handleInput(event);
}

void wifiCaptivePortalRender() {
    WifiCaptivePortal::render();
}

bool wifiCaptivePortalNeedsRedraw() {
    return WifiCaptivePortal::needsRedraw();
}

bool wifiCaptivePortalIsActive() {
    return WifiCaptivePortal::isActive();
}

uint8_t wifiCaptivePortalChannel() {
    return WifiCaptivePortal::channel();
}

const char* wifiCaptivePortalSsid() {
    return WifiCaptivePortal::ssid();
}

uint32_t wifiCaptivePortalRequests() {
    return WifiCaptivePortal::requests();
}

void wifiCaptivePortalSetSsid(const char* ssid) {
    WifiCaptivePortal::setSsid(ssid);
}
