#pragma once

#include <TFT_eSPI.h>
#include "BoardConfig.h"

// Global TFT instance
extern TFT_eSPI tft;

// Simple UI helpers – all drawing is clipped to 160x128
namespace Theme {

  void init();
  void clear(uint16_t color = COL_BG);
  void drawStatusBar(const char* title, bool showBackHint = true);
  void drawFooter(const char* left = nullptr, const char* right = nullptr);

  // Minimal list menu
  // items[] is null-terminated array of const char*
  // selected = current highlight index
  // topVisible = first visible item (for scrolling)
  void drawMenuList(const char* const* items, int count, int selected, int topVisible,
                    int yStart = 18, int rowH = 16);

  // WiFi network list (SSID + RSSI bar)
  // nets is array of {ssid, rssi}, count = number of entries
  void drawWifiList(const char* ssids[], const int32_t rssis[], int count,
                    int selected, int topVisible, int yStart = 18, int rowH = 14);

  // Tiny helpers
  void fillRoundRect(int x, int y, int w, int h, int r, uint16_t color);
  void drawFrame(int x, int y, int w, int h, uint16_t color);
  void printCentered(const char* txt, int y, uint16_t color, uint8_t size = 1);
  void drawRssiBar(int x, int y, int w, int h, int32_t rssi, bool selected);
}
