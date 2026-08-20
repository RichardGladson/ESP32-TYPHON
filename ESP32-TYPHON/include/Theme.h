#pragma once

#include <TFT_eSPI.h>
#include "BoardConfig.h"

extern TFT_eSPI tft;

namespace Theme {

  void init();
  void clear(uint16_t color = COL_BG);
  void drawStatusBar(const char* title, int holdPct = -1);
  void drawFooter(const char* left = nullptr, const char* right = nullptr);

  static const int MENU_ROWS = 5;

  void drawMenuList(const char* const* items, int count, int selected, int topVisible,
                    int yStart = 18, int rowH = 16);

  void drawWifiList(const char* ssids[], const int32_t rssis[], int count,
                    int selected, int topVisible, int yStart = 18, int rowH = 14);

  void fillRoundRect(int x, int y, int w, int h, int r, uint16_t color);
  void drawFrame(int x, int y, int w, int h, uint16_t color);
  void printCentered(const char* txt, int y, uint16_t color, uint8_t size = 1);
  void drawRssiBar(int x, int y, int w, int h, int32_t rssi, bool selected);
}
