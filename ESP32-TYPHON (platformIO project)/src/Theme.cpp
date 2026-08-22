#include "Theme.h"
#include <string.h>
#include <stdio.h>

TFT_eSPI tft = TFT_eSPI();

namespace Theme {

void init() {
  tft.init();
  tft.setRotation(DISPLAY_ROTATION);   // 3 = landscape 160x128
  tft.fillScreen(COL_BG);
  tft.setTextDatum(TL_DATUM);
  tft.setTextFont(1);                  // GLCD font – small & fast
  tft.setTextSize(1);
}

void clear(uint16_t color) {
  tft.fillScreen(color);
}

void drawStatusBar(const char* title, int holdPct) {
  (void)holdPct;  // counter drawn only via drawHoldCounter() — avoids full-screen redraw
  tft.fillRect(0, 0, SCREEN_W, 16, 0x10A2);
  tft.drawFastHLine(0, 16, SCREEN_W, COL_BORDER);
  tft.setTextColor(COL_TITLE, 0x10A2);
  tft.setTextDatum(TL_DATUM);
  tft.setCursor(2, 4);
  tft.print("ESP32-TYPHON");
}

// Partial update: top-right only (approx x=140..159, y=0..15)
void drawHoldCounter(int level) {
  const int x = SCREEN_W - 20;
  const int y = 0;
  const int w = 20;
  const int h = 16;
  tft.fillRect(x, y, w, h, 0x10A2);  // same as status bar bg
  if (level >= 1 && level <= 9) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%d", level);
    tft.setTextColor(level >= 9 ? COL_WARN : COL_ACCENT, 0x10A2);
    tft.setTextDatum(TR_DATUM);
    tft.drawString(buf, SCREEN_W - 2, 4);
  }
}

void drawFooter(const char* left, const char* right) {
  // Bottom bar 112..127
  tft.fillRect(0, 112, SCREEN_W, 16, 0x10A2);
  tft.drawFastHLine(0, 112, SCREEN_W, COL_BORDER);

  tft.setTextColor(COL_DIM, 0x10A2);
  if (left) {
    tft.setTextDatum(TL_DATUM);
    tft.drawString(left, 4, 116);
  }
  if (right) {
    tft.setTextDatum(TR_DATUM);
    tft.drawString(right, SCREEN_W - 4, 116);
  }
}

void drawMenuList(const char* const* items, int count, int selected, int topVisible,
                  int yStart, int rowH) {
  int maxRows = (112 - yStart) / rowH;   // leave room for footer
  if (maxRows < 1) maxRows = 1;

  // Clear list area
  tft.fillRect(0, yStart, SCREEN_W, 112 - yStart, COL_BG);

  for (int i = 0; i < maxRows; i++) {
    int idx = topVisible + i;
    if (idx >= count) break;

    int y = yStart + i * rowH;
    bool sel = (idx == selected);

    if (sel) {
      tft.fillRect(2, y, SCREEN_W - 4, rowH - 1, COL_MENU_SEL_BG);
      tft.setTextColor(COL_MENU_SEL_FG, COL_MENU_SEL_BG);
    } else {
      tft.setTextColor(COL_FG, COL_BG);
    }

    tft.setTextDatum(TL_DATUM);
    tft.setCursor(6, y + 4);
    tft.print(items[idx]);

    // small accent bar on selected
    if (sel) {
      tft.fillRect(0, y, 2, rowH - 1, COL_ACCENT);
    }
  }

  // Scroll indicators
  if (topVisible > 0) {
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setCursor(SCREEN_W - 10, yStart);
    tft.print("^");
  }
  if (topVisible + maxRows < count) {
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setCursor(SCREEN_W - 10, 112 - 12);
    tft.print("v");
  }
}

void fillRoundRect(int x, int y, int w, int h, int r, uint16_t color) {
  tft.fillRoundRect(x, y, w, h, r, color);
}

void drawFrame(int x, int y, int w, int h, uint16_t color) {
  tft.drawRect(x, y, w, h, color);
}

void printCentered(const char* txt, int y, uint16_t color, uint8_t size) {
  tft.setTextSize(size);
  tft.setTextColor(color, COL_BG);
  tft.setTextDatum(TC_DATUM);
  tft.drawString(txt, SCREEN_W / 2, y);
  tft.setTextSize(1);
  tft.setTextDatum(TL_DATUM);
}

// RSSI → bar fill ( -30 = full, -90 = empty )
void drawRssiBar(int x, int y, int w, int h, int32_t rssi, bool selected) {
  // clamp
  if (rssi > -30) rssi = -30;
  if (rssi < -90) rssi = -90;
  int fill = map(rssi, -90, -30, 0, w);
  if (fill < 0) fill = 0;
  if (fill > w) fill = w;

  uint16_t barColor;
  if (rssi >= -55)      barColor = COL_OK;      // strong
  else if (rssi >= -70) barColor = YELLOW;
  else                  barColor = COL_ERR;     // weak

  // background track
  tft.fillRect(x, y, w, h, selected ? 0x2104 : 0x18C3);
  // filled portion
  if (fill > 0) tft.fillRect(x, y, fill, h, barColor);
  // border
  tft.drawRect(x, y, w, h, selected ? COL_ACCENT : COL_BORDER);
}

void drawWifiList(const char* ssids[], const int32_t rssis[], int count,
                  int selected, int topVisible, int yStart, int rowH) {
  const int maxRows = (112 - yStart) / rowH;
  const int barW = 36;
  const int barH = 8;
  const int textMaxW = SCREEN_W - barW - 14;

  // Clear list area
  tft.fillRect(0, yStart, SCREEN_W, 112 - yStart, COL_BG);

  if (count == 0) {
    printCentered("No networks", yStart + 30, COL_DIM, 1);
    return;
  }

  for (int i = 0; i < maxRows; i++) {
    int idx = topVisible + i;
    if (idx >= count) break;

    int y = yStart + i * rowH;
    bool sel = (idx == selected);

    if (sel) {
      tft.fillRect(2, y, SCREEN_W - 4, rowH - 1, COL_MENU_SEL_BG);
    }

    // SSID (truncate without heap String)
    tft.setTextColor(sel ? COL_MENU_SEL_FG : COL_FG, sel ? COL_MENU_SEL_BG : COL_BG);
    tft.setTextDatum(TL_DATUM);
    char buf[18];
    const char* src = ssids[idx] ? ssids[idx] : "";
    size_t n = 0;
    while (src[n] && n < 15) { buf[n] = src[n]; n++; }
    if (src[n]) { buf[n++] = '.'; }  // truncated
    buf[n] = 0;
    tft.setCursor(6, y + 3);
    tft.print(buf);

    // RSSI bar on the right
    drawRssiBar(SCREEN_W - barW - 4, y + 3, barW, barH, rssis[idx], sel);

    // accent bar
    if (sel) {
      tft.fillRect(0, y, 2, rowH - 1, COL_ACCENT);
    }
  }

  // Scroll arrows
  if (topVisible > 0) {
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setCursor(SCREEN_W - 10, yStart);
    tft.print("^");
  }
  if (topVisible + maxRows < count) {
    tft.setTextColor(COL_DIM, COL_BG);
    tft.setCursor(SCREEN_W - 10, 112 - 12);
    tft.print("v");
  }
}

} // namespace Theme
