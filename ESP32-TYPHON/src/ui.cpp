#include <Arduino.h>
#include <TFT_eSPI.h>
#include "config.h"

// hardware.cpp interface
TFT_eSPI& hardwareDisplay();

static bool uiDirty = true;
static uint16_t currentBackground = BLACK;

void uiBegin() {
    TFT_eSPI& tft = hardwareDisplay();

    tft.fillScreen(BLACK);
    tft.setTextWrap(false);
    tft.setTextFont(1);
    tft.setTextSize(1);
    tft.setTextColor(WHITE, BLACK);

    currentBackground = BLACK;
    uiDirty = true;
}

void uiInvalidate() {
    uiDirty = true;
}

bool uiNeedsRedraw() {
    return uiDirty;
}

void uiMarkClean() {
    uiDirty = false;
}

void uiClear(uint16_t color = BLACK) {
    TFT_eSPI& tft = hardwareDisplay();

    tft.fillScreen(color);
    currentBackground = color;
}

void uiSetTextStyle(uint16_t foreground, uint16_t background = BLACK, uint8_t size = 1) {
    TFT_eSPI& tft = hardwareDisplay();

    tft.setTextColor(foreground, background);
    tft.setTextSize(size);
}

void uiText(int16_t x, int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1) {
    TFT_eSPI& tft = hardwareDisplay();

    tft.setTextColor(color, background);
    tft.setTextSize(size);
    tft.setCursor(x, y);
    tft.print(text);
}

void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1) {
    TFT_eSPI& tft = hardwareDisplay();

    tft.setTextColor(color, background);
    tft.setTextSize(size);

    const int16_t width = tft.textWidth(text);
    const int16_t x = (TFT_WIDTH - width) / 2;

    tft.setCursor(x, y);
    tft.print(text);
}

void uiLine(int16_t x1, int16_t y1, int16_t x2, int16_t y2, uint16_t color = WHITE) {
    hardwareDisplay().drawLine(x1, y1, x2, y2, color);
}

void uiBox(int16_t x, int16_t y, int16_t width, int16_t height, uint16_t outline = WHITE, uint16_t fill = BLACK) {
    TFT_eSPI& tft = hardwareDisplay();

    if (fill != outline) {
        tft.fillRect(x, y, width, height, fill);
    }

    tft.drawRect(x, y, width, height, outline);
}

void uiFillRect(int16_t x, int16_t y, int16_t width, int16_t height, uint16_t color) {
    hardwareDisplay().fillRect(x, y, width, height, color);
}

void uiHeader(const char* title, uint16_t color = LBLUE) {
    TFT_eSPI& tft = hardwareDisplay();

    tft.fillRect(0, 0, TFT_WIDTH, 14, color);
    tft.setTextColor(BLACK, color);
    tft.setTextSize(1);
    tft.setCursor(4, 3);
    tft.print(title);

    tft.drawFastHLine(0, 14, TFT_WIDTH, WHITE);
}

void uiFooter(const char* text, uint16_t color = GRAY) {
    TFT_eSPI& tft = hardwareDisplay();

    const int16_t y = TFT_HEIGHT - 12;

    tft.fillRect(0, y, TFT_WIDTH, 12, BLACK);
    tft.setTextColor(color, BLACK);
    tft.setTextSize(1);
    tft.setCursor(3, y + 2);
    tft.print(text);

    tft.drawFastHLine(0, y - 1, TFT_WIDTH, GRAY);
}

void uiMenuRow(int16_t y, const char* text, bool selected, uint16_t accent = LBLUE) {
    TFT_eSPI& tft = hardwareDisplay();

    const uint16_t background = selected ? accent : BLACK;
    const uint16_t foreground = selected ? BLACK : WHITE;

    tft.fillRect(2, y, TFT_WIDTH - 4, 14, background);
    tft.setTextColor(foreground, background);
    tft.setTextSize(1);
    tft.setCursor(6, y + 3);
    tft.print(text);

    if (selected) {
        tft.drawFastVLine(2, y, 14, WHITE);
        tft.drawFastVLine(TFT_WIDTH - 3, y, 14, WHITE);
    }
}

void uiScrollbar(int16_t x, int16_t y, int16_t height, uint16_t totalItems, uint16_t visibleItems, uint16_t selectedItem) {
    TFT_eSPI& tft = hardwareDisplay();

    if (totalItems <= visibleItems || visibleItems == 0) {
        return;
    }

    tft.drawRect(x, y, 4, height, GRAY);

    const int16_t thumbHeight = max<int16_t>(6, (height * visibleItems) / totalItems);
    const uint16_t maxOffset = totalItems - visibleItems;
    const int16_t maxY = y + height - thumbHeight - 1;
    const int16_t thumbY = y + ((maxY - y) * min<uint16_t>(selectedItem, maxOffset)) / maxOffset;

    tft.fillRect(x + 1, thumbY + 1, 2, thumbHeight - 2, WHITE);
}

void uiProgressBar(int16_t x, int16_t y, int16_t width, int16_t height, uint8_t percent, uint16_t fillColor = GREEN) {
    TFT_eSPI& tft = hardwareDisplay();

    percent = min<uint8_t>(percent, 100);

    tft.drawRect(x, y, width, height, GRAY);

    const int16_t innerWidth = width - 2;
    const int16_t fillWidth = (innerWidth * percent) / 100;

    if (fillWidth > 0) {
        tft.fillRect(x + 1, y + 1, fillWidth, height - 2, fillColor);
    }

    if (fillWidth < innerWidth) {
        tft.fillRect(x + 1 + fillWidth, y + 1, innerWidth - fillWidth, height - 2, BLACK);
    }
}

void uiGraph(int16_t x, int16_t y, int16_t width, int16_t height, const int16_t* values, size_t count, int16_t minValue, int16_t maxValue, uint16_t color = LAQUA) {
    TFT_eSPI& tft = hardwareDisplay();

    if (values == nullptr || count == 0 || width < 2 || height < 2 || minValue >= maxValue) {
        return;
    }

    tft.drawRect(x, y, width, height, GRAY);

    const size_t points = min<size_t>(count, static_cast<size_t>(width - 2));

    if (points == 0) {
        return;
    }

    for (size_t i = 1; i < points; ++i) {
        const size_t previousIndex = count - points + i - 1;
        const size_t currentIndex = count - points + i;

        int32_t previousValue = values[previousIndex];
        int32_t currentValue = values[currentIndex];

        previousValue = constrain(previousValue, minValue, maxValue);
        currentValue = constrain(currentValue, minValue, maxValue);

        const int16_t previousY = y + height - 2 -
            ((previousValue - minValue) * (height - 3)) / (maxValue - minValue);

        const int16_t currentY = y + height - 2 -
            ((currentValue - minValue) * (height - 3)) / (maxValue - minValue);

        const int16_t previousX = x + 1 + static_cast<int16_t>(i - 1);
        const int16_t currentX = x + 1 + static_cast<int16_t>(i);

        tft.drawLine(previousX, previousY, currentX, currentY, color);
    }
}

uint16_t uiBackground() {
    return currentBackground;
}
