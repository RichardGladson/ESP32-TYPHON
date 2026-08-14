#include <Arduino.h>
#include <TFT_eSPI.h>
#include "config.h"

// shared display instance
TFT_eSPI tft = TFT_eSPI();

// initialize shared hardware
void hardwareBegin() {
    tft.init();
    tft.setRotation(TFT_ROTATION);
    tft.fillScreen(BLACK);
}

// clear the display
void hardwareClear() {
    tft.fillScreen(BLACK);
}

// return the shared display instance
TFT_eSPI& hardwareDisplay() {
    return tft;
}
