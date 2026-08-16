/*
 * ESP32 TYPHON – ST7735 + Soft-AP Web UI
 * Target : ESP32-WROOM + 1.8" ST7735 (160x128) + HW-504
 * Scope  : Wi-Fi + BLE tools, minimal UI
 *
 * Original project : https://github.com/cifertech/ESP32-DIV
 * This is a clean PlatformIO rewrite focused on the small display.
 */

#include <Arduino.h>
#include "BoardConfig.h"
#include "Theme.h"
#include "Joystick.h"
#include "UI.h"

void setup() {
  setCpuFrequencyMhz(240);  // max clock
  Serial.begin(115200);
  delay(200);
  Serial.println("\n=== ESP32 TYPHON ===");
  Serial.printf("CPU     : %u MHz\n", getCpuFrequencyMhz());
  Serial.printf("Display : %dx%d rotation %d\n", SCREEN_W, SCREEN_H, DISPLAY_ROTATION);
  Serial.println("Joystick: VRX=34 VRY=35 SW=32");

  ui.begin();
  Serial.println("UI ready.");
}

void loop() {
  ui.loop();
  // Keep loop light – feature tools will add their own work later
  delay(5);   // small yield, keeps UI responsive without busy-spin
}
