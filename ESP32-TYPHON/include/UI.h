#pragma once

#include "BoardConfig.h"
#include "Joystick.h"

// All screens
enum Screen : uint8_t {
  SCR_MAIN = 0,
  SCR_WIFI_MENU,
  SCR_BLE_MENU,
  SCR_WIFI_SCAN,
  SCR_PACKET_MON,
  SCR_BEACON,
  SCR_DEAUTH,
  SCR_CLIENT_SNIFF,
  SCR_DEAUTH_DET,
  SCR_PROBE,
  SCR_CAPTIVE,
  SCR_BLE_SCAN,
  SCR_BLE_SNIFF,
  SCR_BLE_SPOOF,
  SCR_SOUR_APPLE,
  SCR_BLE_JAM,
  SCR_AIRTAG,
  SCR_ABOUT,
  SCR_COUNT
};

class UI {
public:
  void begin();
  void loop();

private:
  Screen  _screen = SCR_MAIN;
  int     _sel = 0;
  int     _top = 0;
  bool    _dirty = true;

  static const char* const MAIN_ITEMS[];
  static const int MAIN_COUNT;
  static const char* const WIFI_ITEMS[];
  static const int WIFI_COUNT;
  static const char* const BLE_ITEMS[];
  static const int BLE_COUNT;

  void handleInput(JoyAction a);
  void drawCurrent();
  void enterScreen(Screen s);
  void goBack();
  void drawWifiScanScreen();
  void drawBleScanScreen();
};

extern UI ui;