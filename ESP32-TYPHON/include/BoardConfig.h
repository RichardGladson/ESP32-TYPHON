#pragma once

// ============================================================
// BoardConfig.h  –  ESP32-WROOM + ST7735 1.8" + HW-504 Joystick
// ============================================================

#include <Arduino.h>

// -------------------- Display (ST7735 Blacktab 160x128) --------------------
// Pins already defined via platformio.ini build_flags for TFT_eSPI
// Rotation 3 = landscape (160 wide x 128 tall)
#define DISPLAY_ROTATION  3
#define SCREEN_W          160
#define SCREEN_H          128

// -------------------- Joystick (HW-504) --------------------
#define JOY_VRX           34      // ADC1
#define JOY_VRY           35      // ADC1
#define JOY_SW            32      // Digital, active LOW (pull-up)

// -------------------- Boot button + onboard LED --------------------
#define BOOT_BTN          0       // BOOT / GPIO0 (active LOW)
#define STATUS_LED        2       // Blue LED on most ESP32-WROOM DevKits

// Analog center & deadzone (12-bit ADC 0-4095)
#define JOY_CENTER        2048
#define JOY_DEADZONE      400

// Timing
#define JOY_DEBOUNCE_MS       30
#define JOY_SHORT_MS          40     // minimum press to register
#define JOY_LONG_MS           600    // long press threshold
#define JOY_REPEAT_MS         180    // auto-repeat while held+direction

// -------------------- Color Palette (user specified) --------------------
#define BLACK        0x0000
#define LBLUE        0x35FF
#define GREEN        0x0770
#define AQUA         0x05F8
#define RED          0xF800
#define YELLOW       0xF7E0
#define WHITE        0xF7BE
#define GRAY         0xBDD7
#define BLUE         0x001F
#define LGREEN       0x4FE9
#define LAQUA        0x07FF
#define PURPLE       0x881F
#define ORANGE       0xFC60
#define PINK         0xF818

// UI theme shortcuts
#define COL_BG           BLACK
#define COL_FG           WHITE
#define COL_ACCENT       LBLUE
#define COL_HIGHLIGHT    AQUA
#define COL_TITLE        LAQUA
#define COL_DIM          GRAY
#define COL_WARN         ORANGE
#define COL_ERR          RED
#define COL_OK           LGREEN
#define COL_MENU_SEL_BG  0x18C3   // dark blue-ish for selected row
#define COL_MENU_SEL_FG  WHITE
#define COL_BORDER       GRAY

// -------------------- Feature flags (WiFi + BLE only for now) --------------------
#define ENABLE_WIFI_TOOLS     1
#define ENABLE_BLE_TOOLS      1
#define ENABLE_2G4_TOOLS      0
#define ENABLE_SUBGHZ_TOOLS   0
#define ENABLE_IR_TOOLS       0
#define ENABLE_RFID_TOOLS     0
#define ENABLE_GPS_TOOLS      0
#define ENABLE_DUCKY          0
#define ENABLE_SD             0
