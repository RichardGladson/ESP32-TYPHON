#ifndef CONFIG_H
#define CONFIG_H

// hardware pins
#define JOYSTICK_VRX 34
#define JOYSTICK_VRY 35
#define JOYSTICK_SW  32

#define TFT_SCK  18
#define TFT_MOSI 23
#define TFT_DC   16
#define TFT_RST  17
#define TFT_CS   5

// display
#define TFT_WIDTH  160
#define TFT_HEIGHT 128
#define TFT_ROTATION 3

// joystick
#define JOYSTICK_CENTER 2048
#define JOYSTICK_DEADZONE 30

// button timing
#define BUTTON_LONG_PRESS_MS 500

// ui colors (rgb565)
#define BLACK   0x0000
#define LBLUE   0x35ff
#define GREEN   0x0770
#define AQUA    0x05f8
#define RED     0xf800
#define YELLOW  0xf7e0
#define WHITE   0xf7be
#define GRAY    0xbdd7
#define BLUE    0x001f
#define LGREEN  0x4fe9
#define LAQUA   0x07ff
#define PURPLE  0x881f
#define ORANGE  0xfc60
#define PINK    0xf818

// ui timing
#define UI_REFRESH_INTERVAL_MS 20

#endif
