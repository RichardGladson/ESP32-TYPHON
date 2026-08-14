#include <Arduino.h>
#include "config.h"

// hardware.cpp
void hardwareBegin();
void hardwareClear();

// input.cpp
void inputBegin();
void inputUpdate();
uint8_t inputGetEvent();

// ui.cpp
void uiBegin();
void uiInvalidate();
bool uiNeedsRedraw();
void uiMarkClean();
void uiClear(uint16_t color = BLACK);
void uiHeader(const char* title, uint16_t color = LBLUE);
void uiFooter(const char* text, uint16_t color = GRAY);
void uiCenteredText(int16_t y, const char* text, uint16_t color = WHITE, uint16_t background = BLACK, uint8_t size = 1);

// settings.cpp
void settingsBegin();
void settingsEnd();

enum InputEvent : uint8_t {
    INPUT_NONE = 0,
    INPUT_UP,
    INPUT_DOWN,
    INPUT_LEFT,
    INPUT_RIGHT,
    INPUT_SELECT,
    INPUT_BACK,
    INPUT_GESTURE_UP,
    INPUT_GESTURE_DOWN,
    INPUT_GESTURE_LEFT,
    INPUT_GESTURE_RIGHT
};

enum AppScreen : uint8_t {
    SCREEN_HOME = 0
};

static AppScreen currentScreen = SCREEN_HOME;

static void drawHomeScreen() {
    uiClear(BLACK);
    uiHeader("ESP32-DIV", LBLUE);
    uiCenteredText(34, "ESP32-DIV-RG", AQUA, BLACK, 1);
    uiCenteredText(50, "WROOM EDITION", WHITE, BLACK, 1);
    uiCenteredText(88, "SELECT TO CONTINUE", GRAY, BLACK, 1);
    uiFooter("UP/DOWN  SELECT");
}

static void handleInput(uint8_t rawEvent) {
    const InputEvent event = static_cast<InputEvent>(rawEvent);

    switch (currentScreen) {
        case SCREEN_HOME:
            if (event == INPUT_SELECT) {
                // tool navigation will be added with the tool modules
                uiInvalidate();
            }
            break;

        default:
            currentScreen = SCREEN_HOME;
            uiInvalidate();
            break;
    }
}

void setup() {
    Serial.begin(115200);

    hardwareBegin();
    inputBegin();
    settingsBegin();
    uiBegin();

    currentScreen = SCREEN_HOME;
    uiInvalidate();
}

void loop() {
    inputUpdate();

    const uint8_t event = inputGetEvent();

    if (event != INPUT_NONE) {
        handleInput(event);
    }

    if (uiNeedsRedraw()) {
        switch (currentScreen) {
            case SCREEN_HOME:
                drawHomeScreen();
                break;

            default:
                currentScreen = SCREEN_HOME;
                drawHomeScreen();
                break;
        }

        uiMarkClean();
    }

    delay(1);
}
