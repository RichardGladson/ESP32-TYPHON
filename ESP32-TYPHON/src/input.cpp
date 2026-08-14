#include <Arduino.h>
#include "config.h"

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

static const int JOYSTICK_X_CENTER = 2048;
static const int JOYSTICK_Y_CENTER = 2048;

static bool buttonWasPressed = false;
static unsigned long buttonPressStart = 0;

static bool gestureActive = false;
static InputEvent gestureDirection = INPUT_NONE;

static InputEvent pendingEvent = INPUT_NONE;

static int readAxis(int pin, int center) {
    int value = analogRead(pin);
    return value - center;
}

static InputEvent getJoystickDirection() {
    const int x = readAxis(JOYSTICK_VRX, JOYSTICK_X_CENTER);
    const int y = readAxis(JOYSTICK_VRY, JOYSTICK_Y_CENTER);

    const int deadzone = (4095 * JOYSTICK_DEADZONE) / 100;

    if (abs(x) <= deadzone && abs(y) <= deadzone) {
        return INPUT_NONE;
    }

    if (abs(x) > abs(y)) {
        return (x < 0) ? INPUT_LEFT : INPUT_RIGHT;
    }

    return (y < 0) ? INPUT_UP : INPUT_DOWN;
}

void inputBegin() {
    pinMode(JOYSTICK_VRX, INPUT);
    pinMode(JOYSTICK_VRY, INPUT);
    pinMode(JOYSTICK_SW, INPUT_PULLUP);

    analogReadResolution(12);

    buttonWasPressed = false;
    buttonPressStart = 0;
    gestureActive = false;
    gestureDirection = INPUT_NONE;
    pendingEvent = INPUT_NONE;
}

void inputUpdate() {
    const bool buttonPressed = digitalRead(JOYSTICK_SW) == LOW;
    const InputEvent direction = getJoystickDirection();

    if (buttonPressed && !buttonWasPressed) {
        buttonPressStart = millis();
        gestureActive = true;
        gestureDirection = INPUT_NONE;
    }

    if (buttonPressed) {
        if (gestureActive && direction != INPUT_NONE) {
            gestureDirection = direction;
        }
    }

    if (!buttonPressed && buttonWasPressed) {
        const unsigned long pressDuration = millis() - buttonPressStart;

        if (gestureDirection != INPUT_NONE) {
            switch (gestureDirection) {
                case INPUT_UP:
                    pendingEvent = INPUT_GESTURE_UP;
                    break;

                case INPUT_DOWN:
                    pendingEvent = INPUT_GESTURE_DOWN;
                    break;

                case INPUT_LEFT:
                    pendingEvent = INPUT_GESTURE_LEFT;
                    break;

                case INPUT_RIGHT:
                    pendingEvent = INPUT_GESTURE_RIGHT;
                    break;

                default:
                    pendingEvent = INPUT_NONE;
                    break;
            }
        } else if (pressDuration >= BUTTON_LONG_PRESS_MS) {
            pendingEvent = INPUT_BACK;
        } else {
            pendingEvent = INPUT_SELECT;
        }

        gestureActive = false;
        gestureDirection = INPUT_NONE;
    }

    buttonWasPressed = buttonPressed;

    if (!buttonPressed && direction != INPUT_NONE) {
        if (!buttonWasPressed) {
            pendingEvent = direction;
        }
    }
}

uint8_t inputGetEvent() {
    const InputEvent event = pendingEvent;
    pendingEvent = INPUT_NONE;
    return static_cast<uint8_t>(event);
}

bool inputButtonPressed() {
    return digitalRead(JOYSTICK_SW) == LOW;
}
