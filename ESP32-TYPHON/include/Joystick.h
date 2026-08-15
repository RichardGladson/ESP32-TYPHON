#pragma once

#include "BoardConfig.h"

// Direction & action enum
enum JoyAction : uint8_t {
  JOY_NONE = 0,
  JOY_UP,
  JOY_DOWN,
  JOY_LEFT,
  JOY_RIGHT,
  JOY_SELECT,     // short press (fired on release)
  JOY_BACK,       // long press (fired on release)
  JOY_HOLD_UP,    // hold + direction (continuous while held)
  JOY_HOLD_DOWN,
  JOY_HOLD_LEFT,
  JOY_HOLD_RIGHT
};

class Joystick {
public:
  void begin();
  void update();                  // call every loop
  JoyAction getAction();          // returns one-shot action and clears it
  bool isHeld() const { return _held; }
  int16_t rawX() const { return _rawX; }
  int16_t rawY() const { return _rawY; }

private:
  int16_t _rawX = JOY_CENTER;
  int16_t _rawY = JOY_CENTER;
  bool    _btnDown = false;
  bool    _held = false;
  uint32_t _pressStart = 0;
  uint32_t _lastRepeat = 0;
  JoyAction _pending = JOY_NONE;
  JoyAction _lastDir = JOY_NONE;

  JoyAction readDirection() const;
};

extern Joystick joystick;
