#pragma once
#include "BoardConfig.h"

enum JoyAction : uint8_t {
  JOY_NONE = 0,
  JOY_UP, JOY_DOWN, JOY_LEFT, JOY_RIGHT,
  JOY_SELECT,
  JOY_BACK,
  JOY_BACK2,
  JOY_HOLD_UP, JOY_HOLD_DOWN, JOY_HOLD_LEFT, JOY_HOLD_RIGHT
};

class Joystick {
public:
  void begin();
  void update();
  JoyAction getAction();
  bool isHeld() const { return _held; }
  bool isButtonDown() const { return _btnDown; }
  uint8_t holdProgress() const;
  uint8_t holdProgress2() const;
  uint32_t heldMs() const;
  int16_t rawX() const { return _rawX; }
  int16_t rawY() const { return _rawY; }
private:
  int16_t _rawX = JOY_CENTER, _rawY = JOY_CENTER;
  bool _btnDown = false, _held = false, _firedBack = false, _firedBack2 = false;
  uint32_t _pressStart = 0, _lastRepeat = 0;
  JoyAction _pending = JOY_NONE, _lastDir = JOY_NONE;
  JoyAction readDirection() const;
};
extern Joystick joystick;