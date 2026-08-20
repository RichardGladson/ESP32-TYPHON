#include "Joystick.h"
#ifndef JOY_LONG_MS
#define JOY_LONG_MS 1000
#endif
#ifndef JOY_VERY_LONG_MS
#define JOY_VERY_LONG_MS 2000
#endif
#ifndef JOY_SHORT_MS
#define JOY_SHORT_MS 40
#endif

Joystick joystick;

void Joystick::begin() {
  pinMode(JOY_SW, INPUT_PULLUP);
  _rawX = analogRead(JOY_VRX);
  _rawY = analogRead(JOY_VRY);
}

JoyAction Joystick::readDirection() const {
  int16_t dx = _rawX - JOY_CENTER;
  int16_t dy = _rawY - JOY_CENTER;
  if (abs(dx) < JOY_DEADZONE && abs(dy) < JOY_DEADZONE)
    return JOY_NONE;
  if (abs(dx) > abs(dy))
    return (dx > 0) ? JOY_RIGHT : JOY_LEFT;
  return (dy > 0) ? JOY_DOWN : JOY_UP;
}

uint32_t Joystick::heldMs() const {
  if (!_btnDown) return 0;
  return millis() - _pressStart;
}

uint8_t Joystick::holdProgress() const {
  if (!_btnDown) return 0;
  uint32_t ms = heldMs();
  if (ms >= JOY_LONG_MS) return 100;
  return (uint8_t)((ms * 100UL) / JOY_LONG_MS);
}

uint8_t Joystick::holdProgress2() const {
  if (!_btnDown) return 0;
  uint32_t ms = heldMs();
  if (ms >= JOY_VERY_LONG_MS) return 100;
  return (uint8_t)((ms * 100UL) / JOY_VERY_LONG_MS);
}

void Joystick::update() {
  _rawX = analogRead(JOY_VRX);
  _rawY = analogRead(JOY_VRY);

  bool btn = (digitalRead(JOY_SW) == LOW);
  uint32_t now = millis();

  if (btn && !_btnDown) {
    _btnDown = true;
    _pressStart = now;
    _held = false;
    _firedBack = false;
    _firedBack2 = false;
    _lastDir = JOY_NONE;
  }
  else if (!btn && _btnDown) {
    uint32_t heldMs = now - _pressStart;
    _btnDown = false;
    // Short press only if we never fired long-back
    if (!_firedBack && !_firedBack2 && heldMs >= JOY_SHORT_MS && heldMs < JOY_LONG_MS) {
      _pending = JOY_SELECT;
    }
    _held = false;
    _firedBack = false;
    _firedBack2 = false;
  }
  else if (btn && _btnDown) {
    uint32_t held = now - _pressStart;
    // Fire BACK once at 1s
    if (!_firedBack && held >= JOY_LONG_MS) {
      _firedBack = true;
      _held = true;
      _pending = JOY_BACK;
    }
    // Fire BACK2 once at 2s
    if (!_firedBack2 && held >= JOY_VERY_LONG_MS) {
      _firedBack2 = true;
      _pending = JOY_BACK2;
    }
    // Direction while held (after long) for hold-repeat
    if (held >= JOY_LONG_MS) {
      JoyAction dir = readDirection();
      if (dir != JOY_NONE && (now - _lastRepeat >= JOY_REPEAT_MS)) {
        _lastRepeat = now;
        switch (dir) {
          case JOY_UP:    _pending = JOY_HOLD_UP;    break;
          case JOY_DOWN:  _pending = JOY_HOLD_DOWN;  break;
          case JOY_LEFT:  _pending = JOY_HOLD_LEFT;  break;
          case JOY_RIGHT: _pending = JOY_HOLD_RIGHT; break;
          default: break;
        }
      }
    }
  }

  if (!_btnDown) {
    JoyAction dir = readDirection();
    if (dir != JOY_NONE && dir != _lastDir) {
      _pending = dir;
      _lastDir = dir;
      _lastRepeat = now;
    } else if (dir == JOY_NONE) {
      _lastDir = JOY_NONE;
    } else if (dir == _lastDir && (now - _lastRepeat >= JOY_REPEAT_MS)) {
      _pending = dir;
      _lastRepeat = now;
    }
  }
}

JoyAction Joystick::getAction() {
  JoyAction a = _pending;
  _pending = JOY_NONE;
  return a;
}
