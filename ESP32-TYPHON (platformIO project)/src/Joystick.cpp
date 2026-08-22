#include "Joystick.h"

Joystick joystick;

void Joystick::begin() {
  pinMode(JOY_SW, INPUT_PULLUP);
  // Analog pins need no pinMode on ESP32
  _rawX = analogRead(JOY_VRX);
  _rawY = analogRead(JOY_VRY);
}

JoyAction Joystick::readDirection() const {
  int16_t dx = _rawX - JOY_CENTER;
  int16_t dy = _rawY - JOY_CENTER;   // Y not inverted as requested

  if (abs(dx) < JOY_DEADZONE && abs(dy) < JOY_DEADZONE)
    return JOY_NONE;

  // Prefer the axis with larger deviation
  if (abs(dx) > abs(dy)) {
    return (dx > 0) ? JOY_RIGHT : JOY_LEFT;
  } else {
    return (dy > 0) ? JOY_DOWN : JOY_UP;
  }
}

void Joystick::update() {
  _rawX = analogRead(JOY_VRX);
  _rawY = analogRead(JOY_VRY);

  bool btn = (digitalRead(JOY_SW) == LOW);   // active LOW
  uint32_t now = millis();

  // ---------- Button press / release ----------
  if (btn && !_btnDown) {
    // just pressed
    _btnDown = true;
    _pressStart = now;
    _held = false;
    _lastDir = JOY_NONE;
  }
  else if (!btn && _btnDown) {
    // just released
    _btnDown = false;
    uint32_t heldMs = now - _pressStart;

    if (heldMs >= JOY_LONG_MS) {
      _pending = JOY_BACK;
    } else if (heldMs >= JOY_SHORT_MS) {
      _pending = JOY_SELECT;
    }
    _held = false;
  }
  else if (btn && _btnDown) {
    // still held
    uint32_t heldMs = now - _pressStart;
    if (heldMs >= JOY_LONG_MS) {
      _held = true;
      JoyAction dir = readDirection();
      if (dir != JOY_NONE) {
        // map to HOLD_ variants
        if (now - _lastRepeat >= JOY_REPEAT_MS) {
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
  }

  // ---------- Free navigation (no button held) ----------
  if (!_btnDown) {
    JoyAction dir = readDirection();
    if (dir != JOY_NONE && dir != _lastDir) {
      // edge: new direction appeared
      _pending = dir;
      _lastDir = dir;
      _lastRepeat = now;
    } else if (dir == JOY_NONE) {
      _lastDir = JOY_NONE;
    } else if (dir == _lastDir && (now - _lastRepeat >= JOY_REPEAT_MS)) {
      // auto-repeat while stick held in one direction
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
