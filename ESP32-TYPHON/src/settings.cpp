#include <Arduino.h>
#include <Preferences.h>

// persistent settings storage
static Preferences preferences;

static const char* SETTINGS_NAMESPACE = "esp32div";

void settingsBegin() {
    preferences.begin(SETTINGS_NAMESPACE, false);
}

void settingsEnd() {
    preferences.end();
}

bool settingsGetBool(const char* key, bool defaultValue) {
    return preferences.getBool(key, defaultValue);
}

void settingsSetBool(const char* key, bool value) {
    preferences.putBool(key, value);
}

int32_t settingsGetInt(const char* key, int32_t defaultValue) {
    return preferences.getInt(key, defaultValue);
}

void settingsSetInt(const char* key, int32_t value) {
    preferences.putInt(key, value);
}

uint32_t settingsGetUInt(const char* key, uint32_t defaultValue) {
    return preferences.getUInt(key, defaultValue);
}

void settingsSetUInt(const char* key, uint32_t value) {
    preferences.putUInt(key, value);
}

String settingsGetString(const char* key, const char* defaultValue) {
    return preferences.getString(key, defaultValue);
}

void settingsSetString(const char* key, const String& value) {
    preferences.putString(key, value);
}

bool settingsHasKey(const char* key) {
    return preferences.isKey(key);
}

void settingsClear() {
    preferences.clear();
}
