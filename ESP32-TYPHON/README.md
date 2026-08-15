# ESP32 TYPHON – ST7735 + Joystick + Soft-AP Web UI

Port of ESP32-DIV focused on 1.8" ST7735 (160x128) + HW-504 joystick.

## Soft-AP Web Mode
- Hold **BOOT** (GPIO0) for **2 seconds** to enter / exit
- Blue LED (GPIO2) turns on while active
- Display shows connection info
- Soft-AP: **SSID `ESP32-1`** · **Password `rgisking`**
- Open **http://192.168.4.1** on phone/laptop
- Full control of every tool **except Captive Portal**
- Exit via BOOT again or the “Exit Web Mode” button on the page

## Tools
Wi-Fi: Scanner, Packet Monitor, Beacon Spammer, Deauth, Deauth Detector, Probe Flood, Captive Portal  
BLE: Scanner, Sniffer, Spoofer, Sour Apple, Jammer, AirTag

## Controls (local UI)
Up/Down = navigate · Short press = Select/Start/Stop · Long press = Back

## Pins
TFT SCK=18 MOSI=23 DC=16 RST=17 CS=5  
Joystick VRX=34 VRY=35 SW=32  
BOOT=0 · Status LED=2

Educational / research use only. Only test networks and devices you own.
