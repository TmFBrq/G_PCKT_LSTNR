#include <M5Cardputer.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <SD.h>
#include <vector>
#include <set> 
#include <map>

// GLOBAL VARIABLES
#define HOP_INTERVAL 300 
#define MAX_LOG_LINES 4 
#define MAX_MAP_LINES 8 
#define SD_CS 12 

struct LogEntry { String label; int8_t rssi; uint16_t color; };
struct MapEntry { String client; String cVendor; String ap; String aVendor; };

uint8_t waterfall[14][100];
uint8_t ch = 1;
unsigned long lastHop = 0, lastManualShift = 0;
uint32_t total = 0, lastTotal = 0, pps = 0;
uint32_t pkts[3] = {0, 0, 0}; 

uint32_t cDeauth = 0, cDisas = 0, cProbeReq = 0, cProbeRes = 0, cBeacon = 0;
uint32_t cAuth = 0, cAssoc = 0, cEapol = 0, cAction = 0, cRetry = 0;

unsigned long lastStatsUpdate = 0, lastClientClear = 0; 
bool screenOn = true, autoHop = true, beepOn = false;
int uiMode = 0; 

std::set<String> clients; 
std::set<String> globalClients;
std::vector<LogEntry> probeLog;
std::vector<MapEntry> connectionMap; 

String getVendor(String mac) {
  String prefix = mac; prefix.replace(":", ""); prefix = prefix.substring(0, 6); prefix.toUpperCase();
  File file = SD.open("/oui.csv");
  if (!file) return "UNK";
  String found = "UNK";
  long low = 0, high = file.size();
  while (low <= high) {
    long mid = low + (high - low) / 2; file.seek(mid);
    if (mid != 0) file.readStringUntil('\n');
    String line = file.readStringUntil('\n');
    if (line.length() < 7) break;
    String lPrefix = line.substring(0, 6);
    if (lPrefix == prefix) { 
      found = line.substring(7); found.trim(); 
      // Increased to 13 characters for better readability since MACs are gone
      if (found.length() > 13) found = found.substring(0, 13);
      break; 
    } 
    else if (lPrefix < prefix) low = file.position(); else high = mid - 1;
  }
  file.close();
  found.toUpperCase();
  return found;
}

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
  total++;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* payload = pkt->payload;
  uint8_t pType = (payload[0] >> 2) & 0x03;
  uint8_t pSubtype = (payload[0] >> 4) & 0x0F;
  
  if (pType < 3) pkts[pType]++;
  if (payload[1] & 0x08) cRetry++;

  uint8_t intensity = 3; 
  if (pType == 0) { // MGMT
    intensity = 1;
    switch(pSubtype) {
      case 0x00: cAssoc++; break;
      case 0x04: cProbeReq++; break;
      case 0x05: cProbeRes++; break;
      case 0x08: cBeacon++; break;
      case 0x0A: cDisas++; intensity = 4; if (beepOn) M5Cardputer.Speaker.tone(1000, 100); break;
      case 0x0B: cAuth++; break;
      case 0x0C: cDeauth++; intensity = 4; if (beepOn) M5Cardputer.Speaker.tone(2600, 100); break;
      case 0x0D: cAction++; break;
    }
    if (pSubtype == 0x04) {
      int ssidLen = payload[25];
      if (ssidLen > 0 && ssidLen <= 32) {
        char ssid[33]; memcpy(ssid, &payload[26], ssidLen); ssid[ssidLen] = '\0';
        probeLog.insert(probeLog.begin(), {String(ssid), pkt->rx_ctrl.rssi, 0xFFE0}); 
        if (probeLog.size() > MAX_LOG_LINES) probeLog.pop_back();
      }
    }
  }

  if (pType == 2) { // DATA
    if (payload[30] == 0x88 && payload[31] == 0x8E) {
      cEapol++;
      if (beepOn) { M5Cardputer.Speaker.tone(5000, 40); delay(5); M5Cardputer.Speaker.tone(6000, 40); }
    }
    char src[18], bssid[18];
    sprintf(src, "%02X:%02X:%02X:%02X:%02X:%02X", payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);
    sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", payload[16], payload[17], payload[18], payload[19], payload[20], payload[21]);
    String cleanSrc = String(src);
    bool exists = false;
    for(auto &m : connectionMap) { if(m.client == cleanSrc) { exists = true; break; } }
    if (!exists) {
      connectionMap.insert(connectionMap.begin(), {cleanSrc, getVendor(cleanSrc), String(bssid), getVendor(String(bssid))});
      if (connectionMap.size() > MAX_MAP_LINES) connectionMap.pop_back();
    }
  }

  if (ch >= 1 && ch <= 14) { if (intensity > waterfall[ch-1][0]) waterfall[ch-1][0] = intensity; }
  char srcMac[18]; sprintf(srcMac, "%02X:%02X:%02X", payload[10], payload[11], payload[12]);
  clients.insert(String(srcMac)); globalClients.insert(String(srcMac));
}

void setup() {
  setCpuFrequencyMhz(160); auto cfg = M5.config(); M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setRotation(1); M5Cardputer.Display.fillScreen(BLACK);
  memset(waterfall, 0, sizeof(waterfall));
  if (!SD.begin(SD_CS, SPI, 40000000)) M5Cardputer.Display.println("SD ERROR!");
  WiFi.mode(WIFI_STA); esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void loop() {
  M5Cardputer.update();
  if (M5Cardputer.BtnA.wasPressed()) { screenOn = !screenOn; M5Cardputer.Display.setBrightness(screenOn ? 100 : 0); if (screenOn) M5Cardputer.Display.fillScreen(BLACK); }
  if (millis() - lastStatsUpdate > 1000) { pps = total - lastTotal; lastTotal = total; lastStatsUpdate = millis(); if (millis() - lastClientClear > 60000) { clients.clear(); lastClientClear = millis(); } }

  if (!autoHop && (millis() - lastManualShift > HOP_INTERVAL)) {
    for (int y = 99; y > 0; y--) { waterfall[ch-1][y] = waterfall[ch-1][y-1]; }
    waterfall[ch-1][0] = 0; lastManualShift = millis();
  }

  if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
    if (M5Cardputer.Keyboard.isKeyPressed(' ')) autoHop = !autoHop;
    if (M5Cardputer.Keyboard.isKeyPressed('b')) beepOn = !beepOn;
    if (M5Cardputer.Keyboard.isKeyPressed('m')) { uiMode = 1; M5Cardputer.Display.fillScreen(BLACK); }
    if (M5Cardputer.Keyboard.isKeyPressed('i')) { uiMode = 2; M5Cardputer.Display.fillScreen(BLACK); }
    if (M5Cardputer.Keyboard.isKeyPressed('w')) { uiMode = 3; M5Cardputer.Display.fillScreen(BLACK); }
    if (M5Cardputer.Keyboard.isKeyPressed('s')) { uiMode = 0; M5Cardputer.Display.fillScreen(BLACK); }
    if (!autoHop) {
      if (M5Cardputer.Keyboard.isKeyPressed(';')) ch = (ch >= 13) ? 1 : ch + 1;
      if (M5Cardputer.Keyboard.isKeyPressed('.')) ch = (ch <= 1) ? 13 : ch - 1;
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    }
  }

  if (autoHop && (millis() - lastHop > HOP_INTERVAL)) {
    uint8_t oldCh = ch; for (int y = 99; y > 0; y--) { waterfall[oldCh-1][y] = waterfall[oldCh-1][y-1]; } waterfall[oldCh-1][0] = 0; 
    ch = (ch % 13) + 1; esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE); lastHop = millis();
  }

  if (screenOn) {
    M5Cardputer.Display.startWrite();
    M5Cardputer.Display.setTextSize(1); M5Cardputer.Display.setCursor(0, 0);
    uint16_t headCol = (uiMode == 1) ? MAGENTA : (uiMode == 2 ? 0x07E0 : (uiMode == 3 ? CYAN : YELLOW));
    M5Cardputer.Display.setTextColor(headCol, BLACK);
    const char* modes[] = {"STAT", "MAP ", "INSP", "SPEC"};
    M5Cardputer.Display.printf("%s :%02d ", modes[uiMode], ch);
    M5Cardputer.Display.setTextColor(beepOn ? RED : DARKGREY, BLACK); M5Cardputer.Display.print("[BEEP]");
    M5Cardputer.Display.setTextColor(WHITE, BLACK); M5Cardputer.Display.printf(" PK:%-6d ", total);
    M5Cardputer.Display.drawFastHLine(0, 10, 240, WHITE);

    if (uiMode == 0) { // STAT
      M5Cardputer.Display.setCursor(0, 14); M5Cardputer.Display.setTextColor(0x07FF, BLACK); 
      M5Cardputer.Display.printf("M:%-4d D:%-4d R:%-4d", pkts[0], pkts[2], cRetry);
      M5Cardputer.Display.setTextSize(2); M5Cardputer.Display.setCursor(0, 30); 
      M5Cardputer.Display.setTextColor(GREEN, BLACK); M5Cardputer.Display.printf("DEV:%-3d", clients.size());
      M5Cardputer.Display.setCursor(125, 30); M5Cardputer.Display.setTextColor(CYAN, BLACK); M5Cardputer.Display.printf("GLO:%-3d", globalClients.size());
      M5Cardputer.Display.setCursor(0, 50); M5Cardputer.Display.setTextColor(RED, BLACK); 
      M5Cardputer.Display.printf("DE:%-3d DI:%-3d PPS:%-4d", cDeauth, cDisas, pps);
      M5Cardputer.Display.drawFastHLine(0, 72, 240, DARKGREY); M5Cardputer.Display.setTextSize(1); M5Cardputer.Display.setCursor(160, 76); M5Cardputer.Display.print("PROBE LOG");
      for (int i = 0; i < MAX_LOG_LINES; i++) { M5Cardputer.Display.setCursor(0, 86 + (i * 11)); if (i < (int)probeLog.size()) { M5Cardputer.Display.setTextColor(probeLog[i].color, BLACK); M5Cardputer.Display.printf("[%3d] %s", probeLog[i].rssi, probeLog[i].label.c_str()); } }
    } 
    else if (uiMode == 1) { // MAP (VENDORS ONLY)
      M5Cardputer.Display.setCursor(0, 14); M5Cardputer.Display.setTextColor(WHITE, BLACK); 
      M5Cardputer.Display.println(" CLIENT VENDOR        >   AP VENDOR");
      M5Cardputer.Display.drawFastHLine(0, 24, 240, DARKGREY);
      for (int i = 0; i < MAX_MAP_LINES; i++) { 
        if (i < (int)connectionMap.size()) { 
          M5Cardputer.Display.setCursor(0, 28 + (i * 12)); 
          M5Cardputer.Display.setTextColor(GREEN, BLACK); 
          M5Cardputer.Display.printf("%-15s", connectionMap[i].cVendor.c_str()); 
          M5Cardputer.Display.setTextColor(DARKGREY, BLACK); M5Cardputer.Display.print(" > "); 
          M5Cardputer.Display.setTextColor(CYAN, BLACK); 
          M5Cardputer.Display.printf("%-15s", connectionMap[i].aVendor.c_str()); 
        } 
      }
    }
    // ... (INSP and SPEC modes remain identical to your previous version)
    else if (uiMode == 2) { // INSP
      M5Cardputer.Display.setCursor(0, 14); M5Cardputer.Display.setTextColor(0x07E0, BLACK); M5Cardputer.Display.println(" FRAME SUBTYPE INSPECTOR");
      M5Cardputer.Display.drawFastHLine(0, 24, 240, DARKGREY);
      M5Cardputer.Display.setCursor(0, 30); M5Cardputer.Display.setTextColor(WHITE, BLACK);
      M5Cardputer.Display.printf("BEACON:   %-6d  PROBE REQ: %-6d\n", cBeacon, cProbeReq);
      M5Cardputer.Display.printf("AUTH:     %-6d  PROBE RES: %-6d\n", cAuth, cProbeRes);
      M5Cardputer.Display.printf("ASSOC:    %-6d  ACTION:    %-6d\n", cAssoc, cAction);
      M5Cardputer.Display.printf("RETRY:    %-6d  EAPOL:     %-6d\n", cRetry, cEapol);
      M5Cardputer.Display.setCursor(0, 85); M5Cardputer.Display.setTextColor(RED, BLACK);
      M5Cardputer.Display.printf("DEAUTH:   %-6d  DISASSOC:  %-6d\n", cDeauth, cDisas);
      M5Cardputer.Display.drawFastHLine(0, 110, 240, DARKGREY);
      M5Cardputer.Display.setCursor(0, 115); M5Cardputer.Display.setTextColor(YELLOW, BLACK);
      M5Cardputer.Display.printf("TOTAL MGMT: %-6d DATA: %-6d", pkts[0], pkts[2]);
    } 
    else if (uiMode == 3) { // SPEC (Waterfall)
      M5Cardputer.Display.setCursor(0, 13); M5Cardputer.Display.setTextColor(YELLOW, BLACK); M5Cardputer.Display.print("MGMT "); M5Cardputer.Display.setTextColor(BLUE, BLACK); M5Cardputer.Display.print("DATA "); M5Cardputer.Display.setTextColor(RED, BLACK); M5Cardputer.Display.print("DEA/DIS");
      M5Cardputer.Display.drawFastHLine(0, 22, 240, DARKGREY); int cw = 17;
      for (int c = 0; c < 14; c++) { 
        M5Cardputer.Display.setTextColor(c == (ch-1) ? GREEN : DARKGREY, BLACK); M5Cardputer.Display.setCursor(c * cw + 4, 126); M5Cardputer.Display.printf("%d", c + 1); 
        for (int y = 0; y < 98; y++) { 
          uint16_t color = (waterfall[c][y]==1)?YELLOW:((waterfall[c][y]==3)?BLUE:((waterfall[c][y]==4)?RED:BLACK)); 
          if (color != BLACK || (y==0 && c==(ch-1))) M5Cardputer.Display.fillRect(c * cw + 1, 24 + y, cw - 2, 1, color); 
        } 
      }
    }
    M5Cardputer.Display.endWrite();
  }
  delay(5); 
}