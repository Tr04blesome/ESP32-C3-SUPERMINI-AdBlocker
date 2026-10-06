// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include <time.h>
#include "lwip/etharp.h"
#include "lwip/netif.h"
#if defined(WEBFLASHER_BUILD)
static const char* WIFI_SSID = "";
static const char* WIFI_PASS = "";
#else
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)
#endif

// ---- config ----
static const char* FIRMWARE_VERSION = "1.1.0";
static const IPAddress UPSTREAM(9, 9, 9, 9);     // Quad9
static const IPAddress WIFI_STATIC_IP(192, 168, 1, 99);
static const IPAddress WIFI_SUBNET(255, 255, 255, 0);
static bool staticIpEnabled = true;
static IPAddress configuredStaticIp = WIFI_STATIC_IP;
static uint32_t wifiReconnectAtMs = 0;
static uint32_t wifiReconnectDelayMs = 1000;
static bool statusLedKnown = false;
static bool statusLedLast = false;
static bool parseStaticIp(const String& value, IPAddress& address) {
  return address.fromString(value) && address[0] == 192 && address[1] == 168 && address[3] >= 2 && address[3] <= 254;
}
static IPAddress staticIpGateway(const IPAddress& address) {
  return IPAddress(address[0], address[1], address[2], 1);
}
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// ---- globals ----
static constexpr int WIFI_LED_PIN = 8;  // C3 Super Mini user LED is on GPIO8; GPIO9 is the BOOT button
static constexpr uint8_t WIFI_LED_ON_LEVEL = LOW;
static constexpr uint8_t WIFI_LED_OFF_LEVEL = HIGH;

WiFiUDP dnsServer, upstreamCli, hostnameDns;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[600];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool adblockExcluded, banPlusSpared; String label; String hostname; };
static const int MAX_CLIENTS = 192;
Dev clients[MAX_CLIENTS]; int numClients = 0;
static constexpr uint32_t CLIENT_IDLE_TIMEOUT_MS = 24UL * 60UL * 60UL * 1000UL;
static constexpr uint32_t CLIENT_MAINTENANCE_INTERVAL_MS = 60UL * 1000UL;
static uint32_t lastClientMaintenanceMs = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;
static const int MAX_ALLOW = 100;
String allowDom[MAX_ALLOW]; int numAllow = 0;

static const int MAX_CLIENT_FLAGS = 32;
uint32_t adblockExcludedIP[MAX_CLIENT_FLAGS]; int numAdblockExcluded = 0;
uint32_t banPlusSparedIP[MAX_CLIENT_FLAGS]; int numBanPlusSpared = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
bool     connectionLedOn = true;
bool     ledScheduleEnabled = false;
uint16_t ledScheduleStart = 480;
uint16_t ledScheduleStop = 1320;
int8_t   ledScheduleOverride = -1;
bool     ledScheduleWindowKnown = false;
bool     ledScheduleWindowLast = false;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused
bool banPlusOn = false;
uint32_t banPlusResumeAt = 0;
int8_t banPlusOverride = -1;
bool scheduleEnabled = false;
bool scheduleAdblock = false;
bool scheduleBanPlus = false;
uint16_t scheduleStart = 480;
uint16_t scheduleStop = 1320;
uint16_t schedulePlusStart = 480;
uint16_t schedulePlusStop = 1320;
int16_t scheduleTz = 0;
int8_t scheduleOverride = -1; // -1 follows schedule, 0 forces off, 1 forces on
bool scheduleWindowKnown = false;
bool scheduleWindowLast = false;
bool schedulePlusWindowKnown = false;
bool schedulePlusWindowLast = false;

static int localMinutes() {
  time_t now = time(nullptr);
  if (now < 100000) return -1;
  struct tm utc;
  gmtime_r(&now, &utc);
  int minutes = utc.tm_hour * 60 + utc.tm_min + scheduleTz;
  while (minutes < 0) minutes += 1440;
  while (minutes >= 1440) minutes -= 1440;
  return minutes;
}
static bool scheduleWindowActive(uint16_t start, uint16_t stop, bool enabled) {
  if (!enabled) return false;
  int now = localMinutes();
  if (now < 0 || start == stop) return true;
  if (start < stop) return now >= start && now < stop;
  return now >= start || now < stop;
}
static bool schedulePlusWindowActive() {
  return scheduleWindowActive(schedulePlusStart, schedulePlusStop, scheduleBanPlus);
}
static bool adblockScheduleEnabled() {
  return scheduleEnabled && scheduleAdblock;
}
static bool ledScheduleActive() {
  return scheduleWindowActive(ledScheduleStart, ledScheduleStop, ledScheduleEnabled);
}
static void updateLedScheduleState() {
  bool active = ledScheduleActive();
  if (active != ledScheduleWindowLast || !ledScheduleWindowKnown) {
    if (ledScheduleWindowKnown && active != ledScheduleWindowLast) ledScheduleOverride = -1;
    ledScheduleWindowKnown = true;
    ledScheduleWindowLast = active;
  }
}
static bool ledControlOn() {
  if (ledScheduleOverride >= 0) return ledScheduleOverride == 1;
  return ledScheduleEnabled ? ledScheduleActive() : connectionLedOn;
}
static void updateScheduleState() {
  bool active = scheduleWindowActive(scheduleStart, scheduleStop, adblockScheduleEnabled());
  if (active != scheduleWindowLast || !scheduleWindowKnown) {
    if (adblockScheduleEnabled()) { blockingOn = active; scheduleOverride = -1; }
  }
  bool activePlus = schedulePlusWindowActive();
  if (activePlus != schedulePlusWindowLast || !schedulePlusWindowKnown) {
    if (scheduleBanPlus) { banPlusOn = activePlus; banPlusOverride = -1; }
  }
  scheduleWindowKnown = true; scheduleWindowLast = active;
  schedulePlusWindowKnown = true; schedulePlusWindowLast = activePlus;
  updateLedScheduleState();
}
static bool featureActive(bool manualOn, bool scheduled) {
  return manualOn && (!scheduled || scheduleWindowActive(scheduleStart, scheduleStop, true));
}
static bool blockingActive() { return scheduleOverride >= 0 ? scheduleOverride == 1 : featureActive(blockingOn, adblockScheduleEnabled()); }
static bool banPlusActive() {
  if (banPlusOverride >= 0) return banPlusOverride == 1;
  return banPlusOn && (!scheduleBanPlus || schedulePlusWindowActive());
}

static void loadSchedule() {
  File f = LittleFS.open("/schedule.cfg", "r"); if (!f) return;
  String lines[9]; int count = 0;
  while (f.available() && count < 9) { lines[count] = f.readStringUntil('\n'); lines[count].trim(); count++; }
  if (count >= 9) {
    scheduleEnabled = lines[0] == "1"; scheduleAdblock = lines[1] == "1"; scheduleBanPlus = lines[3] == "1";
    scheduleStart = constrain(lines[4].toInt(), 0, 1439); scheduleStop = constrain(lines[5].toInt(), 0, 1439); scheduleTz = constrain(lines[6].toInt(), -840, 840);
    schedulePlusStart = constrain(lines[7].toInt(), 0, 1439); schedulePlusStop = constrain(lines[8].toInt(), 0, 1439);
  } else {
    scheduleEnabled = lines[0] == "1";
    scheduleAdblock = scheduleEnabled;
    if (count > 1) scheduleStart = constrain(lines[1].toInt(), 0, 1439);
    if (count > 2) scheduleStop = constrain(lines[2].toInt(), 0, 1439);
    if (count > 3) scheduleTz = constrain(lines[3].toInt(), -840, 840);
    schedulePlusStart = scheduleStart; schedulePlusStop = scheduleStop;
  }
  f.close();
}
static void saveSchedule() {
  File f = LittleFS.open("/schedule.cfg", "w"); if (!f) return;
  f.println(scheduleEnabled ? 1 : 0); f.println(scheduleAdblock ? 1 : 0); f.println(scheduleBanPlus ? 1 : 0); f.println(scheduleBanPlus ? 1 : 0);
  f.println(scheduleStart); f.println(scheduleStop); f.println(scheduleTz); f.println(schedulePlusStart); f.println(schedulePlusStop); f.close();
}
static void loadLedSchedule() {
  File f = LittleFS.open("/ledschedule.cfg", "r"); if (!f) return;
  String enabled = f.readStringUntil('\n'); enabled.trim();
  String start = f.readStringUntil('\n'); start.trim();
  String stop = f.readStringUntil('\n'); stop.trim();
  ledScheduleEnabled = enabled == "1";
  if (start.length()) ledScheduleStart = constrain(start.toInt(), 0, 1439);
  if (stop.length()) ledScheduleStop = constrain(stop.toInt(), 0, 1439);
  f.close();
}
static void saveLedSchedule() {
  File f = LittleFS.open("/ledschedule.cfg", "w"); if (!f) return;
  f.println(ledScheduleEnabled ? 1 : 0); f.println(ledScheduleStart); f.println(ledScheduleStop); f.close();
}
static void loadManualState() {
  prefs.begin("control", false);
  blockingOn = prefs.getBool("adblock", true);
  connectionLedOn = prefs.getBool("conn-led", true);
  bool banPlusStateMigrated = prefs.getBool("banplus-v2", false);
  banPlusOn = banPlusStateMigrated ? prefs.getBool("banplus", false) : false;
  prefs.putBool("banplus-v2", true);
  prefs.end();
}
static void saveManualState() {
  prefs.begin("control", false); prefs.putBool("adblock", blockingOn); prefs.putBool("banplus", banPlusOn); prefs.putBool("conn-led", connectionLedOn); prefs.end();
}

static bool isBanPlusSparedIP(uint32_t ip) { for (int i = 0; i < numBanPlusSpared; i++) if (banPlusSparedIP[i] == ip) return true; return false; }
static void loadBanPlusSpared() {
  numBanPlusSpared = 0; File f = LittleFS.open("/banplus_spared.txt", "r"); if (!f) return;
  while (f.available() && numBanPlusSpared < MAX_CLIENT_FLAGS) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) banPlusSparedIP[numBanPlusSpared++] = (uint32_t)ip; }
  f.close();
}
static void saveBanPlusSpared() {
  numBanPlusSpared = 0;
  for (int i = 0; i < numClients && numBanPlusSpared < MAX_CLIENT_FLAGS; i++) if (clients[i].banPlusSpared) banPlusSparedIP[numBanPlusSpared++] = clients[i].ip;
  File f = LittleFS.open("/banplus_spared.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanPlusSpared; i++) { IPAddress ip(banPlusSparedIP[i]); f.println(ip.toString()); }
  f.close();
}

static String lookupHostname(uint32_t ip) {
  IPAddress address(ip); IPAddress dns = WiFi.dnsIP();
  if ((uint32_t)dns == 0) return "";
  uint8_t query[100] = {}; uint16_t id = (uint16_t)esp_random();
  query[0] = id >> 8; query[1] = id; query[2] = 1; query[5] = 1;
  String reverse = String(address[3]) + "." + address[2] + "." + address[1] + "." + address[0] + ".in-addr.arpa";
  int pos = 12, start = 0;
  while (start < reverse.length()) { int dot = reverse.indexOf('.', start); if (dot < 0) dot = reverse.length(); query[pos++] = dot - start; for (int i = start; i < dot; i++) query[pos++] = reverse[i]; start = dot + 1; }
  query[pos++] = 0; query[pos++] = 0; query[pos++] = 12; query[pos++] = 0; query[pos++] = 1;
  hostnameDns.begin(0); hostnameDns.beginPacket(dns, 53); hostnameDns.write(query, pos); hostnameDns.endPacket();
  uint32_t until = millis() + 500;
  while ((int32_t)(millis() - until) < 0) {
    int size = hostnameDns.parsePacket(); if (size < 12) { delay(2); continue; }
    uint8_t response[512]; size = hostnameDns.read(response, sizeof(response));
    if (size < 12 || response[0] != query[0] || response[1] != query[1] || !(response[2] & 0x80)) return "";
    int offset = pos;
    uint16_t answers = (response[6] << 8) | response[7];
    for (int n = 0; n < answers && offset + 12 <= size; n++) {
      if (response[offset] & 0xC0) offset += 2; else { while (offset < size && response[offset++]); }
      if (offset + 10 > size) break;
      uint16_t type = (response[offset] << 8) | response[offset + 1]; uint16_t length = (response[offset + 8] << 8) | response[offset + 9]; offset += 10;
      if (type == 12 && offset + length <= size && length > 0) {
        int p = offset; String name;
        while (p < offset + length && response[p]) { if (response[p] & 0xC0) { p = ((response[p] & 0x3F) << 8) | response[p + 1]; continue; } int count = response[p++]; if (name.length()) name += '.'; while (count-- && p < size) name += (char)response[p++]; }
        if (name.length()) return name;
      }
      offset += length;
    }
    return "";
  }
  return "";
}

// ---------- status LEDs ----------
static bool isWifiConnected() {
  return WiFi.getMode() == WIFI_STA && WiFi.isConnected();
}
static void maintainWifiConnection() {
  if (WiFi.getMode() != WIFI_STA) return;
  uint32_t now = millis();
  if (isWifiConnected()) {
    wifiReconnectAtMs = 0;
    wifiReconnectDelayMs = 1000;
    return;
  }
  if (wifiReconnectAtMs && (int32_t)(now - wifiReconnectAtMs) < 0) return;
  Serial.printf("[wifi] disconnected; reconnecting (next backoff %lu ms)\n", wifiReconnectDelayMs);
  WiFi.reconnect();
  wifiReconnectAtMs = now + wifiReconnectDelayMs;
  wifiReconnectDelayMs = wifiReconnectDelayMs < 15000 ? wifiReconnectDelayMs * 2 : 30000;
}

static void setWifiLed(bool on) {
  digitalWrite(WIFI_LED_PIN, on ? WIFI_LED_ON_LEVEL : WIFI_LED_OFF_LEVEL);
}
static void updateStatusLeds() {
  const bool wifiConnected = isWifiConnected();
  const bool ledOn = wifiConnected ? ledControlOn() : ((millis() / 1000UL) % 2 == 0);
  if (!statusLedKnown || ledOn != statusLedLast) {
    setWifiLed(ledOn);
    statusLedLast = ledOn;
    statusLedKnown = true;
  }
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1; uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    blocklist.seek((uint32_t)mid * HASH_BYTES); blocklist.read(b, HASH_BYTES);
    uint64_t v = 0; for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}
static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inFlash(h) || inCustom(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}
static bool isDohProvider(const char* domain) {
  static const char* providers[] = {
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.google", "dns.quad9.net",
    "doh.opendns.com", "dns.nextdns.io", "doh.cleanbrowsing.org", "doh.sb",
    "doh.tiar.app", "doh.dns.sb", "doh.familyshield.opendns.com", "dns.adguard.com",
    "dns-family.adguard.com", "dns-unfiltered.adguard.com"
  };
  for (const char* provider : providers) {
    size_t length = strlen(provider), domainLength = strlen(domain);
    if (domainLength >= length && strcasecmp(domain + domainLength - length, provider) == 0 &&
        (domainLength == length || domain[domainLength - length - 1] == '.')) return true;
  }
  return false;
}
static bool isAllowedDomain(const char* domain) {
  for (int i = 0; i < numAllow; i++) {
    size_t allowedLength = allowDom[i].length(), domainLength = strlen(domain);
    if (domainLength >= allowedLength && strcasecmp(domain + domainLength - allowedLength, allowDom[i].c_str()) == 0 &&
        (domainLength == allowedLength || domain[domainLength - allowedLength - 1] == '.')) return true;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static void loadAllowlist() {
  numAllow = 0; File f = LittleFS.open("/banplus_allow.txt", "r"); if (!f) return;
  while (f.available() && numAllow < MAX_ALLOW) { String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase(); if (l.length() && l.indexOf('.') > 0) allowDom[numAllow++] = l; }
  f.close();
}
static void saveAllowlist() { File f = LittleFS.open("/banplus_allow.txt", "w"); if (!f) return; for (int i = 0; i < numAllow; i++) f.println(allowDom[i]); f.close(); }
static bool addAllowed(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numAllow >= MAX_ALLOW) return false;
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) return false;
  allowDom[numAllow++] = d; saveAllowlist(); return true;
}
static void removeAllowed(String d) {
  d.toLowerCase();
  for (int i = 0; i < numAllow; i++) if (allowDom[i] == d) { for (int j = i; j < numAllow - 1; j++) allowDom[j] = allowDom[j + 1]; numAllow--; saveAllowlist(); return; }
}
static bool isAdblockExcludedIP(uint32_t ip) { for (int i = 0; i < numAdblockExcluded; i++) if (adblockExcludedIP[i] == ip) return true; return false; }
static void loadAdblockExcluded() {
  numAdblockExcluded = 0; File f = LittleFS.open("/adblock_excluded.txt", "r"); if (!f) return;
  while (f.available() && numAdblockExcluded < MAX_CLIENT_FLAGS) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) adblockExcludedIP[numAdblockExcluded++] = (uint32_t)ip; }
  f.close();
}
static void saveAdblockExcluded() {
  numAdblockExcluded = 0;
  for (int i = 0; i < numClients && numAdblockExcluded < MAX_CLIENT_FLAGS; i++) if (clients[i].adblockExcluded) adblockExcludedIP[numAdblockExcluded++] = clients[i].ip;
  File f = LittleFS.open("/adblock_excluded.txt", "w"); if (!f) return;
  for (int i = 0; i < numAdblockExcluded; i++) { IPAddress ip(adblockExcludedIP[i]); f.println(ip.toString()); }
  f.close();
}
static String loadHostName(uint32_t ip) {
  File f = LittleFS.open("/hosts.txt", "r"); if (!f) return "";
  String key = IPAddress(ip).toString();
  while (f.available()) {
    String line = f.readStringUntil('\n'); line.trim(); int split = line.indexOf('|');
    if (split > 0 && line.substring(0, split) == key) { String name = line.substring(split + 1); f.close(); return name; }
  }
  f.close(); return "";
}
static void saveHostName(uint32_t ip, const String& name) {
  String key = IPAddress(ip).toString(), content;
  File in = LittleFS.open("/hosts.txt", "r");
  while (in && in.available()) {
    String line = in.readStringUntil('\n'); line.trim(); if (!line.length() || line.startsWith(key + "|")) continue;
    content += line + "\n";
  }
  if (in) in.close();
  if (name.length()) content += key + "|" + name + "\n";
  File out = LittleFS.open("/hosts.txt", "w"); if (out) { out.print(content); out.close(); }
}

// ---------- client table ----------
static bool clientHasException(const Dev& client) {
  return client.adblockExcluded || client.banPlusSpared;
}
static void removeClientAt(int index) {
  for (int i = index; i < numClients - 1; i++) clients[i] = clients[i + 1];
  int last = --numClients;
  clients[last].label = "";
  clients[last].hostname = "";
  clients[last].ip = 0;
}
static void maintainClients() {
  uint32_t now = millis();
  if ((uint32_t)(now - lastClientMaintenanceMs) < CLIENT_MAINTENANCE_INTERVAL_MS) return;
  lastClientMaintenanceMs = now;
  for (int i = 0; i < numClients;) {
    if (!clientHasException(clients[i]) && (uint32_t)(now - clients[i].lastSeen) >= CLIENT_IDLE_TIMEOUT_MS) removeClientAt(i);
    else i++;
  }
}
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  maintainClients();
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients >= MAX_CLIENTS) {
    int oldestIndex = -1;
    uint32_t oldestAge = 0;
    uint32_t now = millis();
    for (int i = 0; i < numClients; i++) {
      if (clientHasException(clients[i])) continue;
      uint32_t age = now - clients[i].lastSeen;
      if (oldestIndex < 0 || age > oldestAge) { oldestIndex = i; oldestAge = age; }
    }
    if (oldestIndex >= 0) removeClientAt(oldestIndex);
  }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->adblockExcluded = isAdblockExcludedIP(ip); c->banPlusSpared = isBanPlusSparedIP(ip); c->label = ""; c->hostname = loadHostName(ip);
    if (!c->hostname.length()) {
      String discoveredHostname = lookupHostname(ip);
      String normalizedHostname = discoveredHostname; normalizedHostname.replace('-', '.');
      IPAddress parsedHostname;
      if (!parsedHostname.fromString(discoveredHostname) && !parsedHostname.fromString(normalizedHostname)) c->hostname = discoveredHostname;
    }
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = qtype == 1 ? 0x80 : 0x83; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int forwardUpstream(int qlen) {
  upstreamCli.beginPacket(UPSTREAM, 53); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 250) { int sz = upstreamCli.parsePacket(); if (sz > 0) return upstreamCli.read(buf, sizeof(buf)); delay(1); }
  return 0;
}
// Handle one DNS query per pass so upstream timeouts cannot starve dashboard requests.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 1; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool advancedBan = c && banPlusActive() && !c->banPlusSpared && (!dl || !isAllowedDomain(domain));
    bool blocked = advancedBan || ((!c || !c->adblockExcluded) && blockingActive() && dl && ((numHashes && isBlocked(domain)) || isDohProvider(domain)));
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"version\":\"" + String(FIRMWARE_VERSION) + "\",\"ip\":\"" + WiFi.localIP().toString() + "\",\"staticIpEnabled\":" + (staticIpEnabled ? "true" : "false") +
             ",\"staticIp\":\"" + configuredStaticIp.toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingActive() ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"schedule\":" + (scheduleEnabled ? "true" : "false") +
             ",\"scheduleAdblock\":" + (scheduleAdblock ? "true" : "false") +
             ",\"scheduleBanPlus\":" + (scheduleBanPlus ? "true" : "false") +
             ",\"manualAdblock\":" + (blockingOn ? "true" : "false") + ",\"banPlusOn\":" + (banPlusOn ? "true" : "false") +
             ",\"connectionLed\":" + (ledControlOn() ? "true" : "false") +
             ",\"ledScheduleEnabled\":" + (ledScheduleEnabled ? "true" : "false") + ",\"ledScheduleStart\":" + ledScheduleStart + ",\"ledScheduleStop\":" + ledScheduleStop +
             ",\"banPlusActive\":" + (banPlusActive() ? "true" : "false") +
             ",\"banPlusResumeIn\":" + (uint32_t)(banPlusOn && banPlusResumeAt ? (banPlusResumeAt - millis()) / 1000 : 0) +
             ",\"scheduleStart\":" + scheduleStart + ",\"scheduleStop\":" + scheduleStop +
             ",\"schedulePlusStart\":" + schedulePlusStart + ",\"schedulePlusStop\":" + schedulePlusStop +
             ",\"scheduleTz\":" + scheduleTz + ",\"scheduleTime\":" + localMinutes() +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip); bool clientBanPlus = banPlusActive() && !c.banPlusSpared;
    j += (i ? "," : ""); j += "{\"hostname\":\"" + jesc(c.hostname) + "\",\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"adblockExcluded\":" + (c.adblockExcluded?"true":"false") + ",\"bannedPlus\":" + (clientBanPlus?"true":"false") + ",\"banPlusSpared\":" + (c.banPlusSpared?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"allow\":[";
  for (int i = 0; i < numAllow; i++) { j += (i ? "," : ""); j += "\"" + jesc(allowDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
static void handleAdblockExclude() {
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->adblockExcluded = !c->adblockExcluded; saveAdblockExcluded(); } }
  web.send(200, "text/plain", "ok");
}
static void handleBanPlus() {
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banPlusSpared = !c->banPlusSpared; saveBanPlusSpared(); } }
  web.send(200, "text/plain", "ok");
}
static void handleSetHost() {
  IPAddress ip; String name = web.arg("h"); name.trim();
  if (ip.fromString(web.arg("ip")) && name.length() <= 64) {
    Dev* c = getClient((uint32_t)ip); if (c) { c->hostname = name; saveHostName((uint32_t)ip, name); }
  }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) ok = LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  if (!ok) LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upFailed = false;
static size_t upBytes = 0;
static const char* upError = "empty or invalid blocklist (size must be a nonzero multiple of 5)";
static File upFile;
static void handleUploadDone() {
  web.send(upOk ? 200 : 500, "text/plain", upOk ? "ok" : String("rejected: ") + upError);
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false; upFailed = false; upBytes = 0;
      upError = "could not write the uploaded file to LittleFS";
      beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      if (!upFile) upFailed = true;
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (!upFailed && upFile) {
        size_t written = upFile.write(u.buf, u.currentSize);
        upBytes += written;
        if (written != u.currentSize) {
          upFailed = true;
          upError = "LittleFS ran out of space during upload";
          Serial.printf("[ota] short write: %u of %u bytes\n",
                        (unsigned)written, (unsigned)u.currentSize);
        }
      }
      // The web server parses multipart bodies byte-by-byte; yield between chunks
      // so large uploads don't starve the ESP32 idle task and trigger its watchdog.
      delay(0);
      break;
    case UPLOAD_FILE_END:
      if (upFile) upFile.close();
      if (!upFailed && upBytes != u.totalSize) {
        upFailed = true;
        upError = "incomplete upload";
      }
      if (upFailed) {
        LittleFS.remove("/blocklist.new");
        reopenBlocklist();
        upOk = false;
      } else {
        upOk = commitNewBlocklist();
        if (!upOk) upError = "empty or invalid blocklist (size must be a nonzero multiple of 5)";
      }
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      upFailed = true; upOk = false; upError = "upload interrupted";
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static void forgetWifiCredentials() {
  WiFi.disconnect(false, true);
  prefs.begin("wifi", false);
  prefs.clear();
  prefs.putBool("force-portal", true);
  prefs.end();
}
static bool connectWiFi() {
  if (!prefs.begin("wifi", false)) {
    Serial.println("[wifi] could not open saved network settings");
    return false;
  }
  bool forcePortal = prefs.getBool("force-portal", false);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  staticIpEnabled = prefs.getBool("static", false);
  String savedIp = prefs.getString("ip", WIFI_STATIC_IP.toString());
  bool networkSettingsV2 = prefs.getBool("network-v2", false);
  if (!networkSettingsV2) {
    if (staticIpEnabled && savedIp == WIFI_STATIC_IP.toString()) {
      staticIpEnabled = false;
      prefs.putBool("static", false);
      Serial.println("[wifi] migrating legacy default 192.168.1.99 to DHCP");
    }
    prefs.putBool("network-v2", true);
  }
  prefs.end();
  if (forcePortal) {
    Serial.println("WiFi setup requested; skipping saved and fallback credentials");
    return false;
  }
  if (!parseStaticIp(savedIp, configuredStaticIp)) {
    configuredStaticIp = WIFI_STATIC_IP;
    if (staticIpEnabled) {
      staticIpEnabled = false;
      prefs.begin("wifi", false);
      prefs.putBool("static", false);
      prefs.end();
      Serial.printf("[wifi] invalid saved static IP '%s'; falling back to DHCP\n", savedIp.c_str());
    }
  }
  Serial.printf("[wifi] static IP %s (%s)\n", configuredStaticIp.toString().c_str(),
                staticIpEnabled ? "enabled" : "disabled");
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.persistent(false); WiFi.setAutoReconnect(true);
  if (staticIpEnabled) {
    IPAddress gateway = staticIpGateway(configuredStaticIp);
    WiFi.config(configuredStaticIp, gateway, WIFI_SUBNET, gateway, UPSTREAM);
  }
  WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;min-height:calc(100vh - 72px);margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9;display:flex;flex-direction:column'>"
    "<h2>&#128737; C3 AdBlock <span style='color:#8a9a5b;font-weight:800'>+</span> &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<div style='display:flex;align-items:center;gap:10px;margin:12px 0;color:#c9d1d9'>"
    "<label style='display:flex;align-items:center;gap:7px'><input id=static type=checkbox name=static value=1>Use static IP</label>"
    "<input id=ip name=ip placeholder='192.168.x.x' maxlength=15 aria-label='Static IP address' disabled style='flex:1;min-width:0;box-sizing:border-box;padding:9px;border-radius:5px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'></div>"
    "<p style='color:#8b949e;font-size:12px'>Leave unchecked to use the router-assigned address (DHCP). Check it only if you want to choose a static address.</p>"
    "<p style='color:#8b949e;font-size:12px'>Use 192.168.x.2 through 192.168.x.254. The gateway is set to 192.168.x.1 for that subnet.</p>"
    "<div style='margin:12px 0;color:#8b949e;font-size:12px'><strong>After setup</strong><ol style='padding-left:22px;margin:6px 0'><li>Log into your router&rsquo;s admin panel (usually by typing <code>192.168.1.1</code> into your web browser).</li><li>Navigate to the DHCP or LAN Settings section to find the DNS fields.</li><li>Update the fields with the following details:<ul style='padding-left:18px;margin:4px 0'><li>Primary DNS: Enter the IP address of this device. This routes network DNS traffic through the filter.</li><li>Secondary DNS: Enter 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9).</li></ul></li></ol></div>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form><footer style='margin:auto 0 0;padding-top:28px;text-align:center;color:#8b949e;font-size:12px'>"
    "Modded by <a href='https://bit.ly/m/IssamKanzi' target='_blank' rel='noopener noreferrer' style='color:inherit'>ISSAM. K</a><br>"
    "(Based on M-Abozaid&rsquo;s <a href='https://github.com/M-Abozaid/esp32-c3-adblock' target='_blank' rel='noopener noreferrer' style='color:inherit'>esp32-c3-adblock</a>)"
    "</footer><script>const s=document.getElementById('static'),i=document.getElementById('ip');s.onchange=()=>{i.disabled=!s.checked;i.required=s.checked;if(!s.checked)i.value=''};</script></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  bool enableStaticIp = web.hasArg("static");
  IPAddress requestedIp;
  if (enableStaticIp && !parseStaticIp(web.arg("ip"), requestedIp)) {
    web.send(400, "text/plain", "Use an available address from 192.168.x.2 to 192.168.x.254.");
    return;
  }
  if (!prefs.begin("wifi", false)) {
    web.send(500, "text/plain", "Could not open saved WiFi settings.");
    return;
  }
  prefs.remove("force-portal");
  bool saved = prefs.putString("ssid", ss) == ss.length() &&
               prefs.putString("pass", pw) == pw.length() &&
               prefs.putBool("static", enableStaticIp) == 1 &&
               prefs.putBool("network-v2", true) == 1;
  if (enableStaticIp) {
    String ip = requestedIp.toString();
    saved = (prefs.putString("ip", ip) == ip.length()) && saved;
  }
  String verifiedIp = prefs.getString("ip", "");
  saved = saved &&
          prefs.getBool("static", !enableStaticIp) == enableStaticIp &&
          prefs.getBool("network-v2", false) &&
          (!enableStaticIp || verifiedIp == requestedIp.toString());
  prefs.end();
  if (!saved) {
    web.send(500, "text/plain", "Could not save WiFi settings. Please try again.");
    return;
  }
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + ss + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + jesc(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  while (true) {
    dnsPortal.processNextRequest();
    web.handleClient();
    setWifiLed((millis() / 1000UL) % 2 == 0);
    delay(2);
  }
}

void setup() {
  pinMode(WIFI_LED_PIN, OUTPUT);
  updateStatusLeds();

  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) { numHashes = blocklist.size() / HASH_BYTES; Serial.printf("blocklist: %u domains\n", numHashes); }
  loadCustom(); loadAllowlist(); loadAdblockExcluded(); loadBanPlusSpared(); loadUpdateCfg(); loadSchedule(); loadLedSchedule(); loadManualState();
  Serial.printf("custom: %d, adblock exclusions: %d, ban+ spared: %d\n", numCustom, numAdblockExcluded, numBanPlusSpared);

  // Hold BOOT (GPIO9) at power-on to clear WiFi settings and open setup.
  pinMode(9, INPUT_PULLUP);
  bool bootHeld = (digitalRead(9) == LOW);
  if (bootHeld) { delay(60); bootHeld = (digitalRead(9) == LOW); }
  if (bootHeld) { forgetWifiCredentials();
    Serial.println("[setup] BOOT held -> cleared saved WiFi"); }
  pinMode(WIFI_LED_PIN, OUTPUT);
  updateStatusLeds();

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/exclude", handleAdblockExclude);
  web.on("/banplus", handleBanPlus);
  web.on("/sethost", handleSetHost);
  web.on("/addblock", []() { addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/addallow", []() { addAllowed(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unallow", []() { removeAllowed(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; scheduleOverride = 0; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { blockingOn = true; scheduleOverride = 1; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/startplus", []() {
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    banPlusOn = true; banPlusOverride = 1; banPlusResumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    saveManualState(); web.send(200, "text/plain", "paused");
  });
  web.on("/stopplus", []() { banPlusOn = false; banPlusOverride = 0; banPlusResumeAt = 0; saveManualState(); web.send(200, "text/plain", "stopped"); });
  web.on("/setmanual", []() {
    bool on = web.arg("v") == "1";
    if (web.arg("f") == "adblock") { blockingOn = on; scheduleOverride = on ? 1 : 0; resumeAt = 0; }
    else if (web.arg("f") == "banplus") { banPlusOn = on; banPlusOverride = on ? 1 : 0; banPlusResumeAt = 0; }
    saveManualState(); web.send(200, "text/plain", "ok");
  });
  web.on("/setled", []() {
    if (web.arg("f") == "connection") {
      connectionLedOn = web.arg("v") == "1";
      ledScheduleOverride = ledScheduleEnabled ? (connectionLedOn ? 1 : 0) : -1;
      saveManualState(); updateStatusLeds(); web.send(200, "text/plain", "ok");
    } else if (web.arg("f") == "power") {
      web.send(409, "text/plain", "power LED is hard-wired to VCC on this board");
    } else {
      web.send(400, "text/plain", "unknown LED");
    }
  });
  web.on("/setschedule", []() {
    scheduleAdblock = web.hasArg("a") && web.arg("a") == "1";
    scheduleBanPlus = web.hasArg("p") && web.arg("p") == "1";
    scheduleEnabled = scheduleAdblock || scheduleBanPlus;
    if (web.hasArg("s")) scheduleStart = constrain(web.arg("s").toInt(), 0, 1439);
    if (web.hasArg("t")) scheduleStop = constrain(web.arg("t").toInt(), 0, 1439);
    if (web.hasArg("ps")) schedulePlusStart = constrain(web.arg("ps").toInt(), 0, 1439);
    if (web.hasArg("pt")) schedulePlusStop = constrain(web.arg("pt").toInt(), 0, 1439);
    if (web.hasArg("le")) ledScheduleEnabled = web.arg("le") == "1";
    if (web.hasArg("ls")) ledScheduleStart = constrain(web.arg("ls").toInt(), 0, 1439);
    if (web.hasArg("lt")) ledScheduleStop = constrain(web.arg("lt").toInt(), 0, 1439);
    if (web.hasArg("z")) scheduleTz = constrain(web.arg("z").toInt(), -840, 840);
    if (!scheduleBanPlus) { banPlusOn = false; banPlusResumeAt = 0; }
    scheduleOverride = -1; banPlusOverride = -1; scheduleWindowKnown = false; schedulePlusWindowKnown = false; ledScheduleOverride = -1; ledScheduleWindowKnown = false; saveSchedule(); saveLedSchedule(); updateScheduleState(); updateStatusLeds(); web.send(200, "text/plain", "ok");
  });
  web.on("/setnetwork", []() {
    bool enableStaticIp = web.arg("static") == "1";
    IPAddress requestedIp;
    if (enableStaticIp) {
      if (!parseStaticIp(web.arg("ip"), requestedIp)) {
        web.send(400, "text/plain", "Use an available address from 192.168.x.2 to 192.168.x.254.");
        return;
      }
    }
    if (!prefs.begin("wifi", false)) {
      web.send(500, "text/plain", "Could not open saved WiFi settings.");
      return;
    }
    bool saved = prefs.putBool("static", enableStaticIp) == 1;
    saved = (prefs.putBool("network-v2", true) == 1) && saved;
    String ip = requestedIp.toString();
    if (enableStaticIp) saved = (prefs.putString("ip", ip) == ip.length()) && saved;
    bool verified = prefs.getBool("static", !enableStaticIp) == enableStaticIp;
    if (enableStaticIp) verified = verified && prefs.getString("ip", "") == ip;
    prefs.end();
    if (!saved || !verified) {
      web.send(500, "text/plain", "Could not verify the saved network settings. The device was not restarted.");
      return;
    }
    staticIpEnabled = enableStaticIp;
    if (enableStaticIp) configuredStaticIp = requestedIp;
    web.send(200, "text/plain", "Network settings saved; restarting.");
    delay(500);
    ESP.restart();
  });
  web.on("/reset", []() {
    web.send(200, "text/plain", "Resetting to welcome setup.");
    delay(500);
    if (blocklist) blocklist.close();
    if (!LittleFS.format()) Serial.println("[reset] LittleFS format failed");
    forgetWifiCredentials();
    prefs.begin("control", false); prefs.clear(); prefs.end();
    ESP.restart();
  });
  web.on("/forgetwifi", []() { web.send(200, "text/plain", "cleared — rebooting into setup portal");
    forgetWifiCredentials(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA
  web.on("/fetchnow", []() { fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  Serial.println("DNS :53 + dashboard :80");
}

void loop() {
  maintainClients();
  maintainWifiConnection();
  updateStatusLeds();
  web.handleClient();
  bool busy = handleDns();
  updateScheduleState();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; scheduleOverride = -1; resumeAt = 0; }
  if (banPlusOn && banPlusResumeAt && (int32_t)(millis() - banPlusResumeAt) >= 0) { banPlusOn = false; banPlusOverride = -1; banPlusResumeAt = 0; saveManualState(); }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
