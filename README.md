# ESP32-C3 Super Mini AdBlocker

A DNS sinkhole for ESP32-C3 boards with 4 MB flash and no PSRAM. It stores domains as sorted, five-byte (40-bit) FNV-1a hashes in flash and binary-searches them instead of loading the blocklist into RAM. A match returns `0.0.0.0`; other DNS queries are forwarded to Quad9 (`9.9.9.9`).

The current partition layout supports a blocklist of up to **500,000 hash entries**. At that size the binary search takes about 19 flash reads per hash lookup. The list uses about 2.5 MB; it is not included in the browser firmware installer.

The blocklist builder excludes Reddit, YouTube, and other listed social/video roots, including their subdomains. Very large lists can still contain false positives outside those exclusions.

## Hardware

- Any **ESP32-C3** board (tested on a C3 SuperMini), 4 MB flash, **no PSRAM needed**
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.
- A **USB-A → USB-C dongle** lets it plug straight into the spare USB port on the
  back of most routers — no power supply, no extra box.

### Enclosure

A printable case for the C3 SuperMini: [`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

Printing notes:
- No supports needed; 0.2 mm layers, ~15% infill is plenty.
- **Keep the antenna end clear.** The C3's PCB antenna is the zig-zag trace on the
  short edge opposite the USB-C port — don't bury it in solid plastic or put metal
  near it, or your RSSI will suffer.
- Leave the vents open: the board idles around 45–55 °C.

## Browser Web Flasher

Open the [C3 AdBlocker Web Flasher](https://tr04blesome.github.io/ESP32-C3-SUPERMINI-AdBlocker/) in Chrome or Edge on a desktop computer, connect the ESP32-C3 by USB, and choose **Connect & Install**. The installer flashes the bootloader, partition table, and firmware. It includes **no Wi-Fi credentials and no blocklist**. A clean first install prompts to erase the device; this clears existing data.

After flashing, join the open `C3-AdBlock-XXXX` access point and enter the Wi-Fi name and password on the setup page. The device does not include a blocklist until you upload one from the dashboard.

## Build from Source

Use a current PlatformIO Core. Build the credential-free firmware used by the web flasher with:

```sh
pio run -e webflasher
```

The image is `.pio/build/webflasher/firmware.bin`. The regular `c3` environment includes `src/secrets.h` as a local fallback; do not commit that file or put personal credentials in public builds.

## Blocklists

Build the default list (StevenBlack base plus Hagezi Light) with:

```sh
py tools/build_blocklist.py data/blocklist.bin
```

For a large social-safe list, the checked-in builder supports up to 500,000 hash entries. This command uses StevenBlack, Hagezi Ultimate, and OISD Big, while retaining the builder's social and YouTube exclusions:

```sh
py tools/build_blocklist.py "AdBlocker Blocklists/MaxSocialSafeBlocklist.bin" \
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts" \
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt" \
  "https://big.oisd.nl/domainswild"
```

The output is a five-byte-per-entry binary file. Upload it in the dashboard’s **Blocklist — Upload** section. The current firmware does not bundle a list in its web-flasher image.

## Network Setup

The device initially uses static IP `192.168.1.99` with gateway `192.168.1.1`. The setup page and dashboard let you change the static address or switch to DHCP. Network changes restart the device. When Wi-Fi disconnects, the blue LED blinks; firmware retries the connection with increasing delays up to 30 seconds.

To use the sinkhole network-wide, set the router’s DNS server to the device’s current IP address. A public secondary DNS server may allow some clients to bypass filtering. The dashboard is at `http://c3adblock.local` when mDNS works, or at the device IP.

The dashboard supports up to **192 tracked clients**. Unflagged clients inactive for 24 hours are removed; client exceptions are kept. Limits are 200 custom blocked domains, 100 Ban allowlist domains, and 32 saved client exceptions of each type. The **Reset device** button erases saved data, including Wi-Fi credentials, and returns to first-time setup.

## Flash Layout

The current 4 MB layout in [partitions.csv](partitions.csv) reserves a **1.1875 MiB app slot** and a **2.75 MiB LittleFS partition**. It is a single-app layout, not a dual-firmware-OTA layout. The 500,000-entry blocklist occupies 2.5 MB, leaving filesystem room for settings and metadata. The web flasher publishes firmware only; it does not publish or overwrite user blocklists.

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## Credits

Modded by [ISSAM. K](https://bit.ly/m/IssamKanzi)

Based on M-Abozaid's [esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) (Inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the "answer 0.0.0.0 for blocklisted domains" idea. This is an independent from-scratch implementation focused on the hash-in-flash optimization for PSRAM-less chips.)
