#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Pro) ~= 200k domains: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
    https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate.txt
"""
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MAX_DOMAINS = 500_000                   # fits the single-app LittleFS partition
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~140k domains / 0.67 MB.
# Want more (up to ~250k)? swap light.txt -> pro.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light.txt',  # Hagezi Light
]

# Keep the major social networks and their first-party API, CDN, login, and
# messaging domains out of the list. Matching a root also excludes subdomains.
EXCLUDED_ROOTS = {
    # Meta: Facebook, Instagram, Messenger, WhatsApp, and Threads.
    'facebook.com', 'facebook.net', 'fbcdn.net', 'fbsbx.com', 'fb.me',
    'instagram.com', 'cdninstagram.com', 'ig.me', 'whatsapp.com',
    'whatsapp.net', 'messenger.com', 'meta.com', 'meta.ai', 'threads.net',
    'threads.com', 'workplace.com', 'oculus.com', 'accountkit.com',
    # Other major social, community, video, and messaging services.
    'reddit.com', 'redd.it', 'twitter.com', 'x.com', 't.co', 'twimg.com',
    'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'tiktokcdn-us.com',
    'byteoversea.com', 'ibytedtos.com', 'muscdn.com', 'musical.ly',
    'linkedin.com', 'licdn.com', 'pinterest.com', 'pinimg.com',
    'snapchat.com', 'sc-cdn.net', 'twitch.tv', 'twitchcdn.net',
    'youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com',
    'ytimg.com', 'yt3.ggpht.com', 'youtubei.googleapis.com', 'youtube.googleapis.com',
    'discord.com', 'discordapp.com', 'discordapp.net', 'discordcdn.com', 'discord.gg', 'discord.media',
    'telegram.org', 't.me', 'signal.org', 'wechat.com', 'weixin.qq.com',
    'tumblr.com', 'vk.com', 'vk.ru', 'weibo.com', 'mastodon.social',
    'bsky.app', 'blueskyweb.xyz', 'quora.com', 'medium.com',
}

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    args = sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains = set()
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! skipped {src}: {e}', file=sys.stderr); continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line or line[0] in '!/':
                continue
            parts = line.split()
            d = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::') \
                else parts[0] if len(parts) == 1 else None
            if d:
                d = norm(d)
                if '.' in d and ' ' not in d and not any(
                    d == root or d.endswith('.' + root) for root in EXCLUDED_ROOTS
                ):
                    domains.add(d)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    if len(uniq) > MAX_DOMAINS:
        uniq = uniq[:MAX_DOMAINS]                     # hash order avoids alphabetical domain bias
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
