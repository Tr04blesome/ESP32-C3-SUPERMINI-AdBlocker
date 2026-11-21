'use strict';

const HASH_BYTES = 5;
const MAX_DOMAINS = 500000;
const HASH_MASK = (1n << 40n) - 1n;
const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MAX_PREVIEW = 100;

const FEEDS = {
  stevenblack: {
    name: 'StevenBlack Unified',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
  },
  'hagezi-light': {
    name: 'HaGeZi Light',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light.txt',
  },
  'hagezi-pro': {
    name: 'HaGeZi Pro',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt',
  },
  'hagezi-tif': {
    name: 'HaGeZi Threat Intelligence Feeds',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.txt',
  },
  'stevenblack-extended': {
    name: 'StevenBlack extended',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts',
  },
};

const SOCIAL_SAFE_ROOTS = new Set([
  'facebook.com', 'facebook.net', 'fbcdn.net', 'fbsbx.com', 'fb.me',
  'instagram.com', 'cdninstagram.com', 'ig.me', 'whatsapp.com',
  'whatsapp.net', 'messenger.com', 'meta.com', 'meta.ai', 'threads.net',
  'threads.com', 'workplace.com', 'oculus.com', 'accountkit.com',
  'reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com',
  'redditinc.com', 'twitter.com', 'x.com', 't.co', 'twimg.com',
  'twttr.com', 'xusercontent.com', 'tweetdeck.com', 'periscope.tv',
  'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'tiktokcdn-us.com',
  'tiktokstatic.com', 'byteoversea.com', 'byteoversea.net',
  'ibytedtos.com', 'muscdn.com', 'musical.ly',
  'linkedin.com', 'linkedin.cn', 'licdn.com', 'lnkd.in',
  'pinterest.com', 'pinterest.ca', 'pinimg.com',
  'snapchat.com', 'snap.com', 'snapkit.com', 'sc-cdn.net',
  'twitch.tv', 'twitchcdn.net',
  'youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com',
  'ytimg.com', 'yt3.ggpht.com', 'youtubei.googleapis.com', 'youtube.googleapis.com',
  'discord.com', 'discordapp.com', 'discordapp.net', 'discordcdn.com',
  'discord.gg', 'discord.media', 'discordstatus.com',
  'telegram.org', 'telegram.me', 't.me', 'telesco.pe',
  'signal.org', 'signal.art', 'signal.group', 'signal.link',
  'wechat.com', 'weixin.qq.com',
  'tumblr.com', 'vk.com', 'vk.ru', 'vk.me', 'vkuser.net', 'weibo.com',
  'mastodon.social', 'mastodon.online', 'mastodon.world', 'mstdn.social',
  'fosstodon.org', 'joinmastodon.org', 'bsky.app', 'bsky.network',
  'blueskyweb.xyz', 'bereal.com', 'nextdoor.com', 'truthsocial.com',
  'gettr.com', 'gab.com', 'parler.com', 'rumble.com',
  'quora.com', 'medium.com',
]);

const form = document.getElementById('generator-form');
const generateButton = document.getElementById('generate');
const status = document.getElementById('status');
const result = document.getElementById('result');
const maxDomainsInput = document.getElementById('max-domains');
const domainSearch = document.getElementById('domain-search');
const domainList = document.getElementById('domain-list');
const previewCount = document.getElementById('preview-count');
const downloadBin = document.getElementById('download-bin');
const downloadTxt = document.getElementById('download-txt');
let includedDomains = [];
let downloadUrls = [];

function normalizeDomain(domain) {
  let value = domain.trim().toLowerCase().replace(/^\*+/, '').replace(/^\.+/, '').replace(/\.+$/, '');
  if (value.startsWith('www.')) value = value.slice(4);
  return value;
}

function isDomain(value) {
  return value.length <= 253 &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}

function parseFeed(text) {
  const domains = new Set();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split('#', 1)[0].trim();
    if (!line || line.startsWith('!') || line.startsWith('/')) continue;
    const parts = line.split(/\s+/);
    let domain = null;
    if (parts.length >= 2 && ['0.0.0.0', '127.0.0.1', '::1', '::'].includes(parts[0])) {
      domain = parts[1];
    } else if (parts.length === 1) {
      domain = parts[0];
    }
    if (domain) {
      domain = normalizeDomain(domain);
      if (isDomain(domain)) domains.add(domain);
    }
  }
  return domains;
}

function parseCustomDomains(text) {
  const domains = new Set();
  const invalid = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split('#', 1)[0].trim();
    if (!line) continue;
    const domain = normalizeDomain(line);
    if (isDomain(domain)) domains.add(domain);
    else if (invalid.length < 10) invalid.push(rawLine.trim());
  }
  return { domains, invalid };
}

function isSocialSafeExcluded(domain) {
  let candidate = domain;
  while (candidate.includes('.')) {
    if (SOCIAL_SAFE_ROOTS.has(candidate)) return true;
    candidate = candidate.slice(candidate.indexOf('.') + 1);
  }
  return SOCIAL_SAFE_ROOTS.has(candidate);
}

function hashDomain(domain, encoder) {
  let hash = FNV_OFFSET & HASH_MASK;
  for (const byte of encoder.encode(domain)) {
    hash = ((hash ^ BigInt(byte)) * FNV_PRIME) & HASH_MASK;
  }
  return hash;
}

function renderPreview() {
  const query = domainSearch.value.trim().toLowerCase();
  const matches = [];
  for (const domain of includedDomains) {
    if (!query || domain.includes(query)) {
      matches.push(domain);
      if (matches.length === MAX_PREVIEW) break;
    }
  }
  domainList.replaceChildren();
  for (const domain of matches) {
    const item = document.createElement('div');
    item.textContent = domain;
    domainList.appendChild(item);
  }
  previewCount.textContent = includedDomains.length === 0
    ? 'No generated domain list yet.'
    : `${matches.length === MAX_PREVIEW ? 'Showing up to ' : 'Showing '}${matches.length} of ${includedDomains.filter(domain => !query || domain.includes(query)).length.toLocaleString()} matching included domains. Download the text file for the full list.`;
}

function clearDownloads() {
  for (const url of downloadUrls) URL.revokeObjectURL(url);
  downloadUrls = [];
  includedDomains = [];
  result.hidden = true;
  domainSearch.value = '';
  domainList.replaceChildren();
  previewCount.textContent = 'No generated domain list yet.';
}

function setStatus(message, kind) {
  status.textContent = message;
  status.className = `status${kind ? ` ${kind}` : ''}`;
}

function setBusy(isBusy) {
  form.querySelectorAll('input, textarea, button').forEach(control => {
    control.disabled = isBusy;
  });
  generateButton.textContent = isBusy ? 'Generating…' : 'Fetch feeds and generate';
}

function downloadBlob(blob, filename, anchor) {
  const url = URL.createObjectURL(blob);
  downloadUrls.push(url);
  anchor.href = url;
  anchor.download = filename;
}

async function fetchFeed(feed) {
  const response = await fetch(feed.url, { cache: 'no-store' });
  if (!response.ok) throw new Error(`${feed.name} returned HTTP ${response.status}`);
  return response.text();
}

form.addEventListener('input', () => {
  clearDownloads();
  setStatus('Settings changed. Generate again to update the downloads.');
});

domainSearch.addEventListener('input', renderPreview);

maxDomainsInput.addEventListener('change', () => {
  const value = Number(maxDomainsInput.value);
  if (!Number.isInteger(value) || value < 1 || value > MAX_DOMAINS) {
    maxDomainsInput.setCustomValidity('Choose a number from 1 to 500,000.');
  } else {
    maxDomainsInput.setCustomValidity('');
  }
});

form.addEventListener('submit', async event => {
  event.preventDefault();
  clearDownloads();

  const maxDomains = Number(maxDomainsInput.value);
  if (!Number.isInteger(maxDomains) || maxDomains < 1 || maxDomains > MAX_DOMAINS) {
    maxDomainsInput.setCustomValidity('Choose a number from 1 to 500,000.');
    maxDomainsInput.reportValidity();
    return;
  }
  maxDomainsInput.setCustomValidity('');

  const custom = parseCustomDomains(document.getElementById('custom-domains').value);
  if (custom.invalid.length) {
    setStatus(`Invalid custom domain${custom.invalid.length > 1 ? 's' : ''}: ${custom.invalid.join(', ')}. Enter one domain per line.`, 'error');
    return;
  }

  const selectedFeeds = [...form.querySelectorAll('input[name="feed"]:checked')].map(input => FEEDS[input.value]);
  if (!selectedFeeds.length && custom.domains.size === 0) {
    setStatus('Choose at least one feed or add a custom domain.', 'error');
    return;
  }

  setBusy(true);
  try {
    const domains = new Set(custom.domains);
    for (let index = 0; index < selectedFeeds.length; index += 1) {
      const feed = selectedFeeds[index];
      setStatus(`Fetching ${feed.name} (${index + 1} of ${selectedFeeds.length})…`);
      let text;
      try {
        text = await fetchFeed(feed);
      } catch (error) {
        throw new Error(`Could not fetch ${feed.name}. Check your connection; the publisher may be unavailable or block browser access. ${error.message}`);
      }
      for (const domain of parseFeed(text)) domains.add(domain);
    }

    const socialSafe = document.getElementById('social-safe').checked;
    const filteredDomains = socialSafe
      ? [...domains].filter(domain => !isSocialSafeExcluded(domain))
      : [...domains];
    if (!filteredDomains.length) throw new Error('No valid domains were found in the selected feeds.');

    setStatus(`Hashing ${filteredDomains.length.toLocaleString()} unique domains…`);
    const encoder = new TextEncoder();
    const entries = filteredDomains.map(domain => ({ domain, hash: hashDomain(domain, encoder) }));
    entries.sort((left, right) => {
      if (left.hash < right.hash) return -1;
      if (left.hash > right.hash) return 1;
      return left.domain < right.domain ? -1 : left.domain > right.domain ? 1 : 0;
    });

    const selected = [];
    const outputDomains = [];
    let collisions = 0;
    let uniqueHashes = 0;
    let previousHash = null;
    for (const entry of entries) {
      if (entry.hash === previousHash) {
        collisions += 1;
        if (selected.length && selected[selected.length - 1].hash === entry.hash) {
          outputDomains.push(entry.domain);
        }
        continue;
      }
      previousHash = entry.hash;
      uniqueHashes += 1;
      if (selected.length < maxDomains) {
        selected.push(entry);
        outputDomains.push(entry.domain);
      }
    }
    if (!selected.length) throw new Error('No blocklist entries could be generated.');

    const binary = new Uint8Array(selected.length * HASH_BYTES);
    for (let entryIndex = 0; entryIndex < selected.length; entryIndex += 1) {
      let hash = selected[entryIndex].hash;
      for (let byteIndex = 0; byteIndex < HASH_BYTES; byteIndex += 1) {
        binary[entryIndex * HASH_BYTES + byteIndex] = Number(hash & 0xffn);
        hash >>= 8n;
      }
    }

    includedDomains = outputDomains.sort();
    const date = new Date().toISOString().slice(0, 10);
    const name = `c3-blocklist-${date}`;
    downloadBlob(new Blob([binary], { type: 'application/octet-stream' }), `${name}.bin`, downloadBin);
    downloadBlob(new Blob([includedDomains.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' }), `${name}-domains.txt`, downloadTxt);

    const size = binary.byteLength;
    document.getElementById('stats').textContent = '';
    const stats = [
      `${filteredDomains.length.toLocaleString()} domains after exclusions`,
      `${selected.length.toLocaleString()} hash entries`,
      `${size.toLocaleString()} bytes (${(size / 1024 / 1024).toFixed(2)} MiB)`,
    ];
    for (const text of stats) {
      const item = document.createElement('span');
      item.textContent = text;
      document.getElementById('stats').appendChild(item);
    }
    document.getElementById('collision-note').textContent =
      `${collisions.toLocaleString()} hash collisions detected. Entries are ordered by hash, matching the device format.${selected.length < uniqueHashes ? ` The configured cap includes ${selected.length.toLocaleString()} of ${uniqueHashes.toLocaleString()} unique hashes.` : ''}`;
    result.hidden = false;
    renderPreview();
    setStatus('Blocklist generated. Download the .bin file and upload it from your device dashboard.', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    setBusy(false);
  }
});
