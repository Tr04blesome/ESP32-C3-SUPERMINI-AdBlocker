#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
header #networkmsg{min-height:18px;margin-top:6px;text-align:center;color:#8b949e;font-size:12px}header #networkmsg:empty{display:none}
header h1{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:8px}.header-separator{color:#8b949e}#staticipbtn{font:inherit;padding:0;background:transparent;border:0;border-radius:0;color:#f85149;text-decoration:line-through;text-decoration-color:#f85149;text-decoration-thickness:2px}#staticipbtn.active{background:transparent;border:0;color:#58a6ff;text-decoration:none}#deviceip{width:125px;box-sizing:border-box;text-align:center;font:inherit;padding:4px 6px}#deviceip:disabled{color:#8b949e;opacity:1}#resetbtn{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.45);color:#ff7b72;padding:8px 14px}#resetbtn:hover{background:rgba(248,81,73,.16)}
header h1 .brand-title{color:#c9d1d9}header h1 .brand-plus{font-weight:800;color:#8a9a5b}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;max-width:100%;table-layout:fixed;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px;white-space:nowrap}
td:nth-child(-n+3){overflow:hidden;text-overflow:ellipsis}#ct td:nth-child(n+4){overflow:visible;text-overflow:clip}
th{background:#21262d;color:#8b949e}th.compact-header{cursor:pointer}th.compact-header:hover{background:#30363d}th.short-header{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}.ban-red,.ban-green,.ban-spared,button.client-adblock{background:transparent;border:0;border-radius:0;width:22px;height:22px;padding:0;font-size:15px;line-height:20px}button.client-adblock.excluded{background:transparent;border:0}button.client-adblock:hover,.ban-red:hover,.ban-green:hover,.ban-spared:hover{background:transparent}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
.entry-count{margin-left:8px;font-size:12px;font-weight:400;color:#8b949e}
#ct #col-blocked,#ct #col-allowed{width:10%!important}#ct #col-ban,#ct #col-banplus{width:4%!important}#ct th:nth-last-child(-n+2),#ct td:nth-last-child(-n+2){padding-left:0;padding-right:0;text-align:center}#ct th:nth-last-child(2),#ct td:nth-last-child(2){padding-right:4px}#ct th:last-child,#ct td:last-child{padding-left:4px}
@media(max-width:600px){.exclude-header{font-size:0}.exclude-header::after{content:'Exc..';font-size:13px}}
.feature-toggles{display:flex;justify-content:center;gap:10px;width:100%;flex-wrap:wrap}.feature-toggle{width:110px;padding:7px 10px}.feature-toggle.on{background:#196c2e;border-color:#238636}.feature-toggle.off{background:#9a6700;border-color:#d29922}.manual-toggles{flex-basis:100%}.control-section{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px}.section-head{display:flex;align-items:center;gap:12px;flex:1;min-width:180px}.section-controls{display:flex;align-items:center;justify-content:center;gap:8px;flex-basis:auto}.led-section{display:block}.led-head{display:flex;align-items:center;justify-content:space-between;gap:12px;min-width:0;margin-bottom:10px}.led-head .section-head{min-width:0}.led-controls{flex:0 0 auto;min-width:0}.led-controls button{width:34px;height:34px;min-width:34px;flex:0 0 34px;padding:0;border-radius:50%;font-weight:600}.led-controls button.on{background:#2383d9;border-color:#58a6ff;color:#fff}.led-controls button.off{background:#21262d;border-color:#30363d}.led-schedule{display:flex;align-items:center;justify-content:flex-start;gap:12px}.led-schedule .section-head{min-width:180px}.led-schedule .section-controls{margin-left:auto}#pausedur,#pausedurplus{width:160px;box-sizing:border-box}#pausebtn,#banplusbtn{width:80px;box-sizing:border-box}#banplusbar{flex-wrap:nowrap}#banplusbar .section-head{min-width:0}#banplusbar select{flex:0 1 auto;min-width:0}@media(max-width:600px){.led-head{gap:6px}.led-schedule{display:block}.led-schedule .section-head{min-width:0;margin-bottom:6px}.led-schedule .section-controls{display:flex;margin-left:0;justify-content:flex-start;gap:6px}#banplusbar{gap:8px}#ct th,#ct td{padding-left:5px;padding-right:5px}#ct #col-host{width:18%!important}#ct #col-ip{width:14%!important}#ct #col-mac{width:12%!important}#ct #col-blocked{width:10%!important}#ct #col-allowed{width:10%!important}#ct #col-ban,#ct #col-banplus{width:18%!important}}
</style><style>
.schedule-group{display:block}.schedule-group .group-control{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #30363d}.schedule-group .group-control .section-head{min-width:0}.schedule-group .group-schedule{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.schedule-group .group-schedule .section-head{min-width:180px}
@media(max-width:600px){.schedule-group .group-schedule{display:block}.schedule-group .group-schedule .section-head{min-width:0;margin-bottom:6px}.schedule-group .group-schedule .section-controls{justify-content:flex-start;gap:6px}}
.led-head{padding-bottom:10px;border-bottom:1px solid #30363d}#pausedur,#pausedurplus{width:120px}
#ct #col-host,#ct #col-mac{width:auto}#ct #col-ip{width:112px!important}#ct #col-blocked,#ct #col-allowed{width:70px!important}#ct #col-ban{width:54px!important}#ct #col-banplus{width:36px!important}#ct td:nth-child(n+4){overflow:hidden;text-overflow:ellipsis}#ct th:nth-last-child(2),#ct td:nth-last-child(2){padding-right:6px}#ct th:last-child,#ct td:last-child{padding-left:6px;padding-right:4px}
@media(max-width:600px){#ct th,#ct td{padding-left:3px;padding-right:3px}#ct #col-ip{width:92px!important}#ct #col-blocked,#ct #col-allowed{width:52px!important}#ct #col-ban{width:32px!important}#ct #col-banplus{width:32px!important}}
</style></head><body>
<header><h1><span class=brand-title>🛡️ C3 AdBlock</span><span class=brand-plus>+</span><span class=header-separator>|</span><button id=staticipbtn type=button class=active aria-pressed=true onclick="toggleStaticIp()">Static IP</button><span>:</span><input id=deviceip type=text value="192.168.1.99" maxlength=15 size=15 aria-label="Device IP address" onchange="saveStaticIp()"></h1><div id=networkmsg role=status aria-live=polite></div></header><div class=wrap>
<div class="control-section led-section"><div class=led-head><div class=section-head><span style=font-size:20px>💡</span><b>LED Control</b></div><div class="section-controls led-controls"><button id=connectionledbtn onclick=toggleConnectionLed() aria-label="Toggle connection LED">On</button></div></div><div class=led-schedule><div class=section-head><span style=font-size:20px>🕒</span><b>Schedule</b></div><div class=section-controls><label>Start <input type=time id=ledstart onchange="saveSchedules()"></label><label>Stop <input type=time id=ledstop onchange="saveSchedules()"></label><label><input type=checkbox id=ledschedule onchange="saveSchedules()"> Enable</label></div></div></div>
<div class="control-section schedule-group"><div id=blockbar class=group-control>
<div class=section-head><span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate data-on=1>Adblocking</b></div>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I re-enable</option></select>
<button id=pausebtn onclick=togglePause()>Pause</button></div>
<div class=group-schedule><div class=section-head><span style=font-size:20px>🕒</span><b>Adblocking Schedule</b></div>
<div class=section-controls><label>Start <input type=time id=schstart onchange="saveSchedules()"></label><label>Stop <input type=time id=schstop onchange="saveSchedules()"></label><label><input type=checkbox id=schedadblock onchange="saveSchedules()"> Enable</label></div></div>
</div>
<div class="control-section schedule-group"><div id=banplusbar class=group-control><div class=section-head><span id=banplusdot style=font-size:20px>🚫</span><b id=banplusstate data-on=1>Ban</b></div><select id=pausedurplus style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I stop</option></select><button id=banplusbtn onclick=togglePlus()>Start</button></div>
<div class=group-schedule><div class=section-head><span style=font-size:20px>🕒</span><b>Ban Schedule</b></div><div class=section-controls><label>Start <input type=time id=schplusstart onchange="saveSchedules()"></label><label>Stop <input type=time id=schplusstop onchange="saveSchedules()"></label><label><input type=checkbox id=schedbanplus onchange="saveSchedules()"> Enable</label></div></div></div>
<div class=cards id=sys></div>
<h2>CLIENTS <small style="color:#8b949e;font-weight:normal">click a host name or MAC header to resize | click a host name to edit | use Exclude to bypass adblocking for a client</small></h2><table id=ct><colgroup><col id=col-host><col id=col-ip><col id=col-mac><col id=col-blocked><col id=col-allowed><col id=col-ban><col id=col-banplus></colgroup><thead><tr><th id=th-host class=compact-header title="Click to resize" onclick="toggleClientColumn('host')">Host name</th><th id=th-ip>IP</th><th id=th-mac class=compact-header title="Click to resize" onclick="toggleClientColumn('mac')">MAC</th><th class=short-header>Blocked</th><th class=short-header>Allowed</th><th class=exclude-header>Exclude</th><th class=ban-header>Ban</th></tr></thead><tbody></tbody></table>
<h2>BAN ALLOWLIST <small id=allowcount class=entry-count>0/100</small></h2><div style=margin-bottom:8px><input id=allowdom placeholder="example.com" size=30><button onclick=addAllow()>Allow domain</button></div><table id=allowlist><tbody></tbody></table>
<h2>CUSTOM BLOCKED DOMAINS <small id=customcount class=entry-count>0/200</small></h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom()>Block domain</button></div>
<table id=cl><tbody></tbody></table>
<h2>BLOCKLIST &mdash; UPLOAD</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Upload blocklist</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB</div>
<div style="text-align:center;margin:28px 0 12px"><button id=resetbtn onclick=resetDevice()>Reset device</button></div>
</div><script>
function fmt(n){return n.toLocaleString()}
function saveNetworkSettings(enabled,ip){networkmsg.textContent=enabled?'Reconnecting at '+ip+'. Open that address and refresh.':'Reconnecting with a router-assigned IP. Open the new address and refresh.';fetch('/setnetwork?static='+(enabled?1:0)+'&ip='+encodeURIComponent(ip)).then(async response=>{if(!response.ok){networkmsg.textContent='';alert(await response.text());return}staticipbtn.disabled=true;deviceip.disabled=true}).catch(()=>{staticipbtn.disabled=true;deviceip.disabled=true})}
function toggleStaticIp(){let enabled=staticipbtn.getAttribute('aria-pressed')!=='true';let ip=deviceip.dataset.staticIp||'192.168.1.99';let message=enabled?'Switch to static IP '+ip+'? The device will disconnect and reconnect. Open that address and refresh.':'Switch to DHCP? The device will disconnect and reconnect with a router-assigned IP. Find its new IP address to reconnect or via c3adblock.local';if(confirm(message))saveNetworkSettings(enabled,ip)}
function saveStaticIp(){saveNetworkSettings(true,deviceip.value.trim())}
function resetDevice(){if(confirm('Erase all saved data, including the WiFi name and password, and return to first-time WiFi setup?'))fetch('/reset').then(()=>{document.body.innerHTML='<p style="text-align:center;margin:48px">Resetting. Join the C3-AdBlock setup network to enter WiFi credentials.</p>'}).catch(()=>{document.body.innerHTML='<p style="text-align:center;margin:48px">Resetting. Join the C3-AdBlock setup network to enter WiFi credentials.</p>'})}
const clientColumnWidths={host:['auto','18px'],mac:['auto','18px']};
function clientColumnCompact(name){return localStorage.getItem('client-col-'+name)==='1'}
function setClientColumn(name,compact){let col=document.getElementById('col-'+name);col.style.setProperty('width',clientColumnWidths[name][compact?1:0],'important');document.getElementById('th-'+name).textContent=compact?'-':name=='host'?'Host name':name.toUpperCase();localStorage.setItem('client-col-'+name,compact?'1':'0')}
function toggleClientColumn(name){setClientColumn(name,!clientColumnCompact(name));load()}
['host','mac'].forEach(name=>setClientColumn(name,localStorage.getItem('client-col-'+name)==='1'));
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function editHost(cell){let old=cell.textContent==='—'?'':cell.textContent;let name=prompt('Host name',old);if(name===null)return;name=name.trim();fetch('/sethost?ip='+encodeURIComponent(cell.dataset.ip)+'&h='+encodeURIComponent(name)).then(load)}
function addAllow(){let d=allowdom.value.trim();if(d){fetch('/addallow?d='+encodeURIComponent(d)).then(()=>{allowdom.value='';load()})}}
function togglePause(){if(blockstate.dataset.on=='1')fetch('/pause?s='+pausedur.value).then(load);else fetch('/resume').then(load);}
function togglePlus(){if(banplusstate.dataset.on=='1')fetch('/stopplus').then(load);else fetch('/startplus?s='+pausedurplus.value).then(load);}
function toggleConnectionLed(){fetch('/setled?f=connection&v='+(connectionledbtn.textContent=='On'?0:1)).then(load)}
function setToggle(id,on){let e=document.getElementById(id);e.classList.toggle('on',on);e.classList.toggle('off',!on)}
function toggleBanPlusException(ip){fetch('/banplus?ip='+encodeURIComponent(ip)).then(load)}
function clientButton(ip,excluded){let title=excluded?'Enable adblocking for client':'Exclude client from adblocking';return `<button class="client-adblock ${excluded?'excluded':''}" title="${title}" aria-label="${title}" onclick="fetch('/exclude?ip=${encodeURIComponent(ip)}').then(load)">${excluded?'💥':'🛡️'}</button>`}
function banPlusButton(ip,on,spared){let active=on&&!spared;let title=spared?'Remove client from Ban exclusion':active?'Turn Ban off for client':'Turn Ban on for client';let icon=spared?'🔵':active?'🔴':'🟢';return `<button class="${active?'ban-red':spared?'ban-spared':'ban-green'}" title="${title}" aria-label="${title}" onclick="toggleBanPlusException('${ip}')">${icon}</button>`}
function minTime(n){return String(Math.floor(n/60)%24).padStart(2,'0')+':'+String(n%60).padStart(2,'0')}
function timeMin(v){let p=v.split(':');return (+p[0])*60+(+p[1]||0)}
function saveSchedules(){if(!schstart.value||!schstop.value||!schplusstart.value||!schplusstop.value||!ledstart.value||!ledstop.value)return;fetch('/setschedule?a='+(schedadblock.checked?1:0)+'&p='+(schedbanplus.checked?1:0)+'&s='+timeMin(schstart.value)+'&t='+timeMin(schstop.value)+'&ps='+timeMin(schplusstart.value)+'&pt='+timeMin(schplusstop.value)+'&le='+(ledschedule.checked?1:0)+'&ls='+timeMin(ledstart.value)+'&lt='+timeMin(ledstop.value)+'&z='+(-new Date().getTimezoneOffset())).then(load)}
async function load(){let s=await(await fetch('/stats.json')).json();
allowcount.textContent=s.allow.length+'/100';customcount.textContent=s.custom.length+'/200';
let staticEnabled=!!s.staticIpEnabled;staticipbtn.classList.toggle('active',staticEnabled);staticipbtn.setAttribute('aria-pressed',staticEnabled?'true':'false');deviceip.disabled=!staticEnabled;deviceip.dataset.staticIp=s.staticIp||'192.168.1.99';if(document.activeElement!=deviceip)deviceip.value=staticEnabled?deviceip.dataset.staticIp:s.ip;
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'Adblocking':(s.resumeIn>0?'Paused - resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Pause':'Resume';pausedur.style.display=on?'':'none';
 banplusstate.dataset.on=s.banPlusActive?'1':'0';banplusbar.style.borderColor=s.banPlusActive?'#f85149':'#30363d';banplusdot.textContent='🚫';banplusstate.textContent=s.banPlusActive?'Active'+(s.banPlusResumeIn>0?' - stops in '+s.banPlusResumeIn+'s':''):'Ban';banplusbtn.textContent=s.banPlusActive?'Stop':'Start';pausedurplus.style.display=s.banPlusActive?'none':'';if(document.activeElement!=schedadblock)schedadblock.checked=!!s.scheduleAdblock;if(document.activeElement!=schedbanplus)schedbanplus.checked=!!s.scheduleBanPlus;if(document.activeElement!=schstart)schstart.value=minTime(s.scheduleStart);if(document.activeElement!=schstop)schstop.value=minTime(s.scheduleStop);if(document.activeElement!=schplusstart)schplusstart.value=minTime(s.schedulePlusStart);if(document.activeElement!=schplusstop)schplusstop.value=minTime(s.schedulePlusStop);
connectionledbtn.textContent=s.connectionLed?'On':'Off';connectionledbtn.classList.toggle('on',!!s.connectionLed);connectionledbtn.classList.toggle('off',!s.connectionLed);if(document.activeElement!=ledschedule)ledschedule.checked=!!s.ledScheduleEnabled;if(document.activeElement!=ledstart)ledstart.value=minTime(s.ledScheduleStart);if(document.activeElement!=ledstop)ledstop.value=minTime(s.ledScheduleStop);
sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['Blocklist',fmt(s.domains)+' domains',''],
['Clients',s.clients.length,''],['WiFi',s.rssi+' dBm',''],['Temp',s.temp+' °C',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td class=host-cell data-ip=${c.ip} title="Click to edit" onclick="editHost(this)">${clientColumnCompact('host')?'-':esc(c.hostname||'—')}</td><td>${c.ip}</td><td>${clientColumnCompact('mac')?'-':c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td>${clientButton(c.ip,c.adblockExcluded)}</td><td>${banPlusButton(c.ip,s.banPlusActive && !c.banPlusSpared,c.banPlusSpared)}</td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${d}</td><td style=text-align:right><button onclick="fetch('/unblock?d='+encodeURIComponent('${d}')).then(load)">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
allowlist.tBodies[0].innerHTML=s.allow.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button onclick="fetch('/unallow?d='+encodeURIComponent('${d}')).then(load)">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d)).then(()=>{dom.value='';load()})}}
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
load();setInterval(load,3000);
</script></body></html>)HTML";
