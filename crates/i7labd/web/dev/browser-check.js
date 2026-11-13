#!/usr/bin/env node
// Headless Chrome check of the SPA against web/dev/mock-server.py, driven over the DevTools protocol
// (node >= 22 for the global WebSocket/fetch; no npm packages).
//   node web/dev/browser-check.js [/path/to/chrome]
'use strict';
const { spawn } = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
const CHROME = process.argv[2] || process.env.CHROME || 'google-chrome';
const HERE = __dirname, PORT = 18080, BAD_PORT = 18081, DBG = 19222;
const sleep = ms => new Promise(r => setTimeout(r, ms));
let fails = 0, passes = 0;
const check = (c, msg) => { if (c) { passes++; console.log('  ok   ' + msg); } else { fails++; console.log('  FAIL ' + msg); } };

const RO_HEX = require('crypto').randomBytes(32).toString('hex'), ADMIN_HEX = require('crypto').randomBytes(32).toString('hex');  // random per run
function startMock(port, env) {
  const p = spawn('python3', [path.join(HERE, 'mock-server.py'), '--port', String(port)], { env: Object.assign({}, process.env, { MOCK_QUIET: '1', MOCK_FAST: '1', I7_MOCK_RO_HEX: RO_HEX, I7_MOCK_ADMIN_HEX: ADMIN_HEX }, env), stdio: 'ignore' });
  return p;
}
async function cdpConnect(url) {
  let target;
  for (let i = 0; i < 50; i++) { try { const r = await fetch('http://127.0.0.1:' + DBG + '/json/new?about:blank', { method: 'PUT' }); target = await r.json(); break; } catch (e) { await sleep(200); } }
  if (!target) throw new Error('chrome did not start');
  const ws = new WebSocket(target.webSocketDebuggerUrl); await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const pend = new Map(), listeners = [];
  ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } else listeners.forEach(f => f(d)); };
  const send = (method, params) => new Promise(res => { const i = ++id; pend.set(i, res); ws.send(JSON.stringify({ id: i, method, params: params || {} })); });
  return { send, on: f => listeners.push(f), close: () => ws.close() };
}
async function main() {
  const mock = startMock(PORT, {}), bad = startMock(BAD_PORT, { MOCK_BAD_PROOF: '1' });
  const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'i7spa-'));
  const chrome = spawn(CHROME, ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=' + DBG, '--user-data-dir=' + prof, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  const cleanup = () => { try { mock.kill(); bad.kill(); chrome.kill(); } catch (e) { /* gone */ } try { fs.rmSync(prof, { recursive: true, force: true }); } catch (e) { /* ignore */ } };
  try {
    const c = await cdpConnect(); const errors = [];
    c.on(d => {
      if (d.method === 'Runtime.exceptionThrown') errors.push('exception: ' + JSON.stringify(d.params.exceptionDetails.exception && d.params.exceptionDetails.exception.description || d.params.exceptionDetails.text));
      if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') errors.push('console.error: ' + d.params.args.map(a => a.value || a.description).join(' '));
      if (d.method === 'Log.entryAdded' && d.params.entry.level === 'error' && !/status of 40[0-9]|409|403/.test(d.params.entry.text)) errors.push('log: ' + d.params.entry.text + ' ' + (d.params.entry.url || ''));
    });
    await c.send('Runtime.enable'); await c.send('Page.enable'); await c.send('Log.enable');
    const ev = async (expr) => { const r = await c.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }); if (r.result.exceptionDetails) throw new Error('eval: ' + JSON.stringify(r.result.exceptionDetails.exception.description)); return r.result.result.value; };
    const waitFor = async (expr, ms, what) => { const t0 = Date.now(); for (;;) { let v; try { v = await ev(expr); } catch (e) { v = false; } if (v) return v; if (Date.now() - t0 > (ms || 8000)) { check(false, 'timeout: ' + (what || expr)); return false; } await sleep(100); } };
    const goto = async (url) => { await c.send('Page.navigate', { url }); await sleep(300); await waitFor('document.readyState==="complete"', 8000, 'load'); };
    const text = () => ev('document.getElementById("main").innerText');
    const click = sel => ev('(()=>{const e=document.querySelector(' + JSON.stringify(sel) + ');if(!e)return false;e.click();return true})()');
    const clickText = (sel, txt) => ev('(()=>{const e=[...document.querySelectorAll(' + JSON.stringify(sel) + ')].find(x=>x.textContent.includes(' + JSON.stringify(txt) + '));if(!e)return false;e.click();return true})()');
    const setVal = (sel, v) => ev('(()=>{const e=document.querySelector(' + JSON.stringify(sel) + ');e.value=' + JSON.stringify(v) + ';e.dispatchEvent(new Event("input",{bubbles:true}));e.dispatchEvent(new Event("change",{bubbles:true}));return true})()');
    const base = 'http://127.0.0.1:' + PORT + '/';
    const stubClip = () => ev('(()=>{window.__clip=null;Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:t=>{window.__clip=t;return Promise.resolve()}}})})()');
    async function copyChecks(name) {
      await stubClip();
      check(await ev('document.querySelectorAll("button.copybtn").length===2'), name + ': Copy as Markdown / JSON buttons present');
      await click('button[data-copy=md]'); await waitFor('window.__clip!==null', 3000, 'markdown copied');
      const md = await ev('window.__clip') || '', lines = md.split('\n');
      check(/^# \S/.test(lines[0]) && /^Host lab-\S+ \| build mock-1 \| boot id abcd \| \d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d\d:\d\d$/.test(lines[2]) && /\n## /.test(md), name + ': markdown has the header line (host, build, boot id, local time) and sections');
      { const bm = /(^|[ |])(null|undefined|NaN)([ |]|$)/m.exec(md); check(!bm && !/<img|<script/.test(md.replace(/```[\s\S]*?```/g, '').replace(/\\</g, '')), name + ': markdown has no null/undefined and no unescaped markup' + (bm ? ' (found: ' + md.slice(Math.max(0, bm.index - 60), bm.index + 40).replace(/\n/g, ' ') + ')' : '')); }
      check(await ev('document.querySelector("button[data-copy=md]").textContent==="Copied"'), name + ': "Copied" confirmation');
      await ev('window.__clip=null'); await click('button[data-copy=json]'); await waitFor('window.__clip!==null', 3000, 'json copied');
      let j = null; try { j = JSON.parse(await ev('window.__clip')); } catch (e) { /* checked below */ }
      check(j && j.host && j.boot_id === 'abcd' && Array.isArray(j.sections) && j.sections.length > 0, name + ': JSON copy parses and carries host, boot id, sections');
      if (name === 'network') {
        check(/\| Name \| Kind \| State \| Speed \| MAC \| Permanent MAC \| Driver \| Bus \| MTU \| IPv4 /.test(md) && /\| eth0 \| physical \| up \| 1000 Mb\/s full \| 52:54:00:17:00:02 \| 52:54:00:17:00:02 \| e1000e \| 0000:02:00\.0 \| 1500 \| 10\.0\.2\.15\/24 /.test(md) && /dummy0 \| virtual/.test(md), 'network markdown: driver, bus, MAC, IPv4 columns for every interface');
        check(/Wi-Fi adapter 8086:51f0 \(0000:00:14\.3\) has no Linux driver bound in this image: Wi-Fi is not a control path/.test(md) && /## Alerts/.test(md), 'network markdown: the alert text is included');
        // plain-HTTP path: no Clipboard API -> hidden textarea + execCommand
        await ev('(()=>{window.__exec=null;Object.defineProperty(navigator,"clipboard",{configurable:true,value:undefined});document.execCommand=c=>{window.__exec={c,v:document.activeElement&&document.activeElement.value};return true}})()');
        await click('button[data-copy=json]'); await waitFor('window.__exec!==null', 3000, 'execCommand fallback');
        const fx = await ev('window.__exec'); let fj = null; try { fj = JSON.parse(fx.v); } catch (e) { /* below */ }
        check(fx.c === 'copy' && fj && fj.page === 'Network', 'copy falls back to textarea + execCommand without the Clipboard API');
        check(await ev('!document.querySelector("textarea[aria-hidden]")'), 'fallback textarea is removed again');
        // nothing works: a dialog with the text selected
        await ev('document.execCommand=()=>false'); await click('button[data-copy=md]');
        check(await waitFor('(()=>{const d=document.querySelector("dialog[open] textarea");return !!d&&d.value.startsWith("# Network")})()', 3000, 'copy dialog'), 'if copying is blocked the text is offered in a dialog');
        await clickText('dialog button', 'Close'); await waitFor('!document.querySelector("dialog")', 2000);
      }
      if (name === 'log') check(/\n## Log\n\n```\n[\s\S]*audit line[\s\S]*\n```/.test(md), 'log markdown: lines inside a code fence');
    }

    console.log('login');
    await goto(base);
    check(await waitFor('!!document.getElementById("keyline")', 5000, 'login form'), 'login form shown without a key');
    check(await ev('document.getElementById("nav").hidden'), 'navigation hidden before login');
    check(await ev('!!document.querySelector("script[nonce]") && document.querySelectorAll("script").length===2'), 'only the two nonce scripts are present');
    await setVal('#keyline', 'i7k1:ro:00'); await click('.login button.pri');
    check(await waitFor('document.querySelector(".login .alert.bad")', 3000, 'bad key message'), 'malformed key is rejected locally');
    await setVal('#keyline', 'i7k1:ro:' + RO_HEX); await click('.login button.pri');
    check(await waitFor('location.hash==="#/overview" && document.querySelectorAll(".card").length>3', 8000, 'overview rendered'), 'random run key accepted, overview rendered');
    check(await ev('!!sessionStorage.getItem("i7lab.ro") && !localStorage.getItem("i7lab.ro")'), 'key held in sessionStorage only');

    console.log('overview + escaping');
    await waitFor('document.querySelector(".alert.warn")', 5000, 'attention');
    let tx = await text();
    check(/Ethernet controller Realtek RTL8126 5GbE \(10ec:8126, 0000:03:00\.0\) has no Linux driver bound in this image; the control path is eth0/.test(tx) && /Wi-Fi adapter 8086:51f0 \(0000:00:14\.3\) has no Linux driver bound in this image: Wi-Fi is not a control path; the control path is eth0/.test(tx) && !/cannot carry control traffic/.test(tx), 'attention list: driverless Ethernet and Wi-Fi are told apart, eth0 is the control path');
    check(/ThinkCentre M720q/.test(tx) && /i7-8700/.test(tx) && /4\.0 GiB used of 16/.test(tx), 'machine, CPU and memory cards');
    check(/<img src=x onerror=/.test(tx) === true, 'hostile product string is shown as literal text');
    check(await ev('window.__pwned===undefined && !document.querySelector("img") && !document.querySelector("main script")'), 'no injected element or script ran (render injection)');
    check(await waitFor('/live feed: on/.test(document.getElementById("main").innerText)', 6000, 'sse'), 'SSE snapshot feed connects and verifies event macs');

    const pageChecks = [
      ['pcie', async () => { await waitFor('document.querySelector("ul.tree")', 5000); const t = await text(); check(/0000:03:00\.0/.test(t) && /NO DRIVER/.test(t) && /DEGRADED/.test(t) && /AER 4/.test(t), 'pcie: tree, unbound NIC, degraded link, AER');
        await clickText('button.link', 'details'); check(await waitFor('/BAR0/.test(document.getElementById("main").innerText) || /Capabilities/.test(document.getElementById("main").innerText)', 3000), 'pcie: detail drawer opens');
        await setVal('input[aria-label="Filter devices"]', 'realtek'); await sleep(200); const f = await text(); check(/RTL8126/.test(f) && !/I219/.test(f), 'pcie: filter'); }],
      ['storage', async () => { await waitFor('document.querySelectorAll("section[aria-label^=\\"Disk\\"]").length===3', 5000); const t = await text(); check(/nvme0n1/.test(t) && /boot media/.test(t) && /needs_override/.test(t) && /SMART/.test(t), 'storage: disks, gate verdicts, SMART');
        check(await ev('!!document.querySelector(".bar i")'), 'storage: partition bar'); }],
      ['network', async () => { await waitFor('document.querySelector("svg.chart")', 6000); const t = await text(); check(/eth0/.test(t) && /52:54:00:17:00:02/.test(t) && /VLAN 13/.test(t) && /Wi-Fi adapter 8086:51f0 \(0000:00:14\.3\) has no Linux driver bound in this image: Wi-Fi is not a control path; the control path is eth0/.test(t) && !/No driver for|cannot carry control traffic/.test(t), 'network: NICs, VLAN, Wi-Fi alert names the device and the control path');
        check(/virtual interfaces \(2\)/.test(t) && !/dummy0|sit0/.test(t) && await ev('document.querySelector("details.virt")&&!document.querySelector("details.virt").open'), 'network: dummy0 and sit0 collapsed under "virtual interfaces (2)"');
        check(!/\d+\.\d{2,}\s*(B|KiB|MiB)\/s/.test(t) && !/\d\.\d{3,}/.test(t), 'network: no raw floats in rates'); }],
      ['terminal', async () => { await waitFor('document.getElementById("termwarn")', 3000); const t = await text();
        check(/Unencrypted HTTP: everything you type and see is visible on the network; use only on a trusted LAN/.test(t), 'terminal: plain-HTTP warning shown');
        check(await ev('document.getElementById("termopen").disabled') && /Admin key required/.test(t), 'terminal: disabled with an explanation for the read-only key'); }],
      ['usb', async () => { await waitFor('document.querySelector("ul.tree")', 5000); const t = await text(); check(/Kingston/.test(t) && /Logitech/.test(t), 'usb: tree'); check(await ev('window.__pwned===undefined && !document.querySelector("img")'), 'usb: hostile product inert'); }],
      ['sensors', async () => { await waitFor('document.querySelectorAll("svg.chart").length>=3', 8000); await sleep(2500); const t = await text(); check(/Temperatures/.test(t) && /Fans/.test(t) && /Core 0/.test(t), 'sensors: live charts'); check(await ev('document.querySelectorAll("svg.chart polyline").length>=3'), 'sensors: polylines drawn'); }],
      ['log', async () => { await waitFor('/tick/.test(document.querySelector(".logbox").innerText)', 6000); const t = await text(); check(/Linux version/.test(t) && /error/.test(t), 'log: kernel lines'); check(await ev('window.__pwned===undefined && !document.querySelector("img")'), 'log: hostile line inert');
        await setVal('input[aria-label="Search log"]', 'link up'); await sleep(200); check(/1 of/.test(await ev('document.querySelector("#main .dim:last-of-type")?document.getElementById("main").innerText:""')), 'log: search filters');
        await setVal('input[aria-label="Search log"]', ''); await setVal('select[aria-label="Log source"]', 'audit'); await waitFor('/audit line 0/.test(document.querySelector(".logbox").innerText)', 4000); check(true, 'log: audit source over a verified NDJSON stream'); }],
      ['about', async () => { await waitFor('/Commands/.test(document.getElementById("main").innerText)', 5000); const t = await text(); check(/0\.1\.0-mock/.test(t) && /blk\.write/.test(t) && /planned/.test(t), 'about: id + command table with planned marked'); check(/Failed verification\s*0/.test(t), 'about: zero verification failures'); }],
    ];
    for (const [name, fn] of pageChecks) {
      console.log(name);
      await ev('location.hash="#/' + name + '"'); await sleep(250);
      check(await ev('document.querySelector("#nav a[aria-current=page]").textContent.toLowerCase().startsWith(' + JSON.stringify(name.slice(0, 3)) + ')'), name + ': nav marks the page');
      await fn();
      const pt = await text();
      check(!/(^|\s)(null|undefined|NaN)(\s|$)/.test(pt), name + ': no stray "null"/"undefined"/"NaN" text');
      if (name !== 'terminal') await copyChecks(name);
    }

    console.log('storage: read test and write safety UI');
    await ev('location.hash="#/storage"'); await waitFor('document.querySelectorAll("section[aria-label^=\\"Disk\\"]").length===3', 5000);
    const sec = n => 'section[aria-label="Disk ' + n + '"]';
    await ev('document.querySelector(' + JSON.stringify(sec('vdb') + ' details') + ').open=true');
    await clickText(sec('vdb') + ' button', 'Run read test');
    check(await waitFor('/Test passed/.test(document.querySelector(' + JSON.stringify(sec('vdb')) + ').innerText)', 8000, 'read test result'), 'read test streams progress and ends with a verified result');
    check(await ev('!!document.querySelector(' + JSON.stringify(sec('vdb') + ' svg.chart') + ')'), 'read test: throughput chart');
    const wbtn = n => '(()=>{const b=[...document.querySelectorAll(' + JSON.stringify(sec(n) + ' button') + ')].find(x=>x.textContent==="Write test...");return b})()';
    check(await ev(wbtn('vdb') + '.disabled'), 'write test disabled with the read-only key');
    check(/admin key not loaded/.test(await ev('document.querySelector(' + JSON.stringify(sec('vdb')) + ').innerText')), 'write gate explains why');
    await ev('location.hash="#/actions"'); await waitFor('document.getElementById("adm")', 5000);
    check(await ev('[...document.querySelectorAll("#main button.danger")].every(b=>b.disabled)'), 'actions: reboot/poweroff disabled without the admin key');
    await setVal('#adm', 'i7k1:admin:' + ADMIN_HEX); await clickText('#main button', 'Load admin key');
    check(await waitFor('/Admin key accepted/.test(document.getElementById("main").innerText)', 5000, 'admin accepted'), 'admin key loaded explicitly and verified with the host');
    check(await ev('!!sessionStorage.getItem("i7lab.admin")'), 'admin key kept in sessionStorage');
    await clickText('#main button', 'Ping'); check(await waitFor('/uptime_ms/.test(document.getElementById("main").innerText)', 4000), 'actions: ping');
    await clickText('#main section button.danger', 'Reboot');
    check(await waitFor('!!document.querySelector("dialog[open]")', 3000), 'reboot asks for confirmation');
    check(await ev('document.querySelector("dialog[open] button.danger").disabled'), 'confirm disabled until the host name is typed');
    await clickText('dialog button', 'Cancel'); check(await waitFor('!document.querySelector("dialog")', 2000), 'cancel closes the dialog without sending');
    console.log('terminal (admin key)');
    await ev('location.hash="#/terminal"'); await waitFor('document.getElementById("termopen")', 4000);
    check(await ev('!document.getElementById("termopen").disabled && !document.getElementById("termdeny")'), 'terminal: enabled with the admin key');
    check(await ev('document.querySelectorAll("script").length===2'), 'terminal: xterm is not loaded before the shell is opened');
    await click('#termopen');
    check(await waitFor('!!document.querySelector("#termbox .xterm") && /mock shell ready/.test(document.querySelector("#termbox").innerText)', 10000, 'xterm up'), 'terminal: xterm.js loaded from this host, shell opened, sealed output stream verified');
    await ev('document.querySelector(".xterm-helper-textarea").focus()');
    await c.send('Input.insertText', { text: 'ls -l' });
    await c.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13, text: '\r' });
    await c.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
    check(await waitFor('/ls -l/.test(document.querySelector("#termbox").innerText) && /\[ran\]/.test(document.querySelector("#termbox").innerText)', 8000, 'echo'), 'terminal: keystrokes go out signed and the reply comes back');
    await clickText('#main button', 'Close shell');
    check(await waitFor('/session ended/.test(document.getElementById("main").innerText)', 5000, 'ended'), 'terminal: closing ends the session');
    await ev('location.hash="#/storage"'); await waitFor('document.querySelectorAll("section[aria-label^=\\"Disk\\"]").length===3', 5000);
    for (const n of ['vdb', 'sda', 'nvme0n1']) await ev('document.querySelector(' + JSON.stringify(sec(n) + ' details') + ').open=true');
    check(await ev(wbtn('vdb') + '.disabled'), 'write disabled until the serial is typed');
    await setVal(sec('vdb') + ' input[id^="ser-"]', 'TESTDISK0'); check(await ev(wbtn('vdb') + '.disabled'), 'a partial serial keeps it disabled');
    await setVal(sec('vdb') + ' input[id^="ser-"]', 'TESTDISK01'); check(await ev('!' + wbtn('vdb') + '.disabled'), 'full serial enables the write button');
    await setVal(sec('sda') + ' input[id^="ser-"]', '<b>0123</b>\u001b[2J'); check(await ev(wbtn('sda') + '.disabled'), 'boot media stays disabled even with the serial typed');
    check(/boot media: never writable/.test(await ev('document.querySelector(' + JSON.stringify(sec('sda')) + ').innerText')), 'boot media reason shown');
    await setVal(sec('nvme0n1') + ' input[id^="ser-"]', 'S4EVNX0M123456A'); check(await ev(wbtn('nvme0n1') + '.disabled'), 'disk with a partition table also needs the data-loss tick');
    await ev('document.querySelector(' + JSON.stringify(sec('nvme0n1') + ' input[type=checkbox][id^="ack-"]') + ').click()'); check(await ev('!' + wbtn('nvme0n1') + '.disabled'), 'tick + serial enables the override path');
    await ev(wbtn('vdb') + '.click()'); check(await waitFor('!!document.querySelector("dialog[open]")', 3000), 'write opens the destructive confirmation');
    check(await ev('document.querySelector("dialog[open] button.danger").disabled'), 'dialog confirm disabled until the serial is typed again');
    await setVal('dialog[open] input', 'TESTDISK01'); await click('dialog[open] button.danger');
    check(await waitFor('/Test passed/.test(document.querySelector(' + JSON.stringify(sec('vdb')) + ').innerText)', 8000, 'write result'), 'write test runs after double confirmation');

    console.log('layout, theme, accessibility');
    for (const [w, hgt] of [[1366, 768], [390, 844]]) {
      await c.send('Emulation.setDeviceMetricsOverride', { width: w, height: hgt, deviceScaleFactor: 1, mobile: w < 500 });
      for (const pg of ['overview', 'pcie', 'storage', 'network', 'actions', 'about']) {
        await ev('location.hash="#/' + pg + '"'); await sleep(900);
        check(await ev('document.documentElement.scrollWidth<=window.innerWidth+1'), 'no horizontal page scroll at ' + w + 'px on ' + pg);
      }
    }
    await c.send('Emulation.setDeviceMetricsOverride', { width: 1366, height: 768, deviceScaleFactor: 1, mobile: false });
    await click('#themebtn'); const th = await ev('document.documentElement.getAttribute("data-theme")'); check(th === 'light' || th === 'dark', 'theme toggle sets data-theme=' + th);
    check(await ev('!!document.querySelector("a.skip") && !!document.querySelector("nav[aria-label]") && !!document.querySelector("main#main") && document.documentElement.lang==="en"'), 'skip link, nav landmark, main landmark, lang');
    check(await ev('[...document.querySelectorAll("input[type=text],input[type=password],input[type=number],select")].every(e=>e.id&&document.querySelector("label[for=\\""+e.id+"\\"]")||e.getAttribute("aria-label")||e.closest("label"))'), 'every form control has a label');
    check(await ev('[...document.querySelectorAll("svg.chart")].every(s=>s.getAttribute("role")==="img"&&s.getAttribute("aria-label"))'), 'charts have text alternatives');
    check(await ev('(()=>{const f=[...document.querySelectorAll("button")].filter(b=>!b.textContent.trim()&&!b.getAttribute("aria-label"));return f.length===0})()'), 'no unnamed buttons');
    await click('#signout'); check(await waitFor('!!document.getElementById("keyline")', 3000, 'signed out'), 'forget keys returns to the login page');
    check(await ev('!sessionStorage.getItem("i7lab.ro") && !sessionStorage.getItem("i7lab.admin")'), 'forgetting clears sessionStorage');
    check(errors.length === 0, 'no console errors / exceptions' + (errors.length ? ': ' + errors.slice(0, 5).join(' | ') : ''));

    console.log('forged host (bad X-Lab-Proof)');
    await goto('http://127.0.0.1:' + BAD_PORT + '/');
    await waitFor('!!document.getElementById("keyline")', 5000);
    await setVal('#keyline', 'i7k1:ro:' + RO_HEX); await click('.login button.pri');
    check(await waitFor('/Verification failed/.test(document.body.innerText)', 5000, 'proof failure message'), 'a response with a wrong proof is rejected with a visible error');
    check(await ev('!document.getElementById("nav") || document.getElementById("nav").hidden || !sessionStorage.getItem("i7lab.ro")'), 'key not stored when the host fails verification');
    c.close();
  } finally { cleanup(); }
  console.log('\nbrowser-check: ' + passes + ' passed, ' + fails + ' failed');
  process.exit(fails ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(2); });
