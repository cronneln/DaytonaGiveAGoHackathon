/**
 * Dependency Auditor — Sandbox Harness
 * Runs inside an isolated Daytona workspace. Monkey-patches Node.js internals
 * BEFORE requiring the target package, then reports all suspicious behavior as JSON.
 *
 * Usage: node harness.js <package-name>
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');

const pkg = process.argv[2];
if (!pkg) { console.error('Usage: node harness.js <package-name>'); process.exit(1); }

// Validate package name to prevent path traversal or injection
const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
if (!NPM_NAME_RE.test(pkg)) {
  console.error(`Invalid package name: ${pkg}`);
  process.exit(1);
}

const report = {
  package: pkg,
  networkCalls: [],
  fileSystemWrites: [],
  fileSystemReads: [],
  envVarAccess: [],
  cpuAnomaly: false,
  cpuUserRatioMax: 0,
  errors: [],
  timestamp: Date.now(),
};

// ── CPU baseline ──────────────────────────────────────────────────────────────
const cpuStart = os.cpus().map(c => ({ ...c.times }));

// ── Network interception ──────────────────────────────────────────────────────
function interceptRequest(module, protocol) {
  const orig = module.request.bind(module);
  module.request = function (opts, cb) {
    try {
      const host = typeof opts === 'string'
        ? new URL(opts).hostname
        : (opts.hostname || opts.host || 'unknown');
      const port = typeof opts === 'string'
        ? new URL(opts).port
        : (opts.port || (protocol === 'https' ? 443 : 80));
      const path = typeof opts === 'string'
        ? new URL(opts).pathname
        : (opts.path || '/');
      report.networkCalls.push({ protocol, host, port, path, time: Date.now() });
    } catch (_) {}
    return orig(opts, cb);
  };
  // Also patch .get()
  module.get = function (opts, cb) { return module.request(opts, cb); };
}
interceptRequest(http, 'http');
interceptRequest(https, 'https');

// ── File system interception ──────────────────────────────────────────────────
const SENSITIVE_PATHS = ['.ssh', '.aws', '.env', 'password', 'secret', 'token', 'credential', 'id_rsa', 'private_key'];

const origWriteFile = fs.writeFile.bind(fs);
fs.writeFile = function (p, ...args) {
  report.fileSystemWrites.push({ path: String(p), time: Date.now() });
  return origWriteFile(p, ...args);
};
const origWriteFileSync = fs.writeFileSync.bind(fs);
fs.writeFileSync = function (p, ...args) {
  report.fileSystemWrites.push({ path: String(p), time: Date.now() });
  return origWriteFileSync(p, ...args);
};
const origAppendFile = fs.appendFile.bind(fs);
fs.appendFile = function (p, ...args) {
  report.fileSystemWrites.push({ path: String(p), time: Date.now() });
  return origAppendFile(p, ...args);
};
const origAppendFileSync = fs.appendFileSync.bind(fs);
fs.appendFileSync = function (p, ...args) {
  report.fileSystemWrites.push({ path: String(p), time: Date.now() });
  return origAppendFileSync(p, ...args);
};

// ── fs.promises interception (promise-based API bypasses sync patches) ────────
const origFsPromisesWriteFile = fs.promises.writeFile.bind(fs.promises);
fs.promises.writeFile = function (p, ...args) {
  report.fileSystemWrites.push({ path: String(p), time: Date.now() });
  return origFsPromisesWriteFile(p, ...args);
};
const origFsPromisesAppendFile = fs.promises.appendFile.bind(fs.promises);
fs.promises.appendFile = function (p, ...args) {
  report.fileSystemWrites.push({ path: String(p), time: Date.now() });
  return origFsPromisesAppendFile(p, ...args);
};
const origFsPromisesReadFile = fs.promises.readFile.bind(fs.promises);
fs.promises.readFile = function (p, ...args) {
  const sp = String(p).toLowerCase();
  if (SENSITIVE_PATHS.some(s => sp.includes(s))) {
    report.fileSystemReads.push({ path: String(p), suspicious: true, time: Date.now() });
  }
  return origFsPromisesReadFile(p, ...args);
};

const origReadFile = fs.readFile.bind(fs);
fs.readFile = function (p, ...args) {
  const sp = String(p).toLowerCase();
  if (SENSITIVE_PATHS.some(s => sp.includes(s))) {
    report.fileSystemReads.push({ path: String(p), suspicious: true, time: Date.now() });
  }
  return origReadFile(p, ...args);
};
const origReadFileSync = fs.readFileSync.bind(fs);
fs.readFileSync = function (p, ...args) {
  const sp = String(p).toLowerCase();
  if (SENSITIVE_PATHS.some(s => sp.includes(s))) {
    report.fileSystemReads.push({ path: String(p), suspicious: true, time: Date.now() });
  }
  return origReadFileSync(p, ...args);
};

// ── Environment variable interception ────────────────────────────────────────
const SENSITIVE_ENV = ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PASS', 'AWS', 'GITHUB', 'NPM_', 'AUTH', 'CREDENTIAL', 'PRIVATE'];
try {
  process.env = new Proxy(process.env, {
    get(target, key) {
      if (SENSITIVE_ENV.some(p => String(key).toUpperCase().includes(p))) {
        report.envVarAccess.push({ key: String(key), time: Date.now() });
      }
      return target[key];
    }
  });
} catch (_) { /* Proxy may not work on all Node versions */ }

// ── child_process interception (spawn/exec bypass network intercepts) ─────────
try {
  const cp = require('child_process');
  ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'].forEach(method => {
    if (typeof cp[method] !== 'function') return;
    const orig = cp[method].bind(cp);
    cp[method] = function (cmd, ...args) {
      report.networkCalls.push({ protocol: 'child_process', host: String(cmd).slice(0, 200), port: null, path: null, time: Date.now() });
      return orig(cmd, ...args);
    };
  });
} catch (_) {}

// ── net.createConnection interception (raw TCP bypasses http/https) ───────────
try {
  const net = require('net');
  const origNetConnect = net.createConnection.bind(net);
  net.createConnection = net.connect = function (opts, ...args) {
    const host = opts && typeof opts === 'object' ? (opts.host || 'unknown') : String(opts);
    const port = opts && typeof opts === 'object' ? (opts.port || null) : null;
    report.networkCalls.push({ protocol: 'tcp', host, port, path: null, time: Date.now() });
    return origNetConnect(opts, ...args);
  };
} catch (_) {}

// ── global.fetch interception (Node 18+ built-in fetch bypasses http patches) ─
try {
  if (typeof globalThis.fetch === 'function') {
    const origFetch = globalThis.fetch.bind(globalThis);
    globalThis.fetch = function (input, ...args) {
      try {
        const url = typeof input === 'string' ? new URL(input) : new URL(input.url);
        report.networkCalls.push({ protocol: 'fetch', host: url.hostname, port: url.port || null, path: url.pathname, time: Date.now() });
      } catch (_) {}
      return origFetch(input, ...args);
    };
  }
} catch (_) {}

// ── dns interception (DNS exfiltration via TXT/MX/A lookups) ─────────────────
try {
  const dns = require('dns');
  ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveMx'].forEach(method => {
    if (typeof dns[method] !== 'function') return;
    const orig = dns[method].bind(dns);
    dns[method] = function (hostname, ...args) {
      report.networkCalls.push({ protocol: 'dns', host: String(hostname), port: null, path: null, time: Date.now() });
      return orig(hostname, ...args);
    };
  });
} catch (_) {}

// ── Import the package and attempt to call exports ───────────────────────────
try {
  const mod = require(pkg);
  if (typeof mod === 'function') { try { mod(); } catch (_) {} }
  if (mod && typeof mod.default === 'function') { try { mod.default(); } catch (_) {} }
  if (mod && typeof mod.main === 'function') { try { mod.main(); } catch (_) {} }
} catch (e) {
  report.errors.push(e.message);
}

// ── Wait for async side-effects, then report ─────────────────────────────────
setTimeout(() => {
  // CPU spike check
  const cpuEnd = os.cpus().map(c => c.times);
  const anomalies = cpuEnd.map((end, i) => {
    const start = cpuStart[i];
    const user = end.user - start.user;
    const sys = end.sys - start.sys;
    const idle = end.idle - start.idle;
    const total = user + sys + idle;
    return total > 0 ? user / total : 0;
  });
  report.cpuUserRatioMax = anomalies.length ? Math.max(...anomalies) : 0;
  report.cpuAnomaly = anomalies.some(u => u > 0.75);

  process.stdout.write(JSON.stringify(report) + '\n');
  process.exit(0);
}, 8000);
