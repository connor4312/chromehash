const path = require('path');
const fs = require('fs');
const assert = require('assert');
const url = require('url');
const { hash } = require('./');
const { chromium } = require('playwright');

const testDir = path.join(__dirname, 'test-cases');
const testFiles = fs.readdirSync(testDir).filter(f => f.endsWith('.js'));
const expectedHashes = new Map();

// We need to use Chrome to test it fully, as Node.js cannot require scripts
// that have UTF-16 BOMs.

let browser;
let cdp;
before(async () => {
  browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage('about:blank');

  // grab a CDP session manually since playwright doesn't expose scriptParsed events to us
  cdp = await browser.pageTarget(page).createCDPSession();

  const parsingDone = new Promise(resolve => {
    let todo = testFiles.length;
    cdp.on('Debugger.scriptParsed', evt => {
      expectedHashes.set(evt.url.split('/').pop(), evt.hash);
      if (--todo === 0) {
        resolve();
      }
    });
  });

  await cdp.send('Debugger.enable');
  await page.goto(url.pathToFileURL(path.join(testDir, 'index.html')));
  await parsingDone;
});

after(async () => {
  await browser.close();
});

for (const filename of testFiles) {
  it(filename, async () => {
    const actual = hash(fs.readFileSync(path.join(testDir, filename)));
    assert.strictEqual(actual, expectedHashes.get(filename));
  });

  it(`${filename} file hash matches buffer`, () => {
    const bufHash = hash(fs.readFileSync(path.join(testDir, filename)));
    const fileHash = hash(fs.readFileSync(path.join(testDir, filename)));
    assert.strictEqual(bufHash, fileHash);
  });
}
