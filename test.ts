import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { hash, hashFile, shaHash, shaHashFile } from './index';

const testDir = path.join(__dirname, 'test-cases');
const testFiles = fs.readdirSync(testDir).filter(f => f.endsWith('.js'));

describe('chromehash', () => {
  const expectedHashes = new Map([
    ['blns.js', '3b33b447a9e19333659bb21c05ce7a0f414776b9'],
    ['simple.js', '1283dfddaa33715f0e953c443e071f361de1c9c5'],
    ['utf16be.js', '1283dfddaa33715f52d186d24885740d1de1c9c5'],
    ['utf16le.js', '1283dfddaa33715f52d186d24885740d1de1c9c5'],
    ['utf8-bom.js', '1283dfddaa33715f0e953c443e071f361de1c9c5'],
  ]);

  for (const filename of testFiles) {
    it(filename, async () => {
      const bufHash = hash(fs.readFileSync(path.join(testDir, filename)));
      assert.strictEqual(bufHash, expectedHashes.get(filename));

      const fileHash = await hashFile(path.join(testDir, filename));
      const fileHashSlow = await hashFile(path.join(testDir, filename), 5);
      assert.strictEqual(bufHash, fileHash);
      assert.strictEqual(fileHashSlow, fileHash);
    });
  }
});

describe('sha', () => {
  const expectedHashes = new Map([
    ['blns.js', 'bd2f90038c4ea269f2f610d3502de20f98eb2359eec6ed2da152c52cc861d596'],
    ['simple.js', 'a8217b64f8d6315a5e8fcdc751bff2069a118575d0d9327fc069fb4f060f04a2'],
    ['utf16be.js', 'f7bc3e22e6000869ab4a70052ee353336ac8ff9b63e8d2a343a4fe6e659def9a'],
    ['utf16le.js', 'f7bc3e22e6000869ab4a70052ee353336ac8ff9b63e8d2a343a4fe6e659def9a'],
    ['utf8-bom.js', 'a8217b64f8d6315a5e8fcdc751bff2069a118575d0d9327fc069fb4f060f04a2'],
  ]);

  for (const filename of testFiles) {

    it(filename, async () => {
      const bufHash = shaHash(fs.readFileSync(path.join(testDir, filename)));
      assert.strictEqual(bufHash, expectedHashes.get(filename));

      const fileHash = await shaHashFile(path.join(testDir, filename));
      const fileHashSlow = await shaHashFile(path.join(testDir, filename), 5);
      assert.strictEqual(bufHash, fileHash);
      assert.strictEqual(fileHashSlow, fileHash);
    });
  }
});

