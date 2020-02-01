const { hash, hashFile } = require('./');
const fs = require('fs');

bench('file', () => hashFile('./test-cases/blns.js'))
bench('buffer', () => hash(fs.readFileSync('./test-cases/blns.js')))
