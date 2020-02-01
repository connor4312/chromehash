const { Hasher } = require('./pkg/chromehash');
const fs = require('fs');
const { promisify } = require('util');
const { StringDecoder } = require('string_decoder');

const open = promisify(fs.open);
const read = promisify(fs.read);
const close = promisify(fs.close);

const output = Buffer.alloc(4 * 5);

exports.hash = input => {
  const hash = new Hasher();
  hash.update(normalize(input));
  hash.digest(output);
  hash.free();
  return output.toString('hex');
};

exports.hashFile = async (file, bufferSize = 4096) => {
  if (bufferSize % 2 === 1) {
    bufferSize++; // ensure buffer size is even for the swap16() in BE BOM reading.
  }

  const buf = Buffer.alloc(bufferSize);
  const hasher = new Hasher();

  let fd;
  try {
    fd = await open(file, 'r');

    let lastRead = await read(fd, buf, 0, buf.length, null);
    const bomBuf = buf.slice(0, lastRead.bytesRead);

    if (hasUtf16LEBOM(bomBuf)) {
      hasher.update(bomBuf.slice(2)); // add the trailing BOM read byte
      while (lastRead.bytesRead === buf.length) {
        lastRead = await read(fd, buf, 0, buf.length, null);
        hasher.update(buf.slice(0, lastRead.bytesRead));
      }
    } else if (hasUtf16BEBOM(bomBuf)) {
      hasher.update(bomBuf.slice(2).swap16()); // add the trailing BOM read byte
      while (lastRead.bytesRead === buf.length) {
        lastRead = await read(fd, buf, 0, buf.length, null);
        hasher.update(buf.slice(0, lastRead.bytesRead).swap16());
      }
    } else if (hasUTF8BOM(bomBuf)) {
      const decoder = new StringDecoder('utf8');
      hasher.update(Buffer.from(decoder.write(bomBuf.slice(3)), 'utf16le'));
      while (lastRead.bytesRead === buf.length) {
        lastRead = await read(fd, buf, 0, buf.length, null);
        hasher.update(Buffer.from(decoder.write(buf.slice(0, lastRead.bytesRead)), 'utf16le'));
      }
    } else {
      const decoder = new StringDecoder('utf8');
      hasher.update(Buffer.from(decoder.write(bomBuf), 'utf16le'));
      while (lastRead.bytesRead === buf.length) {
        lastRead = await read(fd, buf, 0, buf.length, null);
        hasher.update(Buffer.from(decoder.write(buf.slice(0, lastRead.bytesRead)), 'utf16le'));
      }
    }

    hasher.digest(output);
    return output.toString('hex');
  } finally {
    hasher.free();
    if (fd !== undefined) {
      await close(fd);
    }
  }
};

const hasUTF8BOM = buffer =>
  buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
const hasUtf16LEBOM = buffer => buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe;
const hasUtf16BEBOM = buffer => buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff;

const normalize = buffer => {
  if (hasUTF8BOM(buffer)) {
    return utf8ToUtf16(buffer.slice(3));
  }

  if (hasUtf16LEBOM(buffer)) {
    return buffer.slice(2);
  }

  if (hasUtf16BEBOM(buffer)) {
    return buffer.slice(2).swap16();
  }

  return utf8ToUtf16(buffer);
};

const utf8ToUtf16 = buffer => Buffer.from(buffer.toString('utf8'), 'utf16le');
