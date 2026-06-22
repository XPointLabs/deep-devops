const mask64 = 0xffffffffffffffffn;
const iv = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n
];

const sigma = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
];

function rotr64(value, shift) {
  const bits = BigInt(shift);
  return ((value >> bits) | (value << (64n - bits))) & mask64;
}

function readUint64LE(bytes, offset) {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    value |= BigInt(bytes[offset + index] ?? 0) << (8n * BigInt(index));
  }
  return value;
}

function writeUint64LE(value, bytes, offset) {
  for (let index = 0; index < 8; index += 1) {
    bytes[offset + index] = Number((value >> (8n * BigInt(index))) & 0xffn);
  }
}

function normalizeBytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
    return value;
  }

  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  throw new TypeError('Expected ArrayBuffer or typed array input');
}

function compress(state, block, offset, counter, isLast) {
  const message = new Array(16);
  for (let index = 0; index < 16; index += 1) {
    message[index] = readUint64LE(block, offset + index * 8);
  }

  const work = [...state, ...iv];
  work[12] ^= counter & mask64;
  work[13] ^= counter >> 64n;
  if (isLast) {
    work[14] ^= mask64;
  }

  const mix = (a, b, c, d, x, y) => {
    work[a] = (work[a] + work[b] + x) & mask64;
    work[d] = rotr64(work[d] ^ work[a], 32);
    work[c] = (work[c] + work[d]) & mask64;
    work[b] = rotr64(work[b] ^ work[c], 24);
    work[a] = (work[a] + work[b] + y) & mask64;
    work[d] = rotr64(work[d] ^ work[a], 16);
    work[c] = (work[c] + work[d]) & mask64;
    work[b] = rotr64(work[b] ^ work[c], 63);
  };

  for (let round = 0; round < 12; round += 1) {
    const schedule = sigma[round];
    mix(0, 4, 8, 12, message[schedule[0]], message[schedule[1]]);
    mix(1, 5, 9, 13, message[schedule[2]], message[schedule[3]]);
    mix(2, 6, 10, 14, message[schedule[4]], message[schedule[5]]);
    mix(3, 7, 11, 15, message[schedule[6]], message[schedule[7]]);
    mix(0, 5, 10, 15, message[schedule[8]], message[schedule[9]]);
    mix(1, 6, 11, 12, message[schedule[10]], message[schedule[11]]);
    mix(2, 7, 8, 13, message[schedule[12]], message[schedule[13]]);
    mix(3, 4, 9, 14, message[schedule[14]], message[schedule[15]]);
  }

  for (let index = 0; index < 8; index += 1) {
    state[index] = state[index] ^ work[index] ^ work[index + 8];
  }
}

export function blake2b(input, options = {}) {
  const digestLength = options.digestLength ?? 64;
  if (!Number.isInteger(digestLength) || digestLength < 1 || digestLength > 64) {
    throw new RangeError('digestLength must be an integer between 1 and 64');
  }

  const bytes = normalizeBytes(input);
  const param = new Uint8Array(64);
  param[0] = digestLength;
  param[2] = 1;
  param[3] = 1;

  if (options.salt != null) {
    const salt = normalizeBytes(options.salt);
    if (salt.length > 16) {
      throw new RangeError('salt must be at most 16 bytes');
    }
    param.set(salt, 32);
  }

  const state = iv.map((value, index) => value ^ readUint64LE(param, index * 8));
  let counter = 0n;
  let offset = 0;

  while (offset + 128 < bytes.length) {
    counter += 128n;
    compress(state, bytes, offset, counter, false);
    offset += 128;
  }

  const lastBlock = new Uint8Array(128);
  const tail = bytes.subarray(offset);
  lastBlock.set(tail);
  counter += BigInt(tail.length);
  compress(state, lastBlock, 0, counter, true);

  const output = new Uint8Array(64);
  for (let index = 0; index < 8; index += 1) {
    writeUint64LE(state[index], output, index * 8);
  }

  return output.subarray(0, digestLength);
}