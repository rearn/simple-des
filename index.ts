import * as tac from 'type-array-convert';

enum cryptoType {
  encrypt = 0,
  decrypt = 1,
}

export class DES {
  private readonly blockSize: number = 8;

  private readonly keys: Uint32Array = new Uint32Array(16 * 2);

  constructor(key: Uint8Array) {
    if (key.length !== this.blockSize) {
      throw new Error('Invalid key length');
    }
    const shiftTable: Uint8Array = new Uint8Array([
      1, 1, 2, 2, 2, 2, 2, 2,
      1, 2, 2, 2, 2, 2, 2, 1,
    ]);

    const key32: Uint32Array = tac.uint8toUint32(key);

    let resultPc1: Uint32Array = this.pc1(key32);
    for (let i: number = 0; i < this.keys.length; i += 2) {
      const shift: number = shiftTable[i >>> 1];
      resultPc1 = resultPc1.map((value) => {
        return this.r28shl(value, shift);
      });
      this.keys.set(this.pc2(resultPc1), i);
    }
  }

  private pc1 = (inBuf: Uint32Array): Uint32Array => {
    let outL: number = 0;
    let outR: number = 0;

    // 7, 15, 23, 31, 39, 47, 55, 63
    // 6, 14, 22, 30, 39, 47, 55, 63
    // 5, 13, 21, 29, 39, 47, 55, 63
    // 4, 12, 20, 28
    let i: number;
    for (i = 7; i >= 5; i -= 1) {
      for (let j: number = 0; j <= 24; j += 8) {
        outL <<= 1;
        outL |= (inBuf[1] >> (j + i)) & 1;
      }
      for (let j: number = 0; j <= 24; j += 8) {
        outL <<= 1;
        outL |= (inBuf[0] >> (j + i)) & 1;
      }
    }
    for (let j: number = 0; j <= 24; j += 8) {
      outL <<= 1;
      outL |= (inBuf[1] >> (j + i)) & 1;
    }

    // 1, 9, 17, 25, 33, 41, 49, 57
    // 2, 10, 18, 26, 34, 42, 50, 58
    // 3, 11, 19, 27, 35, 43, 51, 59
    // 36, 44, 52, 60
    for (i = 1; i <= 3; i += 1) {
      for (let j: number = 0; j <= 24; j += 8) {
        outR <<= 1;
        outR |= (inBuf[1] >> (j + i)) & 1;
      }
      for (let j: number = 0; j <= 24; j += 8) {
        outR <<= 1;
        outR |= (inBuf[0] >> (j + i)) & 1;
      }
    }
    for (let j: number = 0; j <= 24; j += 8) {
      outR <<= 1;
      outR |= (inBuf[0] >> (j + i)) & 1;
    }

    return new Uint32Array([outL >>> 0, outR >>> 0]);
  }

  private r28shl = (num: number, shift: number): number => {
    return ((num << shift) & 0xfffffff) | (num >>> (28 - shift));
  }

  private pc2 = (inBuf: Uint32Array) => {
    let outL: number = 0;
    let outR: number = 0;

    const pc2table: Uint8Array = new Uint8Array([
      // inL => outL
      14, 11, 17, 4, 27, 23, 25, 0,
      13, 22, 7, 18, 5, 9, 16, 24,
      2, 20, 12, 21, 1, 8, 15, 26,

      // inR => outR
      15, 4, 25, 19, 9, 1, 26, 16,
      5, 11, 23, 8, 12, 7, 17, 0,
      22, 3, 10, 14, 6, 20, 27, 24,
    ]);

    const len: number = pc2table.length >>> 1;
    for (let i: number = 0; i < len; i += 1) {
      outL <<= 1;
      outL |= (inBuf[0] >>> pc2table[i]) & 0x1;
    }
    for (let i: number = len; i < pc2table.length; i += 1) {
      outR <<= 1;
      outR |= (inBuf[1] >>> pc2table[i]) & 0x1;
    }

    return new Uint32Array([outL >>> 0, outR >>> 0]);
  }

  public encrypt = (data: Uint8Array): Uint8Array => {
    return this.update(data, cryptoType.encrypt);
  }

  public decrypt = (data: Uint8Array): Uint8Array => {
    return this.update(data, cryptoType.decrypt);
  }

  private update = (data: Uint8Array, type: cryptoType): Uint8Array => {
    if (data.length === 0) {
      return new Uint8Array(0);
    }
    if (data.length % this.blockSize !== 0) {
      throw new Error('Invalid data length');
    }

    const in32: Uint32Array = tac.uint8toUint32(data);
    const out: Uint32Array = new Uint32Array(in32.length);

    // Write blocks
    for (let i: number = 0; i < in32.length; i += 2) {
      out.set(this.update64bit(in32.slice(i, i + 2), type), i);
    }
    return tac.uint32toUint8(out);
  }

  private update64bit = (inp: Uint32Array, type: cryptoType): Uint32Array => {
    // Initial Permutation
    const inBuf: Uint32Array = this.ip(inp);

    const outBuf: Uint32Array = (
      (f: Function): Uint32Array => {
        return f(inBuf);
      })(type === cryptoType.encrypt
          ? this.encrypt64bit
          : this.decrypt64bit);

    // Reverse Initial Permutation
    const out32: Uint32Array = this.rip(outBuf);

    return out32;
  }

  private encrypt64bit = (start: Uint32Array): Uint32Array => {
    let outBuf: Uint32Array = start.slice();

    // Apply f() x16 times
    for (let i: number = 0; i < this.keys.length; i += 2) {
      outBuf = this.fFunction(outBuf, this.keys.slice(i, i + 2));
    }
    return outBuf.reverse();
  }

  private decrypt64bit = (start: Uint32Array): Uint32Array => {
    let outBuf: Uint32Array = start.slice();

    // Apply f() x16 times
    for (let i: number = this.keys.length - 2; i >= 0; i -= 2) {
      outBuf = this.fFunction(outBuf, this.keys.slice(i, i + 2));
    }
    return outBuf.reverse();
  }

  private fFunction = (inBuf: Uint32Array, key: Uint32Array): Uint32Array => {
    // f(r, k)
    const resultF: Uint32Array = this.expand(inBuf[1]);
    const newKey = key.map((value, index) => {
      return value ^ resultF[index];
    });
    const s: number = this.substitute(newKey);
    const f: number = this.permute(s);
    return new Uint32Array([inBuf[1], (inBuf[0] ^ f) >>> 0]);
  }

  private ip = (inBuf: Uint32Array): Uint32Array => {
    let outL: number = 0;
    let outR: number = 0;

    for (let i: number = 6; i >= 0; i -= 2) {
      for (let j: number = 0; j <= 24; j += 8) {
        outL <<= 1;
        outL |= (inBuf[1] >>> (j + i)) & 1;
      }
      for (let j: number = 0; j <= 24; j += 8) {
        outL <<= 1;
        outL |= (inBuf[0] >>> (j + i)) & 1;
      }
    }

    for (let i: number = 6; i >= 0; i -= 2) {
      for (let j: number = 1; j <= 25; j += 8) {
        outR <<= 1;
        outR |= (inBuf[1] >>> (j + i)) & 1;
      }
      for (let j: number = 1; j <= 25; j += 8) {
        outR <<= 1;
        outR |= (inBuf[0] >>> (j + i)) & 1;
      }
    }

    return new Uint32Array([outL >>> 0, outR >>> 0]);
  }

  private rip = (inBuf: Uint32Array): Uint32Array => {
    let outL: number = 0;
    let outR: number = 0;

    for (let i: number = 0; i < 4; i += 1) {
      for (let j: number = 24; j >= 0; j -= 8) {
        outL <<= 1;
        outL |= (inBuf[1] >>> (j + i)) & 1;
        outL <<= 1;
        outL |= (inBuf[0] >>> (j + i)) & 1;
      }
    }
    for (let i: number = 4; i < 8; i += 1) {
      for (let j: number = 24; j >= 0; j -= 8) {
        outR <<= 1;
        outR |= (inBuf[1] >>> (j + i)) & 1;
        outR <<= 1;
        outR |= (inBuf[0] >>> (j + i)) & 1;
      }
    }

    return new Uint32Array([outL >>> 0, outR >>> 0]);
  }

  private expand = (r: number): Uint32Array => {
    let outL: number = 0;
    let outR: number = 0;

    outL = ((r & 1) << 5) | (r >>> 27);
    for (let i: number = 23; i >= 15; i -= 4) {
      outL <<= 6;
      outL |= (r >>> i) & 0x3f;
    }
    for (let i: number = 11; i >= 3; i -= 4) {
      outR |= (r >>> i) & 0x3f;
      outR <<= 6;
    }
    outR |= ((r & 0x1f) << 1) | (r >>> 31);

    return new Uint32Array([outL >>> 0, outR >>> 0]);
  }

  private substitute = (inbuf: Uint32Array): number => {
    const sTable: Uint8Array = new Uint8Array([
      14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
      3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
      4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
      15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13,

      15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
      9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
      0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
      5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9,

      10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
      1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
      13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
      11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12,

      7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
      1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
      10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
      15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14,

      2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
      8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
      4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
      15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3,

      12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
      0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
      9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
      7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13,

      4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
      3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
      1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
      10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12,

      13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
      10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
      7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
      0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11,
    ]);

    let out: number = 0;
    for (let i: number = 0; i < 4; i += 1) {
      const b: number = (inbuf[0] >>> (18 - i * 6)) & 0x3f;
      const sb: number = sTable[i * 0x40 + b];

      out <<= 4;
      out |= sb;
    }
    for (let i: number = 0; i < 4; i += 1) {
      const b: number = (inbuf[1] >>> (18 - i * 6)) & 0x3f;
      const sb: number = sTable[4 * 0x40 + i * 0x40 + b];

      out <<= 4;
      out |= sb;
    }
    return out >>> 0;
  }

  private permute = (num: number): number => {
    let out: number = 0;
    const permuteTable: Uint8Array = new Uint8Array([
      16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22,
      30, 24, 8, 18, 0, 5, 29, 23, 13, 19, 2, 26, 10, 21, 28, 7,
    ]);
    for (let i: number = 0; i < permuteTable.length; i += 1) {
      out <<= 1;
      out |= (num >>> permuteTable[i]) & 0x1;
    }
    return out >>> 0;
  }
}
