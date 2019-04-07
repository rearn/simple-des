import { DES } from '.';

const rand = (): number => {
  return Math.floor(Math.random() * 0x100);
};
const keys = (new Uint8Array(8)).map(rand);
const u8array = (new Uint8Array(64)).map(rand);

const des = new DES(keys);
test('reverse', () => {
  expect(des.decrypt(des.encrypt(u8array)))
    .toMatchObject(u8array);
});

const des1 = new DES(new Uint8Array([
  97, 98, 99, 100, 101, 102, 103, 104,
])); // 'abcdefgh'
const ff = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0xff,
]); // 255
const ffDes = new Uint8Array([
  0x21, 0xec, 0xdb, 0xc1, 0xa8, 0x5a, 0xe0, 0xe2,
]); // '!\xec\xdb\xc1\xa8Z\xe0\xe2'
test('255', () => {
  expect(des1.encrypt(ff))
    .toMatchObject(ffDes);
});

test('255 reverse', () => {
  expect(des1.decrypt(ffDes))
    .toMatchObject(ff);
});
