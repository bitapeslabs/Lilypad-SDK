import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import * as noble_secp256k1 from "@noble/secp256k1";
import { ECPairInterface, bitcoin } from "../bitcoin-core";
noble_secp256k1.etc.hmacSha256Sync = (k, ...m) =>
  hmac(sha256, k, noble_secp256k1.etc.concatBytes(...m));

const MAGIC_BYTES = Buffer.from("Bitcoin Signed Message:\n");

function varintBufNum(n: number) {
  let buf;
  if (n < 253) {
    buf = Buffer.alloc(1);
    buf.writeUInt8(n, 0);
  } else if (n < 0x10000) {
    buf = Buffer.alloc(1 + 2);
    buf.writeUInt8(253, 0);
    buf.writeUInt16LE(n, 1);
  } else if (n < 0x100000000) {
    buf = Buffer.alloc(1 + 4);
    buf.writeUInt8(254, 0);
    buf.writeUInt32LE(n, 1);
  } else {
    buf = Buffer.alloc(1 + 8);
    buf.writeUInt8(255, 0);
    buf.writeInt32LE(n & -1, 1);
    buf.writeUInt32LE(Math.floor(n / 0x100000000), 5);
  }
  return buf;
}

function magicHash(message: string) {
  const prefix1 = varintBufNum(MAGIC_BYTES.length);
  const messageBuffer = Buffer.from(message);
  const prefix2 = varintBufNum(messageBuffer.length);
  const buf = Buffer.concat([prefix1, MAGIC_BYTES, prefix2, messageBuffer]);
  return bitcoin.crypto.hash256(buf);
}

export async function signMessageOfDeterministicECDSA(
  ecpair: ECPairInterface,
  message: string
): Promise<string> {
  if (!ecpair.privateKey) {
    throw new Error("Private key is required for signing message!");
  }
  const hash = magicHash(message);
  const signature = await noble_secp256k1.signAsync(
    Buffer.from(hash),
    ecpair.privateKey
  );
  return signature.toCompactHex();
}
