import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import HDKey from "hdkey";
import { payments, networks, Network } from "bitcoinjs-lib";
import { createHash } from "crypto";
import bs58check from "bs58check";
const sha256 = (data) => {
  return createHash("sha256").update(data).digest("hex");
};

// You must wrap a tiny-secp256k1 compatible implementation

/* Wallet creation */
const generateMnemonic = () => bip39.generateMnemonic(wordlist);

const protocolId = "0"; // valid and registered on BIP44

/*

  protocolId: rbbt1U16ksRSG rb1+bs58(bip44 registered protocol id)
  bip44-path: the registred protocol id on BIP44: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
  Ribbit will treat each protocol as if it were a seperate "chain" entirely.  (BIP)

  For simplicity purposes, native bitcoin (DESPITE THE CHAIN) will always have coin type 0. This is similar to what
  unisat does

  SwitchProtocol(protocolId) -> bs58Decode(id.slice(4)) -> inserted in HDPATH
*/

const protocolSalt = "rbbt" + bs58check.encode(Buffer.from(protocolId));

const validateMnemonic = (mnemonic: string) =>
  bip39.validateMnemonic(mnemonic, wordlist);

const HDPATH = `m/44'/${protocolId}'/0'/0`;

const createAddress = async (network: Network): Promise<void> => {
  const mnemonic =
    "dish old elder submit faith mule ticket cool stomach car isolate cherry"; // generateMnemonic();
  if (!validateMnemonic(mnemonic)) {
    return console.log("Invalid mnemonic!");
  }

  // Generate seed from mnemonic
  const seed = await bip39.mnemonicToSeed(mnemonic, "");
  const hdkey = HDKey.fromMasterSeed(Buffer.from(seed));

  // Derive the child key at the specified path
  const wallet = hdkey.derive(HDPATH);

  console.log("Mnemonic: ", mnemonic);

  const child = wallet.deriveChild(0);
  const { address } = payments.p2pkh({
    pubkey: child.publicKey,
    network,
  });

  console.dir(address);
  console.log("protocolSalt: ", protocolSalt);
  console.log("protocolId: ", protocolId);
};

createAddress(networks.testnet);
