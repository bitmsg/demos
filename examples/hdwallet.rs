use bip39::{Mnemonic, Language, Seed};
use hdwallet::{ExtendedPrivKey, DefaultKeyChain, Derivation, ExtendedPubKey};
use hdwallet::key_chain::KeyChain;
use ring::digest;
use base58::ToBase58;
use ripemd160::Ripemd160;
use ripemd160::Digest;
use secp256k1::{PublicKey, Secp256k1, SignOnly, VerifyOnly};
use bs58;
use bitcoincash_addr::{Address, Network, Scheme};
use bech32::{ToBase32, u5};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

fn main() {
	let phrase = "chat occur neutral super jar cruise then fragile track high check term";

	let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

	let seed = Seed::new(&mnemonic, "");

	println!("seed = {:?}", seed);

	let master_key = ExtendedPrivKey::with_seed(seed.as_bytes()).unwrap();

	btc_derivation(DefaultKeyChain::new(master_key.clone()));

	btc84_derivation(DefaultKeyChain::new(master_key.clone()));

	eth_derivation(DefaultKeyChain::new(master_key.clone()));

	xrp_derivation(DefaultKeyChain::new(master_key.clone()));

	bch_derivation(DefaultKeyChain::new(master_key.clone()));

	ltc_derivation(DefaultKeyChain::new(master_key.clone()));

	bnb_derivation(DefaultKeyChain::new(master_key.clone()));

	trx_derivation(DefaultKeyChain::new(master_key.clone()));

}

fn btc_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BTC:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/0'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/0'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = btc_wif(&from_hex(&format!("{}", private_key)));
	let address = btc_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "1Bi6zFVNtntP5MtDraNrAD7e469ifsQMwF");
}

fn btc84_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BTC84:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/84'/0'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/84'/0'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = btc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(public_key, "bc", Some(0));

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "bc1qfvfvf72ydl745z2mnsd2p99n40tc3dlx6j5t3e");
}

fn eth_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("ETH:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/60'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/60'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = &format!("{}", private_key);
	let address = eth_address(public_key);

	println!("  address#0 private key = 0x{}", private_key);
	println!("  address#0 public key = 0x{}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "0x4c08adcf537d33b282c11f3f8f6a83e6cc48e0a0");
}

fn xrp_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("XRP:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/144'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/144'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = &format!("{}", private_key);
	let address = xrp_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "rDMNKAkDBdzpUqxctgBW5r7bpDLZTAdMF4");
}

fn bch_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BCH:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/145'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/145'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = btc_wif(&from_hex(&format!("{}", private_key)));
	let address = bch_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "bitcoincash:qraupdqydy3cnds2x647rnc3krqdjtt4y59azfs7e3");
}

fn ltc_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("LTC:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/84'/2'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<Btc84Strategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/84'/2'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(public_key,  "ltc", Some(0));

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "ltc1qn6wqy5kytcyt532q2t6wku8rnf0q6lr2pyyrtq");
}

fn bnb_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("BNB:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/714'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/714'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = bech32_address(public_key,  "bnb", None);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "bnb1ktsp45pjwqm9n4qsdpzztaumvx5qla5crknwps");
}


fn trx_derivation(key_chain: DefaultKeyChain) {
	let (master_key, derivation) = key_chain.derive_private_key("m".into()).unwrap();

	let key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(master_key), &derivation);

	println!("TRX:");
	println!("  root key = {}", key);

	let (account_key, derivation) = key_chain.derive_private_key("m/44'/195'/0'".into()).unwrap();

	let account_extended_pub_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PubKey(ExtendedPubKey::from_private_key(&account_key)), &derivation);
	let account_extended_priv_key = serialize_extended_key::<BtcStrategy>(ExtendedKey::PrivKey(account_key), &derivation);

	println!("  account extended priv key = {}", account_extended_priv_key);
	println!("  account extended pub key = {}", account_extended_pub_key);

	let (key, _derivation) = key_chain.derive_private_key("m/44'/195'/0'/0/0".into()).unwrap();

	let private_key = key.private_key;

	let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &private_key);
	let private_key = ltc_wif(&from_hex(&format!("{}", private_key)));
	let address = trx_address(public_key);

	println!("  address#0 private key = {}", private_key);
	println!("  address#0 public key = {}", public_key);
	println!("  address#0 address = {}", address);

	assert_eq!(address, "TWZWdFSL6Kcn7hfAg6SHiGixUP5efEaBtW");
}


enum ExtendedKey {
	PrivKey(ExtendedPrivKey),
	PubKey(ExtendedPubKey),
}

trait Strategy{
	fn version_bytes() -> (Vec<u8>, Vec<u8>);
}

struct BtcStrategy;

impl Strategy for BtcStrategy {
	fn version_bytes() -> (Vec<u8>, Vec<u8>){
			(from_hex("0x0488ADE4"), from_hex("0x0488B21E"))
	}
}

struct Btc84Strategy;

impl Strategy for Btc84Strategy {
	fn version_bytes() -> (Vec<u8>, Vec<u8>){
		(from_hex("0x04b2430c"), from_hex("0x04b24746"))
	}
}

fn serialize_extended_key<S: Strategy>(extended_key: ExtendedKey, derivation: &Derivation) -> String {

	let version_bytes = S::version_bytes();
	let version_bytes = match extended_key {
		ExtendedKey::PrivKey(_) => version_bytes.0,
		ExtendedKey::PubKey(_) => version_bytes.1,
	};

	let parent_fingerprint = match derivation.parent_key {
		Some(ref key) => {
			let pubkey = ExtendedPubKey::from_private_key(key);
			let buf = digest::digest(&digest::SHA256, &pubkey.public_key.serialize());
			let mut hasher = Ripemd160::new();
			hasher.input(&buf.as_ref());
			hasher.result()[0..4].to_vec()
		}
		None => vec![0; 4],
	};

	let mut buf: Vec<u8> = Vec::with_capacity(112);
	buf.extend_from_slice(&version_bytes);
	buf.extend_from_slice(&derivation.depth.to_be_bytes());
	buf.extend_from_slice(&parent_fingerprint);
	match derivation.key_index {
		Some(key_index) => {
			buf.extend_from_slice(&key_index.raw_index().to_be_bytes());
		}
		None => buf.extend_from_slice(&[0; 4]),
	}
	match extended_key {
		ExtendedKey::PrivKey(ref key) => {
			buf.extend_from_slice(&key.chain_code);
			buf.extend_from_slice(&[0]);
			buf.extend_from_slice(&key.private_key[..]);
		}
		ExtendedKey::PubKey(ref key) => {
			buf.extend_from_slice(&key.chain_code);
			buf.extend_from_slice(&key.public_key.serialize());
		}
	}
	assert_eq!(buf.len(), 78);

	let check_sum = {
		let buf = digest::digest(&digest::SHA256, &buf);
		digest::digest(&digest::SHA256, &buf.as_ref())
	};

	buf.extend_from_slice(&check_sum.as_ref()[0..4]);
	(&buf).to_base58()
}

fn from_hex(hex_string: &str) -> Vec<u8> {
	if hex_string.starts_with("0x") {
		hex::decode(&hex_string[2..]).expect("decode")
	} else {
		hex::decode(hex_string).expect("decode")
	}
}

fn to_hex(buf: &[u8]) -> String{
	hex::encode(buf)
}

fn btc_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize();
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let buf = hasher.result().to_vec();
	let mut a = Vec::new();
	a.push(0x00);
	a.extend(buf);
	bs58::encode(&a).with_check().into_string()
}

fn btc_wif(private_key: &[u8]) -> String {
	let mut a = Vec::new();
	a.push(0x80);
	a.extend(private_key);
	a.push(0x01);
	bs58::encode(a).with_check().into_string()
}

fn ltc_wif(private_key: &[u8]) -> String {
	let mut a = Vec::new();
	a.push(0xB0);
	a.extend(private_key);
	a.push(0x01);
	bs58::encode(a).with_check().into_string()
}

fn eth_address(public_key: PublicKey) -> String {

	let public_key = public_key.serialize_uncompressed();

	let public_key = &public_key[1..];

	let mut hasher = sha3::Keccak256::default();
	hasher.input(public_key);

	let out = hasher.result();

	let out = to_hex(&out.as_slice()[12..32]);

	format!("0x{}", out)
}

fn xrp_address(public_key: PublicKey) -> String {

	let public_key = public_key.serialize();
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let buf = hasher.result().to_vec();
	let mut a = Vec::new();
	a.push(0x00);
	a.extend(buf);
	bs58::encode(&a).with_alphabet(bs58::alphabet::RIPPLE).with_check().into_string()
}

fn bch_address(public_key: PublicKey) -> String {
	let public_key = public_key.serialize();
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let buf = hasher.result().to_vec();
	let mut a = Vec::new();
	a.push(0x00);
	a.extend(buf);
	let address = bs58::encode(&a).with_check().into_string();

	let mut address= Address::decode(&address).unwrap();
	address.network = Network::Main;
	address.scheme = Scheme::CashAddr;

	address.encode().unwrap()
}

// https://bitcointalk.org/index.php?topic=4992632.0
// some coin does not have a segwit version, like BNB: https://docs.binance.org/blockchain.html#address
fn bech32_address(public_key: PublicKey, hrp: &str, segwit_version: Option<u8>) -> String {
	let public_key = &public_key.serialize()[..];
	let buf = digest::digest(&digest::SHA256, &public_key);
	let mut hasher = Ripemd160::new();
	hasher.input(&buf.as_ref());
	let mut buf = hasher.result().to_vec().to_base32();
	if let Some(segwit_version) = segwit_version {
		buf.insert(0, u5::try_from_u8(segwit_version).unwrap());
	}
	let b = bech32::encode(
		hrp,
		buf
	).unwrap();
	let encoded = b.to_string();
	encoded
}

fn trx_address(public_key: PublicKey) -> String {

	let public_key = public_key.serialize_uncompressed();

	let public_key = &public_key[1..];

	let mut hasher = sha3::Keccak256::default();
	hasher.input(public_key);

	let out = hasher.result();

	let out = &out.as_slice()[12..32];

	let mut a = Vec::new();
	a.push(0x41);
	a.extend(out);
	bs58::encode(&a).with_check().into_string()
}

