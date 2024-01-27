import fromSeed from './BIP32/fromSeed.js';
import derive from './BIP32/derive.js';
import bip39 from './BIP39/bip39.js';
import ecdsa from './ECDSA/ecdsa.js';

import { standardKey, address } from './utilities/getKeys.js';
import ThresholdSignature from './Threshold-signature/threshold_signature.js';
import BN from 'bn.js';
import { Point } from "@noble/secp256k1";

class Custodial_Wallet {
	#serialization_format;

	constructor(net, masterHDkeys, serialization_format) {
		this.net = net;
		this.masterHDkeys = masterHDkeys;
		this.child_keys = new Set();
		this.#serialization_format = serialization_format;
	}

	static fromRandom(net = 'main' || 'test', passphrase = '') {
		const { mnemonic, seed } = bip39.random(passphrase);
		return [mnemonic, this.fromSeed(net, seed)];
	}

	static fromMnemonic(net = 'main' || 'test', mnemonic = '', passphrase = '') {
		const seed = bip39.mnemonic2seed(mnemonic, passphrase);
		return this.fromSeed(net, seed);
	}

	static fromSeed(net = 'main' || 'test', seed = "000102030405060708090a0b0c0d0e0f") {
		const [hdKey, serialization_format] = fromSeed(seed, net);
		return new this(
			net,
			{
				hdKey,
				keypair: standardKey(serialization_format.privKey, serialization_format.pubKey),
				address: address(serialization_format.versionByte.pubKey, serialization_format.pubKey.key)
			},
			serialization_format
		);
	}

	derive(path = "m/0'", keyType = 'pri' || 'pub') {
		const key = this.masterHDkeys.hdKey[keyType === 'pri' ? 'HDpri' : 'HDpub'];
		const [hdKey, serialization_format] = derive(path, key, this.#serialization_format);

		this.child_keys.add({
			depth: serialization_format.depth,
			childIndex: serialization_format.childIndex,
			hdKey,
			keypair: standardKey(keyType !== 'pub' ? serialization_format.privKey : false, serialization_format.pubKey),
			address: address(serialization_format.versionByte.pubKey, serialization_format.pubKey.key)
		});

		return this;
	}

	sign(message = '') {
		return ecdsa.sign( message, this.#serialization_format.privKey.key.toString('hex') )
	}

	verifySig(sig, msgHash) {
		return ecdsa.verifySig(msgHash, sig, this.#serialization_format.pubKey.points);
	}
}

class Non_Custodial_Wallet extends ThresholdSignature {
	
	constructor(net, group_size, threshold) {
		super(group_size, threshold);
		this.net = net;
		[this.pub, this.address] = this.#wallet();
	}

	static fromRandom(net = "main", group_size = 3, threshold = 2) {
		return new this(
			net,
			group_size,
			threshold
		)
	}

	static fromShares(net = "main", shares, threshold = 2) {
		const wallet = new this(
			net,
			shares.length,
			threshold
		)

		wallet.shares = shares.map(x => new BN(x, 'hex'));
		wallet.public_key = Point.fromPrivateKey( wallet.privite_key().toBuffer() ); 
		[wallet.pub, wallet.address] = wallet.#wallet();

		return wallet;
	}

	getShares() {
		return this.shares.map(x => x.toString('hex')); 
	}

	#wallet() {
		const 
			versionByte = this.net === "main" ? 0x0488b21e : 0x043587cf,
			pubKeyToBuff = Buffer.from(this.public_key.toHex(true), 'hex');
		
		return [
			this.public_key.toHex(true), 
			address(versionByte, pubKeyToBuff)
		];
	}

	restore_pri_key() {
		const privKey = { 
			key: this.privite_key().toBuffer(),
			versionByteNum: this.net === 'main' ? 0x80 : 0xef
		}
		return standardKey( privKey, undefined ).pri;
	}

	verifySig(sig, msgHash) {
		return ThresholdSignature.verify_threshold_signature(this.public_key, msgHash, sig);
	}
}

export {
	Custodial_Wallet,
	Non_Custodial_Wallet
}