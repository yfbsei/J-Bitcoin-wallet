import { createHmac, createHash } from 'node:crypto';
import BN from "bn.js";
import { Signature, signSync, recoverPublicKey, verify, utils } from '@noble/secp256k1';

// https://wiki.bitcoinsv.io/index.php/SIGHASH_flags
// NOTE: Currently all BitcoinSV transactions require an additional SIGHASH flag called SIGHASH_FORKID
// SIGHASH Values including SIGHASH_FORKID In HEX. Example: SIGHASH_FORKID(0x40) + SIGHASH_ALL(0x1) = 0x41


utils.hmacSha256Sync = (key, ...messages) => {
    const hash = createHmac('sha256', key);
    messages.forEach((m) => hash.update(m));
    return Uint8Array.from(hash.digest());
}

const ECDSA = {

    SIGH_HASH: {
        SIGHASH_ALL: 0x41,   // Sign all inputs and outputs
        SIGHASH_NONE: 0x42,  // Sign all inputs and no output
        SIGHASH_SINGLE: 0x43, // Sign all inputs and the output with the same index
        // SIGHASH_FORKID: 0x40,
        ANYONECANPAY: {
          SIGHASH_ALL: 0xC1, // Sign its own input and all outputs
          SIGHASH_NONE: 0xC2, // Sign its own input and no output
          SIGHASH_SINGLE: 0xC3 // Sign its own input and the output with the same index
        }
      },

    sign(message, prikey) {
        const 
            msgHash = createHash('sha256').update( Buffer.from(message) ).digest(),
            sig = signSync(msgHash, prikey, {recovered: true}),
            signature = Signature.fromDER(sig[0]).normalizeS(),
			prefix = new BN(27 + sig[1] + 4).toBuffer(),
            r_buff = new BN(signature.r).toBuffer(), 
            s_buff = new BN(signature.s).toBuffer(),
			serialized_sig = Buffer.concat([prefix, r_buff, s_buff]).toString('base64').toString("ascii");
            
        return {
            sig: signature,
            serialized_sig,
            msgHash,
            recovery_id: sig[1]
        }
    },

    recoverPubKey(msgHash, sig, recovery_id, toCompress = true) {
        return Buffer.from(recoverPublicKey(msgHash, sig, recovery_id, toCompress));
    },
    
    verifySig(msgHash, sig, publicKey) {
        return verify(sig, msgHash, publicKey);
    }, 

    txFormat(sig, sigHash) { // ECDSA.txFormat(x.sig, SIGH_HASH.SIGHASH_ALL)
        const sigHashBuf = Buffer.alloc(1); 
        sigHashBuf.writeUInt8(sigHash, 0);
        return Buffer.concat([Buffer.from(sig.toDERRawBytes()), sigHashBuf]);
    }

}

export default ECDSA;
