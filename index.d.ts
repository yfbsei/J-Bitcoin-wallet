declare type Net = String;
declare type Shares = Array<String>;
interface masterHDkeys {
    hdKey: {
        HDpri: String,
        HDpub: String
    },
    keypair: {
        pri: String,
        pub: String
    },
    address: String
}

interface Signature {
    sig: {
        r: Number,
        s: Number
    }, 
    serialized_sig: String, 
    msgHash: ArrayBuffer, 
    recovery_id: Number
}

export declare class Custodial_Wallet {
    readonly net: Net;
    child_keys: Set<Object>;
    masterHDkeys: masterHDkeys;
    constructor(net: Net, masterHDkeys: masterHDkeys, serialization_format: Object);
    
    static fromRandom(net: Net, passphrase: String) : [String, Custodial_Wallet];
    static fromMnemonic(net: Net, mnemonic: String, passphrase: String) : Custodial_Wallet;
    static fromSeed(net: Net, seed: String) : Custodial_Wallet;
    
    derive(path: String, keyType: String) : Custodial_Wallet;
    sign(message: String) : Signature;
    verifySig(sig: Signature["sig"], msgHash: Signature["msgHash"]) : boolean;
}


export declare class Non_Custodial_Wallet {
    readonly net: Net;
    readonly group_size: Number;
    readonly threshold: Number;
    readonly publicKey: String;
    readonly address: String;

    constructor(net: Net, group_size: Number, threshold: Number);

    static fromRandom(net: Net, group_size: Number, threshold: Number) : Non_Custodial_Wallet;
    static fromShares(net: Net, shares: Shares, threshold: Number) : Non_Custodial_Wallet;

    getShares() : Shares;
    restore_pri_key() : String;
    sign(message: String) : Signature;
    verifySig(sig: Signature["sig"], msgHash: Signature["msgHash"]) : boolean;
}