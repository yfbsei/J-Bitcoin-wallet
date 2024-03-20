# J-Bitcoin
Bitcoin Custodial &amp; non-Custodial Wallets | Threshold signature

| BTC | ✔️ |

| BCH | ✔️ |

| BSV | ✔️ |

## Getting started
`npm i j-bsv`
\
\
`import { Custodial_Wallet, Non_Custodial_Wallet } from 'j-bsv';`

## Custodial Wallet

### Generate wallet
Master wallet(HD)
\
`const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main'); // main network`
\
`const [mnemonic, wallet] = Custodial_Wallet.fromRandom('test'); // test network`

### Import from mnemonic
```
const 
    mnemonic = "teach scatter sample solar casino festival decrease pause random drip memory mystery",
    wallet = Custodial_Wallet.fromMnemonic('main', mnemonic);
```

### Import from seed
```
const 
    seed = "000102030405060708090a0b0c0d0e0f",
    wallet = Custodial_Wallet.fromSeed('main', seed);
```

### Password
```
const [mnemonic, wallet] = Custodial_Wallet.fromRandom('main', 'password123');
// ...
const wallet = Custodial_Wallet.fromMnemonic('main', mnemonic, 'password123');
// Incorrect password returns random wallet
```

### Derive child 
`wallet.derive("m/0", 'pri');`
\
\
Public Keys can't derive from a hardend path \
`wallet.derive("m/0'", 'pub'); // Throws Error`

### Signature
sign
\
`const {sig, serialized_sig, msgHash, recovery_id} = wallet.sign('hello world');`

verfiy siganture
\
`wallet.verifySig(sig, msgHash); // true`


## Non-Custodial Wallet

### Generate wallet
`const wallet = Non_Custodial_Wallet.fromRandom("main", 3, 2); // main network`
\
`const wallet = Non_Custodial_Wallet.fromRandom("test", 3, 2); // test network`

### Import from shares
```
const shares = [
    '79479395a59a8e9d930f2b10ccd5ac3671b0ff0bf8a66aaa1d74978c5353694b',
    '98510126c920e18b148130ac1145686cb299d21f0e010b98ede44169a7bb1c13',
    'b75a6eb7eca7347895f3364755b524a2f382a532235bac87be53eb46fc22cedb'
  ]

const wallet = Non_Custodial_Wallet.fromShares("main", shares, 2);
```

### Shares
`const share_for_each_participant = wallet.getShares();`

### Restore private key
`const groups_prikey = wallet.restore_pri_key();`

### Signature
sign
\
`const { sig, serialized_sig, msgHash, recovery_id } = wallet.sign("hello world");`

verfiy siganture
\
`wallet.verifySig(sig, msgHash); // true`
