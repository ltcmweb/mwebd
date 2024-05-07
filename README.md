## Mimblewimble Extension Block (MWEB) Daemon

The purpose of this module is to provide an easy and quick way to add MWEB
capabilities to existing software (e.g. wallets).

It connects directly to peers on the Litecoin network that have the
`NODE_MWEB_LIGHT_CLIENT` service bit set. It will download block headers, some
MWEB headers and the MWEB UTXO set which it keeps up-to-date.

### MWEB accounts

Accounts are defined by a pair of ECDSA private keys, known as the scan and
spend secret. These are usually derived from a BIP32 root key as the `0'` and
`1'` child of an account branch. For example, if using the BIP43 scheme and
using `1000` for the purpose code (MWEB), `2` for the coin type (Litecoin), and
`0` for the account index, then the scan key can be derived as
`m/1000'/2'/0'/0'` and the spend key as `m/1000'/2'/0'/1'`.

### MWEB addresses

MWEB addresses are a Bech32-encoding of the serialized scan and spend pubkeys
for that address. The serialized pubkey pair is also used directly as the script
pubkey when specifying new MWEB outputs during transaction creation.

The recommended practice is to use address index 0 as the change address and the
rest of the indices for receiving.

### Mode of operation

The daemon can be run either as a traditional process or as part of an app via
FFI bindings. In the former case the port to communicate on should be specified
as an argument to the program. In the latter the port should be set to zero when
calling the `Start` method on the server, and the actual port will be returned
as a result. The second mode is built with `gomobile`, e.g.

    gomobile bind -o mwebd.aar -target=android github.com/ltcsuite/mwebd

### Fee estimation

It is possible during transaction creation to determine the additional fee added
by the MWEB transaction. Let `tx` be the transaction before transformation by
the `Create` RPC, and `tx2` the result post-transformation. Then in Python:

    mweb_input = tx.input_value() - tx2.input_value()
    expected_pegin = max(0, tx.output_value() - mweb_input)
    fee_increase = tx2.output_value() - expected_pegin

Finally, the fee should be increased by a small amount if a peg-in is required,
to pay for the corresponding input on the HogEx transaction:

    if expected_pegin: fee_increase += fee_rate_per_vb * 41

### Basic workflow

The general idea is:
- Use `Status` to determine when the daemon is synced, by cross-referencing with
another trusted source for the chain tip (e.g. Electrum servers).
- Use `Addresses` to generate a pool of MWEB addresses that can be shown to the
user. The pool will also be necessary to determine the address index of any
received UTXOs, as required when spending them. If an address is not found in
the pool then the UTXO should be considered invalid.
- Use `Utxos` to set up a stream of UTXOs belonging to an account. On a fresh
call the stream will begin with already-confirmed UTXOs starting from the
specified height. Subsequently it will forward all unconfirmed and
newly-confirmed UTXOs belonging to that account.
- The `Spent` RPC is useful for determining when MWEB transactions that were
created by the wallet have confirmed.
- `Create` and `Broadcast` are obviously for creating and broadcasting MWEB
transactions. In general existing broadcast mechanisms don't support MWEB.
