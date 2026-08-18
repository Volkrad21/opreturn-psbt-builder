# Bitcoin TX & PSBT Builder

A dependency-free Python tool for manually constructing Bitcoin transactions and PSBTs (Partially Signed Bitcoin Transactions), with optional `OP_RETURN` data.

The goal of this project is to make Bitcoin transaction construction transparent and understandable without relying on external Bitcoin libraries.

The script can:

- Parse a raw parent Bitcoin transaction
- Select a UTXO by `vout`
- Build a new unsigned Bitcoin transaction
- Create an optional payment output
- Create a change output
- Add optional `OP_RETURN` data
- Read `OP_RETURN` data directly from a file
- Calculate transaction fees using a fee rate in sat/vB
- Estimate transaction weight and virtual size
- Calculate the unsigned transaction TXID
- Construct a PSBT
- Export the raw transaction and PSBT to files

Private keys and seed phrases are never required by the script.

> **Warning**
>
> This is experimental software for educational purposes.
> Always inspect and verify the generated transaction before signing it.
> Test the software on Bitcoin testnet/testnet4 before considering use with real funds.

---

## Why This Project Exists

Bitcoin wallets normally hide most of the transaction construction process from the user.

That is convenient, but it can make it difficult to understand what actually happens between selecting a UTXO and broadcasting a signed transaction.

This project takes a more explicit approach.

The basic workflow is:

```text
Existing transaction
        |
        v
Select UTXO (TXID:vout)
        |
        v
Construct outputs
        |
        +----> Optional payment
        |
        +----> Change
        |
        +----> Optional OP_RETURN
        |
        v
Unsigned raw transaction
        |
        v
PSBT
        |
        v
External wallet / signer
        |
        v
Signed transaction
        |
        v
Broadcast
```

The Python script does not sign the transaction.

Signing is deliberately left to a wallet, hardware wallet, or other external signer.

---

# Requirements

The script requires:

- Python 3
- No third-party Python packages

Only modules from the Python standard library are used:

```python
import base64
import hashlib
import struct
from decimal import Decimal, ROUND_CEILING
```

No `pip install` command should be necessary.

---

# Current Scope

The current version is intentionally limited.

It supports:

- One transaction input
- Native SegWit P2WPKH input (`0014...`)
- Bech32 / Bech32m output address decoding
- Bitcoin mainnet addresses (`bc1...`)
- Bitcoin testnet/testnet4 addresses (`tb1...`)
- Regtest addresses (`bcrt1...`)
- Optional payment output
- Change output
- Optional `OP_RETURN`
- Fee-rate based fee calculation
- PSBT creation using `witness_utxo`

It does **not** currently aim to be a complete Bitcoin wallet or general-purpose transaction library.

---

# Security Model

This program constructs transactions.

It does **not** require:

- seed phrases
- private keys
- extended private keys (`xprv`)
- wallet passwords

Do not enter any of those into the program.

The intended workflow is:

```text
Transaction construction
        |
        |  No private keys
        v
      PSBT
        |
        v
Trusted signer
        |
        |  Private keys remain here
        v
Signed transaction
```

This separation allows transaction construction to happen independently from key storage.

---

# Basic Usage

Run the script with Python:

```bash
python createPSBT.py
```

On some systems:

```bash
python3 createPSBT.py
```

The program will guide you through the transaction construction process.

---

# 1. Parent Transaction

The program first asks for the complete raw transaction containing the UTXO you want to spend:

```text
Paste the RAW PARENT transaction:
> <raw_parent_transaction_hex>
```

Paste the complete raw transaction hex.

The program parses the transaction and calculates its TXID.

Example output:

```text
Parent TXID:
<calculated_parent_txid>
```

---

# 2. Select the UTXO (`vout`)

Bitcoin transactions can contain multiple outputs.

Outputs are numbered starting at zero:

```text
Output 0 -> vout 0
Output 1 -> vout 1
Output 2 -> vout 2
```

A UTXO is therefore identified by:

```text
TXID:vout
```

For example:

```text
<parent_txid>:0
```

The script asks:

```text
Which output do you want to spend (vout)?
> 0
```

It then automatically retrieves the amount and `scriptPubKey` from that output.

---

# 3. Input Validation

The current version expects the selected UTXO to be a native SegWit P2WPKH output.

A P2WPKH `scriptPubKey` has the following structure:

```text
0014<20-byte-public-key-hash>
```

The `0014` prefix indicates:

```text
00 = witness version 0
14 = 20-byte witness program
```

If the selected output is not P2WPKH, the script stops instead of attempting to construct an incompatible PSBT.

---

# 4. Optional Payment Output

The script asks:

```text
Create a payment output? (y/n):
>
```

Selecting:

```text
y
```

allows you to enter:

```text
Destination address:
> <destination_address>

Amount to send in sats:
> <amount>
```

Selecting:

```text
n
```

creates no separate payment output.

This is useful when the purpose of the transaction is only to create an `OP_RETURN` while returning the remaining Bitcoin to yourself.

Conceptually:

```text
INPUT
1,000,000 sats
       |
       +----> 998,000 sats -> change
       |
       +----> 0 sats -> OP_RETURN
       |
       +----> 2,000 sats -> transaction fee
```

The amounts above are illustrative only.

With this structure, only one new spendable UTXO is created.

---

# 5. Change Address

The script asks for a change address:

```text
Change address:
> <your_change_address>
```

After calculating the transaction fee, the remaining value is sent to this address.

Conceptually:

```text
change =
    input amount
    - payment amount
    - transaction fee
```

If no payment output is created:

```text
change =
    input amount
    - transaction fee
```

The `OP_RETURN` output itself has a value of zero satoshis.

---

# 6. OP_RETURN

The script optionally creates an `OP_RETURN` output.

```text
Add OP_RETURN? (y/n):
>
```

When enabled, three input modes are available:

```text
OP_RETURN input mode:

1 = Enter UTF-8 text
2 = Read raw bytes from a file
```

## Mode 1 — UTF-8 Text

Example:

```text
OP_RETURN input mode:
> 1

OP_RETURN text:
> Hello World!
```

The text is encoded as UTF-8 and inserted into the `OP_RETURN`.

For ASCII text, one character corresponds to one byte.

---

## Mode 2 — File

Mode 2 reads a file as raw bytes:

```text
OP_RETURN input mode:
> 2

File path:
> <path_to_your_file>
```

The local file path itself is **not** placed into the Bitcoin transaction.

Only the contents of the file are read.

Internally:

```python
with open(filename, "rb") as f:
    op_return_data = f.read()
```

This makes it possible to embed source code or other arbitrary byte data.

### Privacy Warning

Although the file path is not published, the **contents of the file are**.

Before embedding a file, check it carefully for:

- names
- usernames
- email addresses
- local file paths
- API keys
- passwords
- wallet information
- Bitcoin addresses you do not want associated with the transaction
- other identifying information

Blockchain data should be considered permanent.

---

# OP_RETURN Serialization

Bitcoin Script uses different push-data encodings depending on payload size.

The script supports:

```text
0 - 75 bytes
    Direct data push

76 - 255 bytes
    OP_PUSHDATA1

256 - 65,535 bytes
    OP_PUSHDATA2

65,536+ bytes
    OP_PUSHDATA4
```

The resulting script has the general structure:

```text
OP_RETURN
    |
    +----> push opcode
              |
              +----> payload
```

For example, the text:

```text
Hello World!
```

contains 12 ASCII bytes and can be represented conceptually as:

```text
6a
0c
48656c6c6f20576f726c6421
```

where:

```text
6a = OP_RETURN
0c = push 12 bytes
48656c6c6f20576f726c6421 = "Hello World!"
```

This example contains no transaction-specific information.

---

# Transaction Size and Weight

The script checks the estimated final transaction weight against:

```python
MAX_STANDARD_TX_WEIGHT = 400_000
```

A Bitcoin transaction's weight is not simply the number of bytes in the transaction.

Non-witness transaction data counts at four weight units per byte.

Witness data receives the SegWit weight discount.

For the currently supported one-input P2WPKH transaction, the script reserves a conservative amount of space for the future signature and public key witness.

It then calculates an estimated final:

```text
transaction weight (WU)
```

and:

```text
virtual size (vB)
```

Virtual size is calculated as:

```text
vsize = ceil(weight / 4)
```

---

# Large OP_RETURN Payloads

The script is intentionally capable of constructing `OP_RETURN` scripts much larger than the historical 80-byte convention.

However, several different concepts must not be confused:

```text
Bitcoin consensus rules
        !=
Bitcoin Core standardness policy
        !=
Node configuration
        !=
Wallet policy
        !=
Miner policy
```

A transaction that can be serialized by this script is **not automatically guaranteed** to:

- be considered standard by every node
- enter every mempool
- be relayed by every peer
- be accepted by every wallet
- be accepted by every hardware signer
- be mined

The script therefore performs size checks, but these checks should not be interpreted as a guarantee of relay or mining.

---

# Fees

Instead of asking for a fixed absolute fee, the program asks for a fee rate:

```text
Fee rate in sat/vB:
>
```

For example:

```text
1.5
```

The program:

1. Constructs a transaction-size template
2. Estimates the signed P2WPKH transaction weight
3. Converts weight to virtual bytes
4. Multiplies virtual size by the requested fee rate
5. Rounds the fee upward to the next satoshi
6. Subtracts the resulting fee from change

Conceptually:

```text
estimated weight
        |
        v
estimated vsize
        |
        v
vsize * sat/vB
        |
        v
absolute transaction fee
        |
        v
change amount
```

The program prints both the requested fee rate and the calculated absolute fee.

Example:

```text
Fee rate:
1.0 sat/vB

Calculated absolute fee:
<calculated_fee> sats
```

---

# Transaction Construction

The unsigned transaction uses:

```text
Version:
2

Inputs:
1

scriptSig:
empty

Sequence:
0xfffffffd

Locktime:
0
```

The input references:

```text
<parent_txid>:<vout>
```

The outputs are then serialized into the transaction.

Depending on the selected options, the transaction can contain:

```text
Payment + Change

Payment + Change + OP_RETURN

Change only

Change + OP_RETURN
```

---

# TXID Calculation

The script calculates the unsigned transaction TXID using double SHA-256:

```python
SHA256(SHA256(transaction))
```

The resulting 32-byte hash is reversed for conventional TXID display.

Conceptually:

```text
serialized transaction
        |
        v
SHA256
        |
        v
SHA256
        |
        v
reverse byte order
        |
        v
TXID
```

For native SegWit transactions, signatures are placed in the witness rather than the legacy transaction serialization used for the TXID.

---

# PSBT Creation

After constructing the unsigned transaction, the script creates a PSBT.

The PSBT contains:

```text
PSBT
 |
 +-- Global map
 |      |
 |      +-- unsigned transaction
 |
 +-- Input map
 |      |
 |      +-- witness_utxo
 |
 +-- Output map(s)
        |
        +-- currently empty
```

The selected previous output is serialized into:

```text
PSBT_IN_WITNESS_UTXO
```

This provides the signer with:

```text
UTXO amount
+
UTXO scriptPubKey
```

The script itself performs no signing.

---

# Generated Files

After successful construction, three files are created:

```text
unsigned_transaction.txt
transaction.psbt
transaction_psbt_base64.txt
```

## `unsigned_transaction.txt`

Contains the unsigned raw transaction as hexadecimal text.

## `transaction.psbt`

Contains the binary PSBT.

This is the file intended for import into a compatible wallet or signer.

## `transaction_psbt_base64.txt`

Contains the same PSBT encoded as Base64.

These generated files are normally excluded from version control using `.gitignore`.

---

# Example Workflow

The following example deliberately uses placeholders rather than real blockchain data:

```text
Paste the RAW PARENT transaction:
> <raw_parent_transaction_hex>

Which output do you want to spend (vout)?
> 0

Detected input type:
P2WPKH

Create a payment output?
> n

Change address:
> <testnet_change_address>

Add OP_RETURN?
> y

OP_RETURN input mode:
> 1

OP_RETURN text:
> Hello World!

Fee rate in sat/vB:
> 1
```

The resulting transaction has approximately this structure:

```text
INPUT
└── <parent_txid>:0
      |
      v
OUTPUT 0
└── <change_address>
      |
      v
OUTPUT 1
└── OP_RETURN
      └── "Hello World!"
```

The script then creates:

```text
unsigned_transaction.txt
transaction.psbt
transaction_psbt_base64.txt
```

The PSBT can then be inspected and signed externally.

---

# Recommended Testing Procedure

Before using the script with valuable Bitcoin:

1. Start with testnet/testnet4.
2. Use a small test UTXO.
3. Construct a transaction.
4. Inspect every output.
5. Verify the destination address.
6. Verify the change address.
7. Verify the input amount.
8. Verify the change amount.
9. Verify the absolute transaction fee.
10. Verify the fee rate.
11. Verify the `OP_RETURN` contents.
12. Import the PSBT into a trusted wallet.
13. Inspect the transaction again.
14. Sign only after verifying everything.
15. Broadcast the signed transaction.
16. Verify the confirmed transaction independently.

Never blindly sign a PSBT simply because this program generated it.

---

# Known Limitations

The current version has several intentional limitations.

### One input only

The transaction builder currently creates exactly one input.

Multiple-input transactions are not yet supported.

### P2WPKH input only

The selected UTXO must currently be native SegWit P2WPKH:

```text
0014...
```

Other input types may require different PSBT information or signing logic.

### No private-key signing

The program does not sign transactions.

This is intentional.

### No network lookup

The script does not contact a Bitcoin node, block explorer, Electrum server, or other external service.

The raw parent transaction must be supplied manually.

### No automatic UTXO discovery

The script does not scan a wallet for UTXOs.

### No automatic broadcasting

The program does not broadcast transactions.

### Policy differences

Wallets, nodes, and miners can use different transaction policies.

A transaction produced successfully by this script is not guaranteed to be accepted everywhere.

### Experimental large OP_RETURN support

Large `OP_RETURN` payloads may encounter wallet, node, relay, or miner policy restrictions even when the transaction itself can be serialized correctly.

---

# Privacy

Bitcoin transactions are public.

Anything placed inside an `OP_RETURN` may become permanently visible on the blockchain.

Do not include information you are not willing to make public.

This includes:

```text
Personal names
Usernames
Email addresses
Private file paths
Passwords
API keys
Seed phrases
Private keys
xprvs
Confidential documents
Personally identifying information
```

Also remember that publishing data and spending a UTXO can create associations between that data and the transaction history of the coins being spent.

---

# Important Security Warning

**Never enter a Bitcoin seed phrase or private key into this script.**

This program does not need one.

If a modified version of this program asks for:

```text
seed phrase
private key
xprv
wallet password
```

do not assume it is equivalent to the original code.

Review the source before running modified versions.

---

# Development Philosophy

The project intentionally avoids external Bitcoin libraries.

The purpose is educational transparency.

Important Bitcoin structures such as:

- CompactSize integers
- transaction serialization
- TXIDs
- SegWit addresses
- scriptPubKeys
- `OP_RETURN`
- push-data opcodes
- transaction weight
- virtual size
- PSBT maps
- `witness_utxo`

are implemented explicitly in Python.

This makes the code longer than an implementation based on a Bitcoin library, but also makes the individual serialization steps easier to inspect and study.

---

# Disclaimer

This software is experimental.

Bitcoin transactions are irreversible once confirmed.

The author makes no guarantee that transactions generated by this software will be:

- valid
- standard
- relayable
- signable by a particular wallet
- accepted into a mempool
- mined
- appropriate for mainnet use

Always independently verify transaction details before signing.

Use at your own risk.

---

# License

This project is released under the MIT License.

See the `LICENSE` file for details.
