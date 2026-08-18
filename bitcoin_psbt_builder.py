import base64
import hashlib
import struct
from decimal import Decimal, ROUND_CEILING


# ============================================================
# CONFIGURATION
# ============================================================

MAX_STANDARD_TX_WEIGHT = 400_000

# Bitcoin Core 30+ default datacarrier size.
# Node policy can be configured differently.
DEFAULT_DATACARRIER_LIMIT = 100_000

# Conservative maximum witness size for one signed P2WPKH input:
#
# marker + flag              2 bytes
# witness item count         1 byte
# signature length           1 byte
# DER signature + sighash   73 bytes max
# pubkey length              1 byte
# compressed pubkey         33 bytes
#
# Total: 111 witness bytes / weight units.
P2WPKH_WITNESS_WEIGHT = 111


# ============================================================
# BITCOIN SERIALIZATION
# ============================================================

def compact_size(n):
    if n < 0xfd:
        return bytes([n])

    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)

    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)

    else:
        return b"\xff" + struct.pack("<Q", n)


def read_compact_size(data, offset):
    if offset >= len(data):
        raise ValueError("Unexpected end of transaction.")

    first = data[offset]
    offset += 1

    if first < 0xfd:
        return first, offset

    elif first == 0xfd:
        return struct.unpack_from(
            "<H",
            data,
            offset
        )[0], offset + 2

    elif first == 0xfe:
        return struct.unpack_from(
            "<I",
            data,
            offset
        )[0], offset + 4

    else:
        return struct.unpack_from(
            "<Q",
            data,
            offset
        )[0], offset + 8


def double_sha256(data):
    return hashlib.sha256(
        hashlib.sha256(data).digest()
    ).digest()


def serialize_output(amount, script):
    return (
        struct.pack("<Q", amount)
        + compact_size(len(script))
        + script
    )


# ============================================================
# BECH32 / BECH32M
# ============================================================

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    generators = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]

    chk = 1

    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value

        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]

    return chk


def bech32_hrp_expand(hrp):
    return (
        [ord(x) >> 5 for x in hrp]
        + [0]
        + [ord(x) & 31 for x in hrp]
    )


def verify_bech32_checksum(hrp, data):
    value = bech32_polymod(
        bech32_hrp_expand(hrp) + data
    )

    if value == 1:
        return "bech32"

    if value == 0x2bc830a3:
        return "bech32m"

    return None


def convert_bits(data, from_bits, to_bits, pad=True):
    accumulator = 0
    bits = 0
    result = []

    max_value = (1 << to_bits) - 1

    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("Invalid Bech32 data.")

        accumulator = (
            (accumulator << from_bits) | value
        )

        bits += from_bits

        while bits >= to_bits:
            bits -= to_bits

            result.append(
                (accumulator >> bits)
                & max_value
            )

    if pad:
        if bits:
            result.append(
                (accumulator << (to_bits - bits))
                & max_value
            )

    else:
        if bits >= from_bits:
            raise ValueError(
                "Invalid Bech32 padding."
            )

        if (
            (accumulator << (to_bits - bits))
            & max_value
        ):
            raise ValueError(
                "Invalid Bech32 padding."
            )

    return result


def decode_segwit_address(address):
    address = address.strip()

    if (
        address.lower() != address
        and address.upper() != address
    ):
        raise ValueError(
            "Bech32 address contains mixed case."
        )

    address = address.lower()

    position = address.rfind("1")

    if position < 1:
        raise ValueError(
            "Invalid Bech32 address."
        )

    hrp = address[:position]
    data_part = address[position + 1:]

    if len(data_part) < 6:
        raise ValueError(
            "Invalid Bech32 address."
        )

    try:
        data = [
            BECH32_CHARSET.index(c)
            for c in data_part
        ]

    except ValueError:
        raise ValueError(
            "Address contains invalid Bech32 characters."
        )

    encoding = verify_bech32_checksum(
        hrp,
        data
    )

    if encoding is None:
        raise ValueError(
            "Invalid Bech32 checksum."
        )

    data = data[:-6]

    if not data:
        raise ValueError(
            "Missing witness version."
        )

    witness_version = data[0]

    if witness_version > 16:
        raise ValueError(
            "Invalid witness version."
        )

    witness_program = bytes(
        convert_bits(
            data[1:],
            5,
            8,
            False
        )
    )

    if not (
        2 <= len(witness_program) <= 40
    ):
        raise ValueError(
            "Invalid witness program length."
        )

    if witness_version == 0:

        if encoding != "bech32":
            raise ValueError(
                "Witness version 0 must use Bech32."
            )

        if len(witness_program) not in (
            20,
            32
        ):
            raise ValueError(
                "Witness version 0 must contain "
                "20 or 32 bytes."
            )

    else:

        if encoding != "bech32m":
            raise ValueError(
                "Witness versions 1-16 must use Bech32m."
            )

    return (
        hrp,
        witness_version,
        witness_program
    )


def address_to_scriptpubkey(address):
    hrp, version, program = \
        decode_segwit_address(address)

    if hrp not in (
        "bc",
        "tb",
        "bcrt"
    ):
        raise ValueError(
            "Unsupported Bitcoin network."
        )

    if version == 0:
        version_opcode = b"\x00"

    else:
        version_opcode = bytes(
            [0x50 + version]
        )

    script = (
        version_opcode
        + bytes([len(program)])
        + program
    )

    return script, hrp


# ============================================================
# TRANSACTION PARSER
# ============================================================

def parse_transaction(raw_hex):

    raw_hex = "".join(
        raw_hex.split()
    )

    data = bytes.fromhex(
        raw_hex
    )

    offset = 0

    if len(data) < 10:
        raise ValueError(
            "Transaction is too short."
        )

    version_bytes = data[
        offset:offset + 4
    ]

    version = struct.unpack_from(
        "<I",
        data,
        offset
    )[0]

    offset += 4


    # --------------------------------------------------------
    # SEGWIT MARKER + FLAG
    # --------------------------------------------------------

    segwit = False

    if (
        data[offset:offset + 2]
        == b"\x00\x01"
    ):
        segwit = True
        offset += 2


    # --------------------------------------------------------
    # INPUTS
    # --------------------------------------------------------

    input_count, new_offset = \
        read_compact_size(
            data,
            offset
        )

    input_count_bytes = data[
        offset:new_offset
    ]

    offset = new_offset

    base_transaction = (
        version_bytes
        + input_count_bytes
    )

    inputs = []


    for _ in range(input_count):

        previous_txid_le = data[
            offset:offset + 32
        ]

        offset += 32


        vout_bytes = data[
            offset:offset + 4
        ]

        vout = struct.unpack(
            "<I",
            vout_bytes
        )[0]

        offset += 4


        script_length, new_offset = \
            read_compact_size(
                data,
                offset
            )

        script_length_bytes = data[
            offset:new_offset
        ]

        offset = new_offset


        script_sig = data[
            offset:
            offset + script_length
        ]

        offset += script_length


        sequence = data[
            offset:offset + 4
        ]

        offset += 4


        base_transaction += (
            previous_txid_le
            + vout_bytes
            + script_length_bytes
            + script_sig
            + sequence
        )


        inputs.append({
            "txid":
                previous_txid_le[::-1].hex(),

            "vout":
                vout
        })


    # --------------------------------------------------------
    # OUTPUTS
    # --------------------------------------------------------

    output_count, new_offset = \
        read_compact_size(
            data,
            offset
        )

    output_count_bytes = data[
        offset:new_offset
    ]

    offset = new_offset

    base_transaction += \
        output_count_bytes


    outputs = []


    for _ in range(output_count):

        amount_bytes = data[
            offset:offset + 8
        ]

        amount = struct.unpack(
            "<Q",
            amount_bytes
        )[0]

        offset += 8


        script_length, new_offset = \
            read_compact_size(
                data,
                offset
            )

        script_length_bytes = data[
            offset:new_offset
        ]

        offset = new_offset


        script = data[
            offset:
            offset + script_length
        ]

        offset += script_length


        base_transaction += (
            amount_bytes
            + script_length_bytes
            + script
        )


        outputs.append({
            "amount": amount,
            "script": script
        })


    # --------------------------------------------------------
    # WITNESS
    # --------------------------------------------------------

    if segwit:

        for _ in range(input_count):

            item_count, offset = \
                read_compact_size(
                    data,
                    offset
                )

            for _ in range(item_count):

                item_length, offset = \
                    read_compact_size(
                        data,
                        offset
                    )

                offset += item_length


    # --------------------------------------------------------
    # LOCKTIME
    # --------------------------------------------------------

    locktime_bytes = data[
        offset:offset + 4
    ]

    if len(locktime_bytes) != 4:
        raise ValueError(
            "Transaction ends before locktime."
        )

    offset += 4

    base_transaction += \
        locktime_bytes


    if offset != len(data):
        raise ValueError(
            "Unexpected bytes remain "
            "after transaction."
        )


    txid = double_sha256(
        base_transaction
    )[::-1].hex()


    return {
        "raw": data,
        "version": version,
        "segwit": segwit,
        "inputs": inputs,
        "outputs": outputs,
        "txid": txid
    }


# ============================================================
# OP_RETURN
# ============================================================

def push_data(data):

    length = len(data)


    if length <= 75:

        return (
            bytes([length])
            + data
        )


    elif length <= 255:

        return (
            b"\x4c"
            + bytes([length])
            + data
        )


    elif length <= 65535:

        return (
            b"\x4d"
            + struct.pack(
                "<H",
                length
            )
            + data
        )


    elif length <= 0xffffffff:

        return (
            b"\x4e"
            + struct.pack(
                "<I",
                length
            )
            + data
        )


    else:

        raise ValueError(
            "OP_RETURN data is too large."
        )


def make_op_return(data):

    return (
        b"\x6a"
        + push_data(data)
    )


# ============================================================
# BUILD UNSIGNED TRANSACTION
# ============================================================

def build_unsigned_transaction(
    parent_txid,
    vout,
    outputs,
    version=2,
    sequence=0xfffffffd,
    locktime=0
):

    tx = struct.pack(
        "<I",
        version
    )


    # One input
    tx += compact_size(1)


    # Previous TXID little-endian
    tx += bytes.fromhex(
        parent_txid
    )[::-1]


    # vout
    tx += struct.pack(
        "<I",
        vout
    )


    # Empty scriptSig
    tx += b"\x00"


    # Sequence
    tx += struct.pack(
        "<I",
        sequence
    )


    # Outputs
    tx += compact_size(
        len(outputs)
    )


    for amount, script in outputs:

        tx += serialize_output(
            amount,
            script
        )


    # Locktime
    tx += struct.pack(
        "<I",
        locktime
    )


    return tx


# ============================================================
# SIZE / WEIGHT / FEE
# ============================================================

def estimate_signed_p2wpkh_weight(
    unsigned_tx
):

    stripped_size = len(
        unsigned_tx
    )

    return (
        stripped_size * 4
        + P2WPKH_WITNESS_WEIGHT
    )


def weight_to_vsize(weight):

    return (
        weight + 3
    ) // 4


def calculate_fee(
    fee_rate,
    virtual_size
):

    fee = (
        fee_rate
        * Decimal(
            virtual_size
        )
    )

    return int(
        fee.to_integral_value(
            rounding=ROUND_CEILING
        )
    )


# ============================================================
# START
# ============================================================

print()
print("=" * 70)
print("BITCOIN RAW TRANSACTION + PSBT CREATOR")
print("=" * 70)
print()

print(
    "This script creates a one-input P2WPKH "
    "Bitcoin transaction and PSBT."
)

print()

print(
    "No private keys or seed phrases are required."
)

print()


# ============================================================
# PARENT TRANSACTION
# ============================================================

parent_raw_hex = input(
    "Paste the RAW PARENT transaction:\n> "
).strip()

print()


parent = parse_transaction(
    parent_raw_hex
)


print("Parent TXID:")
print(parent["txid"])
print()


vout = int(
    input(
        "Which output do you want to spend (vout)?\n> "
    )
)


if (
    vout < 0
    or vout >= len(parent["outputs"])
):
    raise ValueError(
        "The selected vout does not exist."
    )


utxo = parent["outputs"][vout]

input_amount = utxo["amount"]
input_script = utxo["script"]


print()
print("Selected UTXO:")
print()

print(
    "TXID:",
    parent["txid"]
)

print(
    "vout:",
    vout
)

print(
    "Amount:",
    input_amount,
    "sats"
)

print(
    "scriptPubKey:",
    input_script.hex()
)

print()


# ============================================================
# REQUIRE P2WPKH
# ============================================================

if not (
    len(input_script) == 22
    and input_script[:2] == b"\x00\x14"
):

    raise ValueError(
        "This version only supports "
        "native P2WPKH inputs (0014...)."
    )


print(
    "Detected input type: P2WPKH"
)

print()


# ============================================================
# OPTIONAL PAYMENT OUTPUT
# ============================================================

payment_outputs = []

create_payment = input(
    "Create a payment output? (y/n):\n> "
).strip().lower()


payment_total = 0
network = None


if create_payment in (
    "y",
    "yes"
):

    print()

    destination_address = input(
        "Destination address:\n> "
    ).strip()


    destination_script, network = \
        address_to_scriptpubkey(
            destination_address
        )


    print()

    send_amount = int(
        input(
            "Amount to send in sats:\n> "
        )
    )


    if send_amount <= 0:
        raise ValueError(
            "Send amount must be greater than zero."
        )


    payment_outputs.append(
        (
            send_amount,
            destination_script
        )
    )


    payment_total = send_amount


else:

    print()

    print(
        "No payment output will be created."
    )

    print(
        "The transaction will return the remaining "
        "funds to the change address."
    )


# ============================================================
# CHANGE ADDRESS
# ============================================================

print()

change_address = input(
    "Change address:\n> "
).strip()


change_script, change_network = \
    address_to_scriptpubkey(
        change_address
    )


if (
    network is not None
    and change_network != network
):

    raise ValueError(
        "Payment and change addresses "
        "use different Bitcoin networks."
    )


network = change_network


# ============================================================
# OPTIONAL OP_RETURN
# ============================================================

print()

add_op_return = input(
    "Add OP_RETURN? (y/n):\n> "
).strip().lower()


op_return_script = None
op_return_data = None


if add_op_return in (
    "y",
    "yes"
):

    print()

    print(
        "OP_RETURN input mode:"
    )

    print(
        "1 = Enter UTF-8 text"
    )

    print(
        "2 = Read raw bytes from a file"
    )

    print()

    mode = input(
        "> "
    ).strip()


    if mode == "1":

        print()

        op_return_text = input(
            "OP_RETURN text:\n> "
        )

        op_return_data = \
            op_return_text.encode(
                "utf-8"
            )


    elif mode == "2":

        print()

        filename = input(
            "File path:\n> "
        ).strip()


        with open(
            filename,
            "rb"
        ) as f:

            op_return_data = \
                f.read()


    else:

        raise ValueError(
            "Invalid OP_RETURN input mode."
        )


    op_return_script = \
        make_op_return(
            op_return_data
        )


    print()

    print(
        "OP_RETURN payload:",
        len(op_return_data),
        "bytes"
    )

    print(
        "OP_RETURN scriptPubKey:",
        len(op_return_script),
        "bytes"
    )


    if (
        len(op_return_script)
        > DEFAULT_DATACARRIER_LIMIT
    ):

        raise ValueError(
            "\nThe OP_RETURN script exceeds the "
            "configured 100,000-byte datacarrier "
            "policy limit used by this script."
        )


# ============================================================
# FEE RATE
# ============================================================

print()

fee_rate = Decimal(
    input(
        "Fee rate in sat/vB:\n> "
    ).strip()
)


if fee_rate <= 0:

    raise ValueError(
        "Fee rate must be greater than zero."
    )


# ============================================================
# BUILD OUTPUT TEMPLATE
#
# Change amount is temporarily zero.
# The amount field is always 8 bytes, so this does not
# change transaction size when the real value is inserted.
# ============================================================

template_outputs = []


for output in payment_outputs:

    template_outputs.append(
        output
    )


# Change output always exists.
template_outputs.append(
    (
        0,
        change_script
    )
)


if op_return_script is not None:

    template_outputs.append(
        (
            0,
            op_return_script
        )
    )


# ============================================================
# BUILD TEMPLATE TX
# ============================================================

template_tx = \
    build_unsigned_transaction(
        parent["txid"],
        vout,
        template_outputs
    )


# ============================================================
# ESTIMATE FINAL SIGNED SIZE
# ============================================================

estimated_weight = \
    estimate_signed_p2wpkh_weight(
        template_tx
    )


estimated_vsize = \
    weight_to_vsize(
        estimated_weight
    )


# ============================================================
# STANDARDNESS WEIGHT CHECK
# ============================================================

if (
    estimated_weight
    > MAX_STANDARD_TX_WEIGHT
):

    raise ValueError(
        "\nTransaction is too large for the "
        "standard transaction weight limit.\n\n"
        f"Estimated weight: {estimated_weight} WU\n"
        f"Maximum:          "
        f"{MAX_STANDARD_TX_WEIGHT} WU"
    )


# ============================================================
# CALCULATE ABSOLUTE FEE
# ============================================================

absolute_fee = \
    calculate_fee(
        fee_rate,
        estimated_vsize
    )


# ============================================================
# CALCULATE CHANGE
# ============================================================

change_amount = (
    input_amount
    - payment_total
    - absolute_fee
)


if change_amount <= 0:

    raise ValueError(
        "\nNot enough funds.\n\n"
        f"Input amount:    {input_amount} sats\n"
        f"Payment amount:  {payment_total} sats\n"
        f"Fee:             {absolute_fee} sats"
    )


# ============================================================
# BUILD FINAL OUTPUTS
# ============================================================

outputs = []


for output in payment_outputs:

    outputs.append(
        output
    )


outputs.append(
    (
        change_amount,
        change_script
    )
)


if op_return_script is not None:

    outputs.append(
        (
            0,
            op_return_script
        )
    )


# ============================================================
# BUILD FINAL UNSIGNED TRANSACTION
# ============================================================

unsigned_tx = \
    build_unsigned_transaction(
        parent["txid"],
        vout,
        outputs
    )


unsigned_tx_hex = \
    unsigned_tx.hex()


unsigned_txid = \
    double_sha256(
        unsigned_tx
    )[::-1].hex()


# ============================================================
# VERIFY SIZE DID NOT CHANGE
# ============================================================

final_estimated_weight = \
    estimate_signed_p2wpkh_weight(
        unsigned_tx
    )


final_estimated_vsize = \
    weight_to_vsize(
        final_estimated_weight
    )


if (
    final_estimated_vsize
    != estimated_vsize
):

    raise RuntimeError(
        "Unexpected transaction size change."
    )


# ============================================================
# CREATE PSBT
# ============================================================

psbt = b"psbt\xff"


# ------------------------------------------------------------
# GLOBAL MAP
#
# PSBT_GLOBAL_UNSIGNED_TX = 0x00
# ------------------------------------------------------------

global_key = b"\x00"


psbt += compact_size(
    len(global_key)
)

psbt += global_key


psbt += compact_size(
    len(unsigned_tx)
)

psbt += unsigned_tx


# End global map
psbt += b"\x00"


# ------------------------------------------------------------
# INPUT MAP
#
# PSBT_IN_WITNESS_UTXO = 0x01
# ------------------------------------------------------------

witness_utxo = \
    serialize_output(
        input_amount,
        input_script
    )


input_key = b"\x01"


psbt += compact_size(
    len(input_key)
)

psbt += input_key


psbt += compact_size(
    len(witness_utxo)
)

psbt += witness_utxo


# End input map
psbt += b"\x00"


# ------------------------------------------------------------
# EMPTY OUTPUT MAPS
# ------------------------------------------------------------

for _ in outputs:

    psbt += b"\x00"


# ============================================================
# PSBT BASE64
# ============================================================

psbt_base64 = \
    base64.b64encode(
        psbt
    ).decode(
        "ascii"
    )


# ============================================================
# RESULTS
# ============================================================

print()
print("=" * 70)
print("TRANSACTION CREATED")
print("=" * 70)
print()


print("Input:")
print(
    parent["txid"]
    + ":"
    + str(vout)
)

print()


print("Input amount:")
print(
    input_amount,
    "sats"
)

print()


print("Payment amount:")
print(
    payment_total,
    "sats"
)

print()


print("Change amount:")
print(
    change_amount,
    "sats"
)

print()


if op_return_data is not None:

    print("OP_RETURN payload:")
    print(
        len(op_return_data),
        "bytes"
    )

    print()


print("Unsigned transaction size:")
print(
    len(unsigned_tx),
    "bytes"
)

print()


print("Estimated signed weight:")
print(
    final_estimated_weight,
    "WU"
)

print()


print("Estimated signed virtual size:")
print(
    final_estimated_vsize,
    "vB"
)

print()


print("Fee rate:")
print(
    fee_rate,
    "sat/vB"
)

print()


print("Calculated absolute fee:")
print(
    absolute_fee,
    "sats"
)

print()


actual_rate = (
    Decimal(absolute_fee)
    / Decimal(final_estimated_vsize)
)


print("Resulting fee rate:")
print(
    round(
        actual_rate,
        4
    ),
    "sat/vB"
)

print()


print("Number of outputs:")
print(
    len(outputs)
)

print()


# ============================================================
# RAW TRANSACTION
# ============================================================

print("=" * 70)
print("UNSIGNED RAW TRANSACTION")
print("=" * 70)
print()

print(
    unsigned_tx_hex
)

print()


# ============================================================
# TXID
# ============================================================

print("=" * 70)
print("UNSIGNED TRANSACTION TXID")
print("=" * 70)
print()

print(
    unsigned_txid
)

print()


# ============================================================
# PSBT
# ============================================================

print("=" * 70)
print("PSBT BASE64")
print("=" * 70)
print()

print(
    psbt_base64
)

print()


# ============================================================
# SAVE FILES
# ============================================================

with open(
    "unsigned_transaction.txt",
    "w"
) as f:

    f.write(
        unsigned_tx_hex
    )


with open(
    "transaction.psbt",
    "wb"
) as f:

    f.write(
        psbt
    )


with open(
    "transaction_psbt_base64.txt",
    "w"
) as f:

    f.write(
        psbt_base64
    )


print("=" * 70)
print("FILES CREATED")
print("=" * 70)
print()

print(
    "unsigned_transaction.txt"
)

print(
    "transaction.psbt"
)

print(
    "transaction_psbt_base64.txt"
)

print()

print(
    "Import transaction.psbt into your wallet "
    "for inspection and signing."
)

print()
