import hashlib
import json
from datetime import datetime

from database import get_connection


def calculate_hash(block_index, timestamp, data, previous_hash):
    block_content = (
        str(block_index)
        + str(timestamp)
        + json.dumps(data, sort_keys=True)
        + str(previous_hash)
    )

    return hashlib.sha256(block_content.encode()).hexdigest()


def add_block(data):
    connection = get_connection()

    last_block = connection.execute(
        "SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1"
    ).fetchone()

    if last_block:
        block_index = last_block["block_index"] + 1
        previous_hash = last_block["block_hash"]
    else:
        block_index = 0
        previous_hash = "0"

    timestamp = datetime.now().isoformat()
    data_json = json.dumps(data, sort_keys=True)

    block_hash = calculate_hash(
        block_index,
        timestamp,
        data,
        previous_hash
    )

    connection.execute("""
        INSERT INTO blocks (
            block_index,
            timestamp,
            data,
            previous_hash,
            block_hash
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        block_index,
        timestamp,
        data_json,
        previous_hash,
        block_hash
    ))

    connection.commit()
    connection.close()

    return block_hash


def get_blocks():
    connection = get_connection()

    blocks = connection.execute(
        "SELECT * FROM blocks ORDER BY block_index ASC"
    ).fetchall()

    connection.close()

    return blocks


def verify_chain():
    blocks = get_blocks()

    if not blocks:
        print("Blockchain is empty!")
        return False

    # Check Genesis Block
    if blocks[0]["block_index"] != 0:
        print("Genesis Block is missing!")
        return False

    # Verify Genesis Block's previous hash
    if blocks[0]["previous_hash"] != "0":
        print("Invalid Genesis Block!")
        return False

    # Verify blocks after Genesis
    for i in range(1, len(blocks)):
        block = blocks[i]

        # Check sequential block index
        if block["block_index"] != i:
            print(f"Block index mismatch at position {i}")
            return False

        try:
            data = json.loads(block["data"])
        except (json.JSONDecodeError, TypeError):
            print(f"Invalid data format at Block #{block['block_index']}")
            return False

        # Recalculate block hash
        calculated_hash = calculate_hash(
            block["block_index"],
            block["timestamp"],
            data,
            block["previous_hash"]
        )

        if calculated_hash != block["block_hash"]:
            print(f"Hash mismatch at Block #{block['block_index']}")
            return False

        # Verify link to previous block
        previous_block = blocks[i - 1]

        if block["previous_hash"] != previous_block["block_hash"]:
            print(f"Link mismatch at Block #{block['block_index']}")
            return False

    print("Blockchain verification successful!")
    return True