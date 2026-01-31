import time

ledger = {}

def issue_to_blockchain(cert_id, cert_hash):
    if cert_id in ledger:
        raise Exception("Blockchain: Certificate already exists")
    ledger[cert_id] = {
        "hash": cert_hash,
        "timestamp": time.time()
    }

def verify_on_blockchain(cert_id, cert_hash):
    if cert_id not in ledger:
        return False
    return ledger[cert_id]["hash"] == cert_hash
