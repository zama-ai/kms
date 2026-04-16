import os
import json
import csv
import re
import sys

# ---------------------------------------------------------------------------
# TFHE / BGV parameter and experiment tables
# ---------------------------------------------------------------------------

# Maps parameter-set name to the CSV file it should produce.
PARAMS_MAP = {
    "NIST_PARAMS_P32_SNS_FGLWE": "TFHE_Clear_P32_FGLWE.csv",
    "NIST_PARAMS_P32_SNS_LWE":   "TFHE_Clear_P32_LWE.csv",
    "NIST_PARAMS_P8_SNS_FGLWE":  "TFHE_Clear_P8_FGLWE.csv",
    "NIST_PARAMS_P8_SNS_LWE":    "TFHE_Clear_P8_LWE.csv",
    "BC_PARAMS_SNS":              "TFHE_Clear_BC_FGLWE.csv",
    "bgv":                        "BGV_Clear.csv",
}

EXPERIMENTS_MAP = {
    "non-threshold_keygen": "KeyGen",
    "non-threshold_erc20":  "ERC20",
    "non-threshold_basic-ops": {
        "encrypt": "Enc",
        "decrypt": "Dec",
        "mul":     "Mult64",
    },
}

# ---------------------------------------------------------------------------
# ZK PoK parameter and operation tables
# ---------------------------------------------------------------------------

# Maps parameter-set name to the ZK CSV file it should produce.
ZK_PARAMS_MAP = {
    "NIST_PARAMS_P32_SNS_FGLWE": "ZK_PoK_NIST_PARAMS_P32_SNS_FGLWE.csv",
    "NIST_PARAMS_P32_SNS_LWE":   "ZK_PoK_NIST_PARAMS_P32_SNS_LWE.csv",
    "NIST_PARAMS_P8_SNS_FGLWE":  "ZK_PoK_NIST_PARAMS_P8_SNS_FGLWE.csv",
    "NIST_PARAMS_P8_SNS_LWE":    "ZK_PoK_NIST_PARAMS_P8_SNS_LWE.csv",
    "BC_PARAMS_SNS":              "ZK_PoK_BC_PARAMS_SNS.csv",
}

# Internal operation key → CSV row label.
# Ordered longest-first so substring checks are unambiguous.
ZK_OPS = ["verify_two_steps", "verify_batched", "proof_gen", "crs_gen"]

# Compute-load variants present in bench names (crs_gen has no load variant).
ZK_LOADS = ["load_proof", "load_verify"]

# ---------------------------------------------------------------------------
# Unit conversions
# ---------------------------------------------------------------------------

# I think we only have ns ?
UNIT_CONV_TO_MS = {"ns": 1e-6}
# I think we only have B ?
UNIT_CONV_TO_KB = {"B": 1e-3}

# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

class ResultEntry:
    def __init__(self):
        self.keygen_latency:  float = -1
        self.keygen_memory:   float = -1
        self.erc20_latency:   float = -1
        self.erc20_memory:    float = -1
        self.encrypt_latency: float = -1
        self.encrypt_memory:  float = -1
        self.decrypt_latency: float = -1
        self.decrypt_memory:  float = -1
        self.mul_latency:     float = -1
        self.mul_memory:      float = -1

    def all_missing(self):
        return all(v == -1 for v in [
            self.keygen_latency,  self.keygen_memory,
            self.erc20_latency,   self.erc20_memory,
            self.encrypt_latency, self.encrypt_memory,
            self.decrypt_latency, self.decrypt_memory,
            self.mul_latency,     self.mul_memory,
        ])


class ZkResultEntry:
    def __init__(self):
        # CRS generation — no compute-load variant
        self.crs_gen_latency:                     float = -1
        self.crs_gen_memory:                      float = -1
        # Proof generation
        self.proof_gen_load_proof_latency:         float = -1
        self.proof_gen_load_proof_memory:          float = -1
        self.proof_gen_load_verify_latency:        float = -1
        self.proof_gen_load_verify_memory:         float = -1
        # Verification — TwoSteps pairing mode
        self.verify_two_steps_load_proof_latency:  float = -1
        self.verify_two_steps_load_proof_memory:   float = -1
        self.verify_two_steps_load_verify_latency: float = -1
        self.verify_two_steps_load_verify_memory:  float = -1
        # Verification — Batched pairing mode
        self.verify_batched_load_proof_latency:    float = -1
        self.verify_batched_load_proof_memory:     float = -1
        self.verify_batched_load_verify_latency:   float = -1
        self.verify_batched_load_verify_memory:    float = -1

    def all_missing(self):
        return all(v == -1 for v in [
            self.crs_gen_latency,                     self.crs_gen_memory,
            self.proof_gen_load_proof_latency,         self.proof_gen_load_proof_memory,
            self.proof_gen_load_verify_latency,        self.proof_gen_load_verify_memory,
            self.verify_two_steps_load_proof_latency,  self.verify_two_steps_load_proof_memory,
            self.verify_two_steps_load_verify_latency, self.verify_two_steps_load_verify_memory,
            self.verify_batched_load_proof_latency,    self.verify_batched_load_proof_memory,
            self.verify_batched_load_verify_latency,   self.verify_batched_load_verify_memory,
        ])


RESULT_MAP    = {k: ResultEntry()   for k in PARAMS_MAP}
ZK_RESULT_MAP = {k: ZkResultEntry() for k in ZK_PARAMS_MAP}

# ---------------------------------------------------------------------------
# Helpers shared by both TFHE and ZK parsers
# ---------------------------------------------------------------------------

def fetch_mean_memory(line):
    """Return (mean_str, unit) from a bench_memory output line, or None."""
    match = re.search(r"Memory usage for .* \(avg over .* runs\) : (.*) B\.", line)
    if match:
        return (match.group(1), "B")

# ---------------------------------------------------------------------------
# TFHE / BGV latency parsing
# ---------------------------------------------------------------------------

def find_parameters_from_json(data):
    for key in PARAMS_MAP:
        if key in data["id"]:
            return key
    print("Skipping {} no params found".format(data["id"]))
    return None

def find_op_from_json(data):
    for key in EXPERIMENTS_MAP["non-threshold_basic-ops"]:
        if key in data["id"]:
            return key
    print("Skipping {} op not needed".format(data["id"]))

def parse_latency_keygen(data):
    parameters = find_parameters_from_json(data)
    if parameters is None:
        return
    mean_latency = data["mean"]["estimate"]
    mean_unit    = data["mean"]["unit"]
    RESULT_MAP[parameters].keygen_latency = mean_latency * UNIT_CONV_TO_MS[mean_unit]

def parse_latency_erc20(data):
    parameters = find_parameters_from_json(data)
    if parameters is None:
        return
    mean_latency = data["mean"]["estimate"]
    mean_unit    = data["mean"]["unit"]
    RESULT_MAP[parameters].erc20_latency = mean_latency * UNIT_CONV_TO_MS[mean_unit]

def parse_latency_basic_ops(data):
    parameters = find_parameters_from_json(data)
    if parameters is None:
        return
    op           = find_op_from_json(data)
    mean_latency = data["mean"]["estimate"]
    mean_unit    = data["mean"]["unit"]
    latency      = mean_latency * UNIT_CONV_TO_MS[mean_unit]
    if op == "encrypt":
        RESULT_MAP[parameters].encrypt_latency = latency
    elif op == "decrypt":
        RESULT_MAP[parameters].decrypt_latency = latency
    elif op == "mul":
        RESULT_MAP[parameters].mul_latency = latency
    else:
        print("Skipped op {} as it's not one we care about in NIST doc.".format(op))

# ---------------------------------------------------------------------------
# ZK PoK latency parsing
# ---------------------------------------------------------------------------

def find_zk_params_from_json(data):
    for key in ZK_PARAMS_MAP:
        if key in data["id"]:
            return key
    print("Skipping ZK entry {} – no matching params".format(data["id"]))
    return None

def find_zk_op_from_json(data):
    for op in ZK_OPS:  # longest names first — avoids prefix ambiguity
        if op in data["id"]:
            return op
    print("Skipping ZK entry {} – unknown op".format(data["id"]))
    return None

def find_zk_load(text):
    """Return 'load_proof' or 'load_verify' if present in text, else None (e.g. crs_gen)."""
    for load in ZK_LOADS:
        if load in text:
            return load
    return None

def parse_zk_latency(data):
    params = find_zk_params_from_json(data)
    if params is None:
        return
    op = find_zk_op_from_json(data)
    if op is None:
        return
    load = find_zk_load(data["id"])
    latency = data["mean"]["estimate"] * UNIT_CONV_TO_MS[data["mean"]["unit"]]
    entry = ZK_RESULT_MAP[params]
    if op == "crs_gen":
        entry.crs_gen_latency = latency
    elif op == "proof_gen":
        if load == "load_proof":
            entry.proof_gen_load_proof_latency = latency
        elif load == "load_verify":
            entry.proof_gen_load_verify_latency = latency
    elif op == "verify_two_steps":
        if load == "load_proof":
            entry.verify_two_steps_load_proof_latency = latency
        elif load == "load_verify":
            entry.verify_two_steps_load_verify_latency = latency
    elif op == "verify_batched":
        if load == "load_proof":
            entry.verify_batched_load_proof_latency = latency
        elif load == "load_verify":
            entry.verify_batched_load_verify_latency = latency

# ---------------------------------------------------------------------------
# Shared latency-file entry point
# ---------------------------------------------------------------------------

def parse_latency_file():
    with open(LATENCY_FILE, "r") as f:
        for line in f:
            data = json.loads(line)
            if data.get("id") is None:
                print("Skipping entry with no id: {}".format(data))
                continue
            experiment_name = data["id"]
            if "non-threshold_zk-pok" in experiment_name:
                parse_zk_latency(data)
            elif "non-threshold_keygen" in experiment_name:
                parse_latency_keygen(data)
            elif "non-threshold_erc20" in experiment_name:
                parse_latency_erc20(data)
            elif "non-threshold_basic-ops" in experiment_name and (
                "FheUint64" in experiment_name or "bgv" in experiment_name
            ):
                parse_latency_basic_ops(data)

# ---------------------------------------------------------------------------
# TFHE / BGV memory parsing
# ---------------------------------------------------------------------------

def find_params_from_line(line):
    for key in PARAMS_MAP:
        if key in line:
            return key

def find_op_from_line(line):
    for key in EXPERIMENTS_MAP["non-threshold_basic-ops"]:
        if key in line:
            return key
    print("Skipping {}".format(line))

def parse_memory_keygen(line):
    params = find_params_from_line(line)
    if params is None:
        return
    result = fetch_mean_memory(line)
    if result is None:
        return
    mean_memory, unit = result
    RESULT_MAP[params].keygen_memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]

def parse_memory_erc20(line):
    params = find_params_from_line(line)
    if params is None:
        return
    result = fetch_mean_memory(line)
    if result is None:
        return
    mean_memory, unit = result
    RESULT_MAP[params].erc20_memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]

def parse_memory_basic_ops(line):
    params = find_params_from_line(line)
    if params is None:
        return
    result = fetch_mean_memory(line)
    if result is None:
        return
    mean_memory, unit = result
    memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]
    if "encrypt" in line:
        RESULT_MAP[params].encrypt_memory = memory
    if "decrypt" in line:
        RESULT_MAP[params].decrypt_memory = memory
    if "mul" in line:
        RESULT_MAP[params].mul_memory = memory

# ---------------------------------------------------------------------------
# ZK PoK memory parsing
# ---------------------------------------------------------------------------

def find_zk_params_from_line(line):
    for key in ZK_PARAMS_MAP:
        if key in line:
            return key
    return None

def find_zk_op_from_line(line):
    for op in ZK_OPS:  # longest names first — avoids prefix ambiguity
        if op in line:
            return op
    return None

def parse_zk_memory(line):
    params = find_zk_params_from_line(line)
    if params is None:
        return
    op = find_zk_op_from_line(line)
    if op is None:
        return
    load = find_zk_load(line)
    result = fetch_mean_memory(line)
    if result is None:
        return
    mean_memory, unit = result
    memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]
    entry = ZK_RESULT_MAP[params]
    if op == "crs_gen":
        entry.crs_gen_memory = memory
    elif op == "proof_gen":
        if load == "load_proof":
            entry.proof_gen_load_proof_memory = memory
        elif load == "load_verify":
            entry.proof_gen_load_verify_memory = memory
    elif op == "verify_two_steps":
        if load == "load_proof":
            entry.verify_two_steps_load_proof_memory = memory
        elif load == "load_verify":
            entry.verify_two_steps_load_verify_memory = memory
    elif op == "verify_batched":
        if load == "load_proof":
            entry.verify_batched_load_proof_memory = memory
        elif load == "load_verify":
            entry.verify_batched_load_verify_memory = memory

# ---------------------------------------------------------------------------
# Shared memory-file entry point
# ---------------------------------------------------------------------------

def parse_memory_file():
    with open(MEMORY_FILE, "r") as f:
        for line in f:
            if "non-threshold_zk-pok" in line:
                parse_zk_memory(line)
            elif "non-threshold_keygen" in line:
                parse_memory_keygen(line)
            elif "non-threshold_erc20" in line:
                parse_memory_erc20(line)
            elif "non-threshold_basic-ops" in line and (
                "FheUint64" in line or "bgv" in line
            ):
                parse_memory_basic_ops(line)

# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def output_result_csv_files():
    """Write one TFHE/BGV CSV file per parameter set that has at least one result."""
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    for params, result in RESULT_MAP.items():
        if result.all_missing():
            continue  # no data for this param set in the given folder
        file_name = os.path.join(OUTPUT_DIRECTORY, PARAMS_MAP[params])
        with open(file_name, "w") as f:
            w = csv.writer(f, delimiter=",")
            w.writerow(["Operation", "avg_latency_ms", "max_memory_kBytes"])
            w.writerow(["KeyGen",  result.keygen_latency,  result.keygen_memory])
            w.writerow(["Enc",     result.encrypt_latency, result.encrypt_memory])
            w.writerow(["Dec",     result.decrypt_latency, result.decrypt_memory])
            w.writerow(["ERC20",   result.erc20_latency,   result.erc20_memory])
            w.writerow(["Mult64",  result.mul_latency,     result.mul_memory])

def output_zk_csv_files():
    """Write one ZK PoK CSV file per parameter set that has at least one result.

    Each non-CRS operation appears twice: once for ZkComputeLoad::Proof proofs
    and once for ZkComputeLoad::Verify proofs, since the two proof types carry
    different trade-offs between proving and verification cost.
    """
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    for params, result in ZK_RESULT_MAP.items():
        if result.all_missing():
            continue  # no ZK data for this param set in the given folder
        file_name = os.path.join(OUTPUT_DIRECTORY, ZK_PARAMS_MAP[params])
        with open(file_name, "w") as f:
            w = csv.writer(f, delimiter=",")
            w.writerow(["Operation", "avg_latency_ms", "max_memory_kBytes"])
            w.writerow(["CRSGen",
                         result.crs_gen_latency,
                         result.crs_gen_memory])
            w.writerow(["ProofGen_LoadProof",
                         result.proof_gen_load_proof_latency,
                         result.proof_gen_load_proof_memory])
            w.writerow(["ProofGen_LoadVerify",
                         result.proof_gen_load_verify_latency,
                         result.proof_gen_load_verify_memory])
            w.writerow(["VerifyTwoSteps_LoadProof",
                         result.verify_two_steps_load_proof_latency,
                         result.verify_two_steps_load_proof_memory])
            w.writerow(["VerifyTwoSteps_LoadVerify",
                         result.verify_two_steps_load_verify_latency,
                         result.verify_two_steps_load_verify_memory])
            w.writerow(["VerifyBatched_LoadProof",
                         result.verify_batched_load_proof_latency,
                         result.verify_batched_load_proof_memory])
            w.writerow(["VerifyBatched_LoadVerify",
                         result.verify_batched_load_verify_latency,
                         result.verify_batched_load_verify_memory])

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global LATENCY_FILE, MEMORY_FILE, OUTPUT_DIRECTORY
    if len(sys.argv) != 2:
        print("Usage: {} <folder>".format(sys.argv[0]))
        sys.exit(1)
    folder = sys.argv[1]
    LATENCY_FILE     = os.path.join(folder, "bench_results.json")
    MEMORY_FILE      = os.path.join(folder, "memory_bench_results.txt")
    OUTPUT_DIRECTORY = os.path.join(folder, "output")

    parse_latency_file()
    parse_memory_file()
    output_result_csv_files()
    output_zk_csv_files()


if __name__ == "__main__":
    main()
