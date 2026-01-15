import os
import json
import csv
import re
# Maps parameters name to the corresponding csv file
PARAMS_MAP = {
    "NIST_PARAMS_P32_SNS_FGLWE":"TFHE_Clear_P32_FGLWE.csv",
    "NIST_PARAMS_P32_SNS_LWE":"TFHE_Clear_P32_LWE.csv",
    "NIST_PARAMS_P8_SNS_FGLWE":"TFHE_Clear_P8_FGLWE.csv",
    "NIST_PARAMS_P8_SNS_LWE":"TFHE_Clear_P8_LWE.csv",
    "BC_PARAMS_SNS":"TFHE_Clear_BC_FGLWE.csv"
}

# Maps the experiment name to the corresponding row in the csv file
EXPERIMENTS_MAP = {
    "non-threshold_keygen" : "KeyGen",
    "non-threshold_erc20" : "ERC20",
    "non-threshold_basic-ops" : {
        "encrypt" : "Enc",
        "decrypt" : "Dec",
        "mul" : "Mult64",
    }
}

RESULT_MAP = {}

# I think we only have ns ?
UNIT_CONV_TO_MS = {"ns": 1e-6}
# I think we only have B ?
UNIT_CONV_TO_KB = {"B": 1e-3}

#Get $HOME env variable
HOME = os.getenv("HOME")
TARGET = os.path.join(HOME, "kms", "core", "threshold")
LATENCY_FILE = os.path.join(TARGET,"bench_results.json")
MEMORY_FILE = os.path.join(TARGET,"memory_bench_results.txt")
OUTPUT_DIRECTORY = os.path.join(TARGET, "NIST_results")



class ResultEntry:
    def __init__(self):
        self.keygen_latency = -1
        self.keygen_memory = -1
        self.erc20_latency = -1
        self.erc20_memory = -1
        self.encrypt_latency = -1
        self.encrypt_memory = -1
        self.decrypt_latency = -1
        self.decrypt_memory = -1
        self.mul_latency = -1
        self.mul_memory = -1

RESULT_MAP = {
    "NIST_PARAMS_P32_SNS_FGLWE":ResultEntry(),
    "NIST_PARAMS_P32_SNS_LWE":ResultEntry(),
    "NIST_PARAMS_P8_SNS_FGLWE":ResultEntry(),
    "NIST_PARAMS_P8_SNS_LWE":ResultEntry(),
    "BC_PARAMS_SNS":ResultEntry()
    }

def find_parameters_from_json(data):
    for key in PARAMS_MAP.keys():
        if key in data["id"]:
            return key
    print("Skipping {} no params found".format(data["id"]))
    return None

def find_op_from_json(data):
    for key in EXPERIMENTS_MAP["non-threshold_basic-ops"].keys():
        if key in data["id"]:
            return key
    print("Skipping {} op not needed".format(data["id"]))

def parse_latency_keygen(data):
    parameters = find_parameters_from_json(data)
    if parameters == None:
        return
    mean_latency = data["mean"]["estimate"]
    mean_unit = data["mean"]["unit"]

    latency = mean_latency * UNIT_CONV_TO_MS[mean_unit]

    RESULT_MAP[parameters].keygen_latency = latency


def parse_latency_erc20(data):
    parameters = find_parameters_from_json(data)
    if parameters == None:
        return
    mean_latency = data["mean"]["estimate"]
    mean_unit = data["mean"]["unit"]

    latency = mean_latency * UNIT_CONV_TO_MS[mean_unit]

    RESULT_MAP[parameters].erc20_latency = latency


def parse_latency_basic_ops(data):
    parameters = find_parameters_from_json(data)
    if parameters == None:
        return
    op = find_op_from_json(data)
    mean_latency = data["mean"]["estimate"]
    mean_unit = data["mean"]["unit"]

    latency = mean_latency * UNIT_CONV_TO_MS[mean_unit]

    if op == "encrypt":
        RESULT_MAP[parameters].encrypt_latency = latency
    elif op == "decrypt":
        RESULT_MAP[parameters].decrypt_latency = latency
    elif op == "mul":
        RESULT_MAP[parameters].mul_latency = latency
    else:
        print("Skipped op {} as it's not one we care about in NIST doc.".format(op))



def parse_latency_file():
    # Open LATENCY_FILE and read each line which is a json struct with the bench data
    with open(LATENCY_FILE, "r") as f:
        for line in f:
            data = json.loads(line)
            # Process the json data as needed
            # Acces the `id` field which contains the experiment name
            # Make sure id exists in data
            if data.get("id") is None:
                print("Skipping entry with no id: {}".format(data))
                continue
            experiment_name = data["id"]
            if "non-threshold_keygen" in experiment_name :
                parse_latency_keygen(data)
            elif "non-threshold_erc20" in experiment_name :
                parse_latency_erc20(data)
            # We only care about FheUint64 type
            elif "non-threshold_basic-ops" in experiment_name and "FheUint64" in experiment_name:
                parse_latency_basic_ops(data)
            else :
                continue

def find_params_from_line(line):
    for key in PARAMS_MAP.keys():
        if key in line:
            return key

def find_op_from_line(line):
    for key in EXPERIMENTS_MAP["non-threshold_basic-ops"].keys():
        if key in line:
            return key
    print("Skipping {}".format(line))

def fetch_mean_memory(line):
    # fetch memory from a line that looks like
    match = re.search(r"Memory usage for .* \(avg over .* runs\) : (.*) B.", line)
    if match:
        mean_memory = match.group(1)
        return (mean_memory, "B")

def parse_memory_keygen(line):
    params = find_params_from_line(line)
    if params == None:
        return
    (mean_memory,unit) = fetch_mean_memory(line)

    memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]

    RESULT_MAP[params].keygen_memory = memory

def parse_memory_erc20(line):
    params = find_params_from_line(line)
    if params == None:
        return

    (mean_memory,unit) = fetch_mean_memory(line)

    memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]

    RESULT_MAP[params].erc20_memory = memory

def parse_memory_basic_ops(line):
    params = find_params_from_line(line)
    if params == None:
        return

    (mean_memory,unit) = fetch_mean_memory(line)

    memory = float(mean_memory) * UNIT_CONV_TO_KB[unit]

    if "encrypt" in line:
        RESULT_MAP[params].encrypt_memory = memory
    if "decrypt" in line:
        RESULT_MAP[params].decrypt_memory = memory
    if "mul" in line:
        RESULT_MAP[params].mul_memory = memory

def parse_memory_file():
    # Open MEMORY_FILE and read each line
    with open(MEMORY_FILE, "r") as f:
        for line in f:
            if "non-threshold_keygen" in line :
                parse_memory_keygen(line)
            elif "non-threshold_erc20" in line :
                parse_memory_erc20(line)
            # We only care about FheUint64 type
            elif "non-threshold_basic-ops" in line and "FheUint64" in line:
                parse_memory_basic_ops(line)
            else :
                continue

def output_result_csv_files():
    # Create output directory if it does not exist
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)

    # For each element in RESULT_MAP create the associated csv file
    for params, result in RESULT_MAP.items():
        file_name = os.path.join(OUTPUT_DIRECTORY, PARAMS_MAP[params])
        with open(file_name, "w") as f:
            # Use , as delimiter in csv file
            csv_writer = csv.writer(f, delimiter=',')
            # Write the header
            csv_writer.writerow(["Operation", "avg_latency_ms", "max_memory_kBytes"])
            csv_writer.writerow(["KeyGen", result.keygen_latency, result.keygen_memory])
            csv_writer.writerow(["Enc", result.encrypt_latency, result.encrypt_memory])
            csv_writer.writerow(["Dec", result.decrypt_latency, result.decrypt_memory])
            csv_writer.writerow(["ERC20", result.erc20_latency, result.erc20_memory])
            csv_writer.writerow(["Mult64", result.mul_latency, result.mul_memory])


def main():
    parse_latency_file()
    parse_memory_file()
    output_result_csv_files()



if __name__ == "__main__":
    main()