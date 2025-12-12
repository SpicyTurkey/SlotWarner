#!/bin/bash
if [ $# -lt 1 ]; then
    echo "usage: $0 <file_path1> <file_path2> ..."
    exit 1
fi

OUTPUT_DIR="output"

echo "=== Processing multiple solidity files ==="

rm -rf hard/contracts
mkdir -p hard/contracts
rm -rf output/
mkdir -p output

for CONTRACT_PATH in "$@"; do
    CONTRACT_NAME=$(basename "$CONTRACT_PATH" .sol)
    echo "Copying: $CONTRACT_PATH -> hard/contracts/"
    cp "$CONTRACT_PATH" hard/contracts/
    cp "$CONTRACT_PATH" output/
done

cd hard
npx hardhat clean
npx hardhat compile
cd ..

find "hard/artifacts/contracts" -name "*.dbg.json" | while read dbg_file; do
    contract_file=$(basename "$dbg_file" .dbg.json)
    filename=$(basename $(jq -r '.buildInfo' "$dbg_file"))
    echo "-------> processing build-info files $filename"
    new_path="hard/artifacts/build-info/$filename"
    build_info_path="$new_path"
    
    if [ "$build_info_path" != "null" ] && [ -n "$build_info_path" ]; then
        
        if [ -f "$build_info_path" ]; then            
            contracts=$(jq -r '.output.contracts | keys[]' "$build_info_path")
            
            echo "$contracts" | while read contract_key; do                
                contract_name=$(echo "$contract_key" | sed 's/.*\///' | sed 's/\.sol//')
                
                storage_data=$(jq -r --arg key "$contract_key" '
                    .output.contracts[$key] as $contracts |
                    $contracts | 
                    to_entries[] | 
                    select(.value.storageLayout? != null) |
                    {
                        contract: .key,
                        storage: .value.storageLayout.storage | map({
                            variable: .label,
                            slot: .slot,
                            offset: (.offset // 0),
                            type: .type
                        })
                    }
                ' "$build_info_path")
                
                if [ -n "$storage_data" ] && [ "$storage_data" != "null" ]; then
                    output_file="$OUTPUT_DIR/${contract_name}.json"
                    echo "$storage_data" > "$output_file"
                    echo "Generated storage layout for: $contract_name"
                else
                    echo "contract $contract_name has no storage-layout info"
                fi
            done
        else
            echo "buildInfo does not exist: $build_info_path"
        fi
    else
        echo "file : $dbg_file does not find buildInfo path"
    fi
done

echo "=== generate storage layout info for all contracts ---> Done ==="
