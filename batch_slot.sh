#!/bin/bash

# 批量分析脚本 - batch_analyze.sh

# 显示用法信息
usage() {
    echo "用法: $0 -f <1|2> -d <contracts_directory>"
    echo "  -f 1: 将目录下所有合约作为逻辑合约单独分析"
    echo "  -f 2: 将目录下合约两两配对进行分析（逻辑合约+代理合约）"
    echo "  -d: 包含合约文件的目录"
    exit 1
}

# 使用高精度时间统计执行命令
execute_with_high_precision_timing() {
    local command="$1"
    local output_file="$2"
    
    # 使用time命令获取高精度时间统计
    # -p 使用POSIX格式输出
    # 重定向stderr到文件，同时保留stdout用于命令输出
    { time -p bash -c "$command" > >(tee /tmp/temp_stdout_$$.log) 2>&1; } 2> "$output_file"
    
    # 将命令输出保存到文件
    cat /tmp/temp_stdout_$$.log
    rm -f /tmp/temp_stdout_$$.log
    
    return $?
}

# 解析高精度时间输出
parse_high_precision_time() {
    local time_file="$1"
    local real_time=0
    local user_time=0
    local sys_time=0
    
    if [ -f "$time_file" ]; then
        while IFS= read -r line; do
            case $line in
                "real "*)
                    real_time=$(echo "$line" | awk '{print $2}')
                    ;;
                "user "*)
                    user_time=$(echo "$line" | awk '{print $2}')
                    ;;
                "sys "*)
                    sys_time=$(echo "$line" | awk '{print $2}')
                    ;;
            esac
        done < "$time_file"
    fi
    
    # 计算总CPU时间（用户+系统）
    local total_cpu_time=$(echo "$user_time + $sys_time" | bc -l)
    
    echo "${real_time},${total_cpu_time}"
}

# 监控进程内存使用
monitor_process_memory() {
    local pid=$1
    local monitor_peak=0
    local monitor_total=0
    local monitor_count=0
    
    # 监控进程直到它结束
    while kill -0 "$pid" 2>/dev/null; do
        # 获取当前内存使用
        local current_mem=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
        if [ -n "$current_mem" ] && [ "$current_mem" -gt 0 ]; then
            # 更新峰值
            if [ "$current_mem" -gt "$monitor_peak" ]; then
                monitor_peak=$current_mem
            fi
            # 累计用于计算平均值
            monitor_total=$((monitor_total + current_mem))
            monitor_count=$((monitor_count + 1))
        fi
        sleep 0.1  # 更频繁的采样
    done
    
    # 计算平均内存
    local monitor_avg=0
    if [ $monitor_count -gt 0 ]; then
        monitor_avg=$((monitor_total / monitor_count))
    fi
    
    echo "${monitor_peak},${monitor_avg}"
}

# 获取进程内存峰值
get_process_memory_peak() {
    local pid=$1
    local peak_mem=0
    
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
        echo "0"
        return
    fi
    
    # 使用ps获取峰值内存
    peak_mem=$(ps -o vsz= -p "$pid" 2>/dev/null | tr -d ' ')
    
    # 如果没有获取到，使用rss作为备选
    if [ -z "$peak_mem" ] || [ "$peak_mem" -eq 0 ]; then
        peak_mem=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
    fi
    
    echo "${peak_mem:-0}"
}

# 格式化时间显示
format_time() {
    local seconds=$1
    # 检查是否是小数
    if [[ $seconds =~ ^[0-9]+\.?[0-9]*$ ]]; then
        local int_seconds=$(echo "$seconds" | cut -d. -f1)
        local decimal=$(echo "$seconds" | cut -d. -f2)
        local milliseconds=$((decimal / 100))
        
        local hours=$((int_seconds / 3600))
        local minutes=$(( (int_seconds % 3600) / 60 ))
        local secs=$((int_seconds % 60))
        
        if [ $hours -gt 0 ]; then
            printf "%dh %dm %d.%02ds" $hours $minutes $secs $milliseconds
        elif [ $minutes -gt 0 ]; then
            printf "%dm %d.%02ds" $minutes $secs $milliseconds
        else
            printf "%d.%02ds" $secs $milliseconds
        fi
    else
        # 整数处理
        local hours=$((seconds / 3600))
        local minutes=$(( (seconds % 3600) / 60 ))
        local secs=$((seconds % 60))
        
        if [ $hours -gt 0 ]; then
            printf "%dh %dm %ds" $hours $minutes $secs
        elif [ $minutes -gt 0 ]; then
            printf "%dm %ds" $minutes $secs
        else
            printf "%ds" $secs
        fi
    fi
}

# 格式化内存显示
format_memory() {
    local kb=$1
    if [ $kb -ge 1048576 ]; then
        printf "%.2f GB" $(echo "scale=2; $kb / 1048576" | bc)
    elif [ $kb -ge 1024 ]; then
        printf "%.2f MB" $(echo "scale=2; $kb / 1024" | bc)
    else
        printf "%d KB" $kb
    fi
}

# 参数解析
FILE_COUNT=""
CONTRACTS_DIR=""

while getopts "f:d:" opt; do
    case $opt in
        f)
            FILE_COUNT="$OPTARG"
            ;;
        d)
            CONTRACTS_DIR="$OPTARG"
            ;;
        \?)
            echo "无效选项: -$OPTARG" >&2
            usage
            ;;
        :)
            echo "选项 -$OPTARG" 需要参数. >&2
            usage
            ;;
    esac
done

# 验证参数
if [ -z "$FILE_COUNT" ] || [ -z "$CONTRACTS_DIR" ]; then
    echo "错误: -f 和 -d 参数都是必需的"
    usage
fi

if [ "$FILE_COUNT" != "1" ] && [ "$FILE_COUNT" != "2" ]; then
    echo "错误: -f 参数必须是 1 或 2"
    usage
fi

if [ ! -d "$CONTRACTS_DIR" ]; then
    echo "错误: 目录 '$CONTRACTS_DIR' 不存在"
    exit 1
fi

# 检查必要的脚本是否存在
if [ ! -f "slotwarner.sh" ]; then
    echo "错误: slotwarner.sh 不存在于当前目录"
    exit 1
fi

if [ ! -f "slot_taint.py" ]; then
    echo "错误: slot_taint.py 不存在于当前目录"
    exit 1
fi

# 检查bc是否可用
if ! command -v bc &> /dev/null; then
    echo "错误: bc 命令不可用，请安装 bc 包"
    exit 1
fi

# 创建结果目录
RESULT_DIR="result"
mkdir -p "$RESULT_DIR"

# 创建临时目录用于存储时间统计文件
TIME_DIR="/tmp/cpu_time_stats_$$"
mkdir -p "$TIME_DIR"

# 创建性能统计文件（在脚本所在目录）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATS_FILE="$SCRIPT_DIR/csvslotwarner.csv"
echo "AnalysisType,Contract/Pair,StartTime,EndTime,TotalTime(seconds),PeakMemory(KB),AverageMemory(KB),CPUTime(seconds),Status" > "$STATS_FILE"

# 设置脚本可执行权限
chmod +x slotwarner.sh

echo "=== 开始批量分析 ==="
echo "模式: -f $FILE_COUNT"
echo "合约目录: $CONTRACTS_DIR"
echo "结果目录: $RESULT_DIR"
echo "性能统计: $STATS_FILE"
echo

# 获取所有sol文件
contract_files=()
while IFS= read -r -d '' file; do
    contract_files+=("$file")
done < <(find "$CONTRACTS_DIR" -name "*.sol" -type f -print0)

if [ ${#contract_files[@]} -eq 0 ]; then
    echo "错误: 在目录 '$CONTRACTS_DIR' 中未找到 .sol 文件"
    exit 1
fi

echo "找到 ${#contract_files[@]} 个合约文件:"
for file in "${contract_files[@]}"; do
    echo "  - $(basename "$file")"
done
echo

# 根据文件计数模式处理
if [ "$FILE_COUNT" -eq 1 ]; then
    # 单个文件模式：每个合约单独作为逻辑合约分析
    for contract_file in "${contract_files[@]}"; do
        contract_name=$(basename "$contract_file" .sol)
        echo "=== 分析逻辑合约: $contract_name ==="
        
        # 记录开始时间
        start_time=$(date +%s.%N)
        start_datetime=$(date '+%Y-%m-%d %H:%M:%S')
        
        # 创建临时文件用于存储时间统计
        slotwarner_time_file="$TIME_DIR/slotwarner_${contract_name}.time"
        slottaint_time_file="$TIME_DIR/slottaint_${contract_name}.time"
        
        # 步骤1: 运行 slotwarner.sh 并使用高精度计时
        echo "执行: ./slotwarner.sh \"$contract_file\""
        
        # 启动进程并获取PID
        ./slotwarner.sh "$contract_file" &
        slotwarner_pid=$!
        
        # 监控内存使用（在后台）
        monitor_process_memory $slotwarner_pid > "$TIME_DIR/slotwarner_memory_${contract_name}.log" &
        memory_monitor_pid=$!
        
        # 等待进程完成
        wait $slotwarner_pid
        slotwarner_exit_code=$?
        
        # 等待内存监控完成
        wait $memory_monitor_pid
        
        # 读取内存使用数据
        IFS=',' read -r slotwarner_peak_mem slotwarner_avg_mem < "$TIME_DIR/slotwarner_memory_${contract_name}.log"
        
        # 使用time命令重新执行以获取精确的CPU时间
        execute_with_high_precision_timing "./slotwarner.sh \"$contract_file\"" "$slotwarner_time_file" > /dev/null 2>&1
        
        # 解析时间输出
        IFS=',' read -r slotwarner_real_time slotwarner_cpu_time <<< "$(parse_high_precision_time "$slotwarner_time_file")"
        
        # 检查是否生成了布局文件
        layout_file="output/${contract_name}.json"
        if [ ! -f "$layout_file" ]; then
            echo "警告: 布局文件 $layout_file 未生成，跳过此合约"
            end_time=$(date +%s.%N)
            total_time=$(echo "$end_time - $start_time" | bc -l)
            echo "SingleContract,${contract_name},${start_datetime},$(date '+%Y-%m-%d %H:%M:%S'),${total_time},0,0,0,Failed: Layout file not generated" >> "$STATS_FILE"
            continue
        fi
        
        # 步骤2: 运行 slot_taint.py 并使用高精度计时
        echo "执行: python3 slot_taint.py -f 1 --logic-layout \"$layout_file\" \"output/${contract_name}.sol\""
        
        # 启动进程并获取PID
        python3 slot_taint.py -f 1 --logic-layout "$layout_file" "output/${contract_name}.sol" &
        slottaint_pid=$!
        
        # 监控内存使用（在后台）
        monitor_process_memory $slottaint_pid > "$TIME_DIR/slottaint_memory_${contract_name}.log" &
        memory_monitor_pid=$!
        
        # 等待进程完成
        wait $slottaint_pid
        slottaint_exit_code=$?
        
        # 等待内存监控完成
        wait $memory_monitor_pid
        
        # 读取内存使用数据
        IFS=',' read -r slottaint_peak_mem slottaint_avg_mem < "$TIME_DIR/slottaint_memory_${contract_name}.log"
        
        # 使用time命令重新执行以获取精确的CPU时间
        execute_with_high_precision_timing "python3 slot_taint.py -f 1 --logic-layout \"$layout_file\" \"output/${contract_name}.sol\"" "$slottaint_time_file" > /dev/null 2>&1
        
        # 解析时间输出
        IFS=',' read -r slottaint_real_time slottaint_cpu_time <<< "$(parse_high_precision_time "$slottaint_time_file")"
        
        # 计算总体资源使用
        overall_peak_mem=$((slotwarner_peak_mem > slottaint_peak_mem ? slotwarner_peak_mem : slottaint_peak_mem))
        overall_avg_mem=$(( (slotwarner_avg_mem + slottaint_avg_mem) / 2 ))
        overall_cpu_time=$(echo "$slotwarner_cpu_time + $slottaint_cpu_time" | bc -l)
        
        # 记录结束时间
        end_time=$(date +%s.%N)
        end_datetime=$(date '+%Y-%m-%d %H:%M:%S')
        total_time=$(echo "$end_time - $start_time" | bc -l)
        
        # 步骤3: 为每个合约创建独立目录并复制所有相关文件
        contract_result_dir="$RESULT_DIR/${contract_name}"
        mkdir -p "$contract_result_dir"
        
        echo "复制结果文件到 $contract_result_dir/"
        
        # 复制所有与该合约相关的文件
        for result_file in output/*"${contract_name}"*; do
            if [ -f "$result_file" ]; then
                filename=$(basename "$result_file")
                cp "$result_file" "$contract_result_dir/"
                echo "  已复制: $filename"
            fi
        done
        
        # 确保至少复制了主要的 .sol 和 .json 文件
        if [ -f "output/${contract_name}.sol" ]; then
            cp "output/${contract_name}.sol" "$contract_result_dir/" 2>/dev/null || true
        fi
        if [ -f "output/${contract_name}.json" ]; then
            cp "output/${contract_name}.json" "$contract_result_dir/" 2>/dev/null || true
        fi
        
        # 记录性能统计
        status="Success"
        if [ $slotwarner_exit_code -ne 0 ] || [ $slottaint_exit_code -ne 0 ]; then
            status="Warning: Some steps failed"
        fi
        
        echo "SingleContract,${contract_name},${start_datetime},${end_datetime},${total_time},${overall_peak_mem},${overall_avg_mem},${overall_cpu_time},${status}" >> "$STATS_FILE"
        
        echo "=== 完成逻辑合约: $contract_name ==="
        echo "时间花费: $(format_time $total_time)"
        echo "CPU时间: $(format_time $overall_cpu_time)"
        echo "内存峰值: $(format_memory $overall_peak_mem)"
        echo "平均内存: $(format_memory $overall_avg_mem)"
        echo "结果保存在: $contract_result_dir"
        echo
    done
    
else
    # 两个文件模式：合约两两配对分析
    echo "开始合约配对分析..."
    
    for ((i=0; i<${#contract_files[@]}; i++)); do
        for ((j=i+1; j<${#contract_files[@]}; j++)); do
            contract1="${contract_files[i]}"
            contract2="${contract_files[j]}"
            
            contract1_name=$(basename "$contract1" .sol)
            contract2_name=$(basename "$contract2" .sol)
            pair_name="${contract1_name}_${contract2_name}"
            
            echo "=== 分析合约对: $contract1_name + $contract2_name ==="
            
            # 记录开始时间
            start_time=$(date +%s.%N)
            start_datetime=$(date '+%Y-%m-%d %H:%M:%S')
            
            # 创建临时文件用于存储时间统计
            slotwarner_time_file="$TIME_DIR/slotwarner_${pair_name}.time"
            slottaint_time_file="$TIME_DIR/slottaint_${pair_name}.time"
            
            # 步骤1: 运行 slotwarner.sh 并使用高精度计时
            echo "执行: ./slotwarner.sh \"$contract1\" \"$contract2\""
            
            # 启动进程并获取PID
            ./slotwarner.sh "$contract1" "$contract2" &
            slotwarner_pid=$!
            
            # 监控内存使用（在后台）
            monitor_process_memory $slotwarner_pid > "$TIME_DIR/slotwarner_memory_${pair_name}.log" &
            memory_monitor_pid=$!
            
            # 等待进程完成
            wait $slotwarner_pid
            slotwarner_exit_code=$?
            
            # 等待内存监控完成
            wait $memory_monitor_pid
            
            # 读取内存使用数据
            IFS=',' read -r slotwarner_peak_mem slotwarner_avg_mem < "$TIME_DIR/slotwarner_memory_${pair_name}.log"
            
            # 使用time命令重新执行以获取精确的CPU时间
            execute_with_high_precision_timing "./slotwarner.sh \"$contract1\" \"$contract2\"" "$slotwarner_time_file" > /dev/null 2>&1
            
            # 解析时间输出
            IFS=',' read -r slotwarner_real_time slotwarner_cpu_time <<< "$(parse_high_precision_time "$slotwarner_time_file")"
            
            # 检查是否生成了布局文件
            layout1="output/${contract1_name}.json"
            layout2="output/${contract2_name}.json"
            
            if [ ! -f "$layout1" ] || [ ! -f "$layout2" ]; then
                echo "警告: 布局文件未完全生成，跳过此合约对"
                end_time=$(date +%s.%N)
                total_time=$(echo "$end_time - $start_time" | bc -l)
                echo "ContractPair,${pair_name},${start_datetime},$(date '+%Y-%m-%d %H:%M:%S'),${total_time},0,0,0,Failed: Layout files not fully generated" >> "$STATS_FILE"
                continue
            fi
            
            # 步骤2: 运行 slot_taint.py 并使用高精度计时
            echo "执行: python3 slot_taint.py -f 2 --logic-layout \"$layout1\" --proxy-layout \"$layout2\" \"output/${contract1_name}.sol\" \"output/${contract2_name}.sol\""
            
            # 启动进程并获取PID
            python3 slot_taint.py -f 2 --logic-layout "$layout1" --proxy-layout "$layout2" "output/${contract1_name}.sol" "output/${contract2_name}.sol" &
            slottaint_pid=$!
            
            # 监控内存使用（在后台）
            monitor_process_memory $slottaint_pid > "$TIME_DIR/slottaint_memory_${pair_name}.log" &
            memory_monitor_pid=$!
            
            # 等待进程完成
            wait $slottaint_pid
            slottaint_exit_code=$?
            
            # 等待内存监控完成
            wait $memory_monitor_pid
            
            # 读取内存使用数据
            IFS=',' read -r slottaint_peak_mem slottaint_avg_mem < "$TIME_DIR/slottaint_memory_${pair_name}.log"
            
            # 使用time命令重新执行以获取精确的CPU时间
            execute_with_high_precision_timing "python3 slot_taint.py -f 2 --logic-layout \"$layout1\" --proxy-layout \"$layout2\" \"output/${contract1_name}.sol\" \"output/${contract2_name}.sol\"" "$slottaint_time_file" > /dev/null 2>&1
            
            # 解析时间输出
            IFS=',' read -r slottaint_real_time slottaint_cpu_time <<< "$(parse_high_precision_time "$slottaint_time_file")"
            
            # 计算总体资源使用
            overall_peak_mem=$((slotwarner_peak_mem > slottaint_peak_mem ? slotwarner_peak_mem : slottaint_peak_mem))
            overall_avg_mem=$(( (slotwarner_avg_mem + slottaint_avg_mem) / 2 ))
            overall_cpu_time=$(echo "$slotwarner_cpu_time + $slottaint_cpu_time" | bc -l)
            
            # 记录结束时间
            end_time=$(date +%s.%N)
            end_datetime=$(date '+%Y-%m-%d %H:%M:%S')
            total_time=$(echo "$end_time - $start_time" | bc -l)
            
            # 步骤3: 为每对合约创建独立目录并复制所有相关文件
            pair_result_dir="$RESULT_DIR/${pair_name}"
            mkdir -p "$pair_result_dir"
            
            echo "复制结果文件到 $pair_result_dir/"
            
            # 复制所有与这对合约相关的文件
            for result_file in output/*"${contract1_name}"* output/*"${contract2_name}"*; do
                if [ -f "$result_file" ]; then
                    filename=$(basename "$result_file")
                    cp "$result_file" "$pair_result_dir/"
                    echo "  已复制: $filename"
                fi
            done
            
            # 确保至少复制了主要的 .sol 和 .json 文件
            for contract_name in "$contract1_name" "$contract2_name"; do
                if [ -f "output/${contract_name}.sol" ]; then
                    cp "output/${contract_name}.sol" "$pair_result_dir/" 2>/dev/null || true
                fi
                if [ -f "output/${contract_name}.json" ]; then
                    cp "output/${contract_name}.json" "$pair_result_dir/" 2>/dev/null || true
                fi
            done
            
            # 记录性能统计
            status="Success"
            if [ $slotwarner_exit_code -ne 0 ] || [ $slottaint_exit_code -ne 0 ]; then
                status="Warning: Some steps failed"
            fi
            
            echo "ContractPair,${pair_name},${start_datetime},${end_datetime},${total_time},${overall_peak_mem},${overall_avg_mem},${overall_cpu_time},${status}" >> "$STATS_FILE"
            
            echo "=== 完成合约对: $contract1_name + $contract2_name ==="
            echo "时间花费: $(format_time $total_time)"
            echo "CPU时间: $(format_time $overall_cpu_time)"
            echo "内存峰值: $(format_memory $overall_peak_mem)"
            echo "平均内存: $(format_memory $overall_avg_mem)"
            echo "结果保存在: $pair_result_dir"
            echo
        done
    done
fi

# 清理临时目录
rm -rf "$TIME_DIR"

echo "=== 批量分析完成 ==="
echo "所有结果保存在: $RESULT_DIR/"
echo "性能统计保存在: $STATS_FILE"
echo
echo "性能统计摘要:"
echo "----------------------------------------"
if [ -f "$STATS_FILE" ] && [ $(wc -l < "$STATS_FILE") -gt 1 ]; then
    tail -n +2 "$STATS_FILE" | while IFS=',' read -r type contract start end time peak avg cpu status; do
        echo "Contract: $contract"
        echo "  Type: $type | Status: $status"
        echo "  Wall Time: $(format_time $time) | CPU Time: $(format_time $cpu)"
        echo "  Peak Memory: $(format_memory $peak) | Avg Memory: $(format_memory $avg)"
        echo "----------------------------------------"
    done
else
    echo "No statistics information"
fi
