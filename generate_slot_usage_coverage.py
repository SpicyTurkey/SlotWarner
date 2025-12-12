"""
合约存储槽位污染分析脚本
生成完整的存储槽位布局图，并标记直接和间接污染的槽位
"""

import os
import json
import glob
import re
from pathlib import Path
from slither import Slither
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
import solc_control as sc


def split_multiple_json_objects(content):
    """
    将包含多个JSON对象的内容分割成单独的JSON对象

    Args:
        content: 包含多个JSON对象的字符串

    Returns:
        list: 单独的JSON对象字典列表
    """
    objects = []
    brace_count = 0
    current_obj = ""

    for char in content:
        current_obj += char
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                # 找到一个完整的JSON对象
                try:
                    obj = json.loads(current_obj.strip())
                    objects.append(obj)
                    current_obj = ""
                except json.JSONDecodeError:
                    # 如果解析失败，继续累积字符
                    continue

    return objects


def analyze_contract_storage(sol_file_path, json_file_path):
    """
    分析合约存储布局并标记可被污染的槽位

    Args:
        sol_file_path: .sol合约文件路径
        json_file_path: .json存储布局文件路径

    Returns:
        dict: 包含污染分析结果的数据结构
    """

    try:
        # 使用Slither分析合约
        slither = sc.generat_slot_used(str(sol_file_path))
    except Exception as e:
        print(f"Slither分析失败: {e}")
        return None

    # 读取存储布局JSON文件 - 处理多个JSON对象
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        # 分割多个JSON对象
        json_objects = split_multiple_json_objects(content)
        print(f"找到 {len(json_objects)} 个JSON对象")

        # 创建合约名到存储布局的映射
        storage_layouts = {}
        for obj in json_objects:
            contract_name = obj.get('contract')
            if contract_name:
                storage_layouts[contract_name] = obj

    except Exception as e:
        print(f"读取存储布局文件失败: {e}")
        print(f"文件内容前500字符: {content[:500] if 'content' in locals() else '无法读取'}")
        return None

    analysis_result = {
        "contracts": {},
        "contaminated_slots": []
    }

    # 遍历所有合约
    for contract in slither.contracts:
        contract_name = contract.name
        print(f"分析合约: {contract_name}")

        # 获取合约的存储布局
        contract_storage = storage_layouts.get(contract_name)

        if not contract_storage:
            print(f"未找到合约 {contract_name} 的存储布局")
            print(f"可用的合约名: {list(storage_layouts.keys())}")
            continue

        # 获取所有状态变量及其存储信息
        all_variables = get_all_state_variables(contract, contract_storage)

        # 查找可被外部调用的函数
        external_functions = find_external_functions(contract)

        # 查找这些函数可以直接修改的状态变量
        directly_contaminated_variables = find_directly_contaminated_variables(external_functions, contract)

        # 进行污染传播分析
        contaminated_variables = propagate_contamination(directly_contaminated_variables, contract, all_variables)

        # 标记被污染的存储槽位
        contaminated_slots = mark_contaminated_slots(contaminated_variables, contract_storage, contract_name)

        # 获取所有存储槽位信息
        all_slots = get_all_slots(contract_storage, contract_name)

        analysis_result["contracts"][contract_name] = {
            "external_functions": [f.name for f in external_functions],
            "directly_contaminated_variables": [v.name for v in directly_contaminated_variables],
            "contaminated_variables": [v.name for v in contaminated_variables],
            "storage_slots": all_slots,
            "contaminated_slots": contaminated_slots
        }

        analysis_result["contaminated_slots"].extend(contaminated_slots)

    return analysis_result


def get_all_state_variables(contract, storage_layout):
    """
    获取合约的所有状态变量及其存储信息

    Args:
        contract: Slither合约对象
        storage_layout: 存储布局数据

    Returns:
        dict: 变量名到变量对象的映射
    """
    variables = {}
    for variable in contract.state_variables:
        variables[variable.name] = variable
    return variables


def find_external_functions(contract):
    """
    查找可被外部用户调用的函数

    Args:
        contract: Slither合约对象

    Returns:
        list: 外部函数列表
    """
    external_functions = []

    for function in contract.functions:
        # 排除构造函数和fallback/receive函数
        if function.is_constructor or function.is_fallback or function.is_receive:
            continue

        # 检查函数可见性 - 必须是public或external
        if function.visibility not in ['public', 'external']:
            continue

        # 检查是否有onlyOwner等修饰器限制
        if has_restrictive_modifiers(function):
            continue

        external_functions.append(function)

    return external_functions


def has_restrictive_modifiers(function):
    """
    检查函数是否有限制性修饰器（如onlyOwner）

    Args:
        function: Slither函数对象

    Returns:
        bool: 是否有限制性修饰器
    """
    restrictive_patterns = [
        'onlyOwner', 'onlyAdmin', 'onlyRole', 'authenticated',
        'whenNotPaused', 'nonReentrant', 'onlyowner', 'onlyadmin'
    ]

    for modifier in function.modifiers:
        modifier_name = modifier.name.lower()
        for pattern in restrictive_patterns:
            if pattern.lower() in modifier_name:
                return True

    return False


def find_directly_contaminated_variables(external_functions, contract):
    """
    查找可被外部函数直接修改的状态变量

    Args:
        external_functions: 外部函数列表
        contract: Slither合约对象

    Returns:
        list: 可直接被污染的状态变量列表
    """
    contaminated_variables = set()

    for function in external_functions:
        # 获取函数写入的状态变量
        written_variables = function.state_variables_written

        for variable in written_variables:
            # 确保变量属于当前合约
            if variable.contract == contract:
                contaminated_variables.add(variable)

    return list(contaminated_variables)


def propagate_contamination(directly_contaminated, contract, all_variables):
    """
    进行污染传播分析，找出所有可能被污染的变量

    Args:
        directly_contaminated: 直接污染的变量列表
        contract: Slither合约对象
        all_variables: 所有状态变量

    Returns:
        list: 所有可能被污染的变量列表
    """
    contaminated = set(directly_contaminated)
    # 用于跟踪是否在迭代中有新的污染变量被发现
    changed = True

    # 进行多轮传播，直到没有新的污染变量被发现
    while changed:
        changed = False
        for function in contract.functions:
            # 检查函数中是否使用了被污染的变量
            used_contaminated = False
            for var in function.state_variables_read:
                if var in contaminated:
                    used_contaminated = True
                    break

            # 如果函数使用了被污染的变量，则它写入的所有变量也被污染
            if used_contaminated:
                for var in function.state_variables_written:
                    if var not in contaminated and var.contract == contract:
                        contaminated.add(var)
                        changed = True

    return list(contaminated)


def mark_contaminated_slots(contaminated_variables, storage_layout, contract_name):
    """
    标记被污染的存储槽位

    Args:
        contaminated_variables: 被污染的状态变量列表
        storage_layout: 存储布局数据
        contract_name: 合约名称

    Returns:
        list: 被污染的槽位信息
    """
    contaminated_slots = []

    if 'storage' not in storage_layout:
        return contaminated_slots

    # 创建变量名到存储信息的映射
    variable_storage_map = {}
    for storage_item in storage_layout['storage']:
        # 使用'variable'字段作为变量名
        variable_name = storage_item.get('variable')
        if variable_name:
            variable_storage_map[variable_name] = storage_item

    # 标记被污染的变量
    for variable in contaminated_variables:
        variable_name = variable.name
        if variable_name in variable_storage_map:
            storage_info = variable_storage_map[variable_name]

            slot_info = {
                'variable_name': variable_name,
                'slot': storage_info.get('slot', 'unknown'),
                'offset': storage_info.get('offset', 0),
                'type': storage_info.get('type', 'unknown'),
                'contract': contract_name,
                'contaminated': True
            }
            contaminated_slots.append(slot_info)

    return contaminated_slots


def get_all_slots(storage_layout, contract_name):
    """
    获取合约的所有存储槽位信息

    Args:
        storage_layout: 存储布局数据
        contract_name: 合约名称

    Returns:
        list: 所有存储槽位信息
    """
    all_slots = []

    if 'storage' not in storage_layout:
        return all_slots

    for storage_item in storage_layout['storage']:
        slot_info = {
            'variable_name': storage_item.get('variable', 'unknown'),
            'slot': storage_item.get('slot', 'unknown'),
            'offset': storage_item.get('offset', 0),
            'type': storage_item.get('type', 'unknown'),
            'contract': contract_name,
            'contaminated': False  # 将在后续步骤中标记
        }
        all_slots.append(slot_info)

    return all_slots


def get_slot_visualization(all_slots, contaminated_slots, slot_size=32):
    """
    生成存储槽位的可视化表示

    Args:
        all_slots: 所有槽位数据
        contaminated_slots: 被污染的槽位数据
        slot_size: 槽位大小（字节）

    Returns:
        str: 可视化的槽位表示
    """
    # 创建污染变量映射
    contaminated_map = {}
    for item in contaminated_slots:
        slot_key = f"{item['slot']}_{item['offset']}"
        contaminated_map[slot_key] = True

    # 按槽位分组
    slots = {}
    for item in all_slots:
        slot = item['slot']
        if slot not in slots:
            slots[slot] = []
        # 标记是否被污染
        slot_key = f"{item['slot']}_{item['offset']}"
        item['contaminated'] = slot_key in contaminated_map
        slots[slot].append(item)

    visualization = ""

    for slot_num in sorted(slots.keys(), key=lambda x: int(x) if x.isdigit() else x):
        visualization += f"\n槽位 {slot_num}:\n"

        # 创建槽位字节图
        slot_bytes = ["  "] * slot_size  # 每个位置用2个字符表示

        # 标记每个变量在槽位中的位置
        for item in slots[slot_num]:
            offset = item['offset']
            var_name = item['variable_name']
            contaminated = item['contaminated']
            var_type = item['type']

            # 根据类型估算变量大小
            size = estimate_variable_size(var_type)

            # 标记变量位置
            for i in range(offset, min(offset + size, slot_size)):
                if contaminated:
                    slot_bytes[i] = "██"  # 被污染的变量用██表示
                else:
                    slot_bytes[i] = "░░"  # 安全的变量用░░表示

            # 添加变量信息
            status = "⚠️被污染" if contaminated else "✅安全"
            visualization += f"  {offset:2d}-{offset + size - 1:2d}: {var_name} ({var_type}) [{status}]\n"

        # 添加字节图
        visualization += "  " + "".join(slot_bytes) + "\n"

        # 添加字节索引
        indices = "  "
        for i in range(0, slot_size, 4):
            indices += f"{i:2d}  "
        visualization += indices + "\n"

    return visualization


def estimate_variable_size(var_type):
    """
    根据变量类型估算其大小（字节）

    Args:
        var_type: 变量类型字符串

    Returns:
        int: 估算的大小
    """
    # 基本类型大小映射
    type_sizes = {
        't_address': 20,
        't_bool': 1,
        't_uint8': 1,
        't_uint16': 2,
        't_uint32': 4,
        't_uint64': 8,
        't_uint128': 16,
        't_uint256': 32,
        't_int8': 1,
        't_int16': 2,
        't_int32': 4,
        't_int64': 8,
        't_int128': 16,
        't_int256': 32,
        't_bytes1': 1,
        't_bytes2': 2,
        't_bytes4': 4,
        't_bytes8': 8,
        't_bytes16': 16,
        't_bytes32': 32,
    }

    # 检查精确匹配
    for pattern, size in type_sizes.items():
        if pattern in var_type:
            return size

    # 检查包含关系
    if 'uint' in var_type:
        # 提取数字
        match = re.search(r'uint(\d+)', var_type)
        if match:
            bits = int(match.group(1))
            return bits // 8
        return 32  # 默认uint256大小

    if 'int' in var_type:
        # 提取数字
        match = re.search(r'int(\d+)', var_type)
        if match:
            bits = int(match.group(1))
            return bits // 8
        return 32  # 默认int256大小

    if 'bytes' in var_type and not var_type.startswith('t_bytes'):
        # 提取数字
        match = re.search(r'bytes(\d+)', var_type)
        if match:
            return int(match.group(1))

    # 映射和数组类型通常占用整个槽位
    if 'mapping' in var_type or 'array' in var_type:
        return 32

    # 默认大小
    return 32


def generate_slot_file_content(analysis_result):
    """
    生成可视化的.slot文件内容

    Args:
        analysis_result: 分析结果

    Returns:
        str: 可视化的.slot文件内容
    """
    content = "合约存储槽位污染分析报告\n"
    content += "=" * 60 + "\n\n"

    content += "图例说明:\n"
    content += "  ██ - 可被外部用户污染的存储区域\n"
    content += "  ░░ - 安全的存储区域\n"
    content += "  ⚠️  - 被污染的变量\n"
    content += "  ✅  - 安全的变量\n\n"

    for contract_name, contract_data in analysis_result["contracts"].items():
        content += f"合约: {contract_name}\n"
        content += "-" * 40 + "\n"

        content += "可被外部调用的函数:\n"
        for func in contract_data["external_functions"]:
            content += f"  - {func}\n"

        content += "\n直接可被污染的状态变量:\n"
        directly_contaminated = contract_data["directly_contaminated_variables"]
        if directly_contaminated:
            for var in directly_contaminated:
                content += f"  - {var} ⚠️\n"
        else:
            content += "  无\n"

        content += "\n所有可能被污染的状态变量 (包括传播):\n"
        all_contaminated = contract_data["contaminated_variables"]
        if all_contaminated:
            for var in all_contaminated:
                content += f"  - {var} ⚠️\n"
        else:
            content += "  无\n"

        # 生成可视化槽位布局
        if contract_data["storage_slots"]:
            content += "\n完整存储槽位布局:\n"
            visualization = get_slot_visualization(
                contract_data["storage_slots"],
                contract_data["contaminated_slots"]
            )
            content += visualization
        else:
            content += "\n未找到存储槽位信息\n"

        content += "\n" + "=" * 60 + "\n\n"

    # 汇总统计
    total_contaminated = len(analysis_result["contaminated_slots"])
    if total_contaminated > 0:
        content += f"汇总: 发现 {total_contaminated} 个被污染的存储槽位\n"
    else:
        content += "汇总: 未发现被污染的存储槽位\n"

    return content


def main():
    """主函数"""
    # 获取脚本所在目录
    output_dir = Path("output")

    if not output_dir.exists():
        print(f"错误: 未找到output目录: {output_dir}")
        return

    # 查找所有.json文件
    json_files = list(output_dir.glob("*.json"))

    if not json_files:
        print("在output目录中未找到任何JSON文件")
        return

    for json_file in json_files:
        prefix = json_file.stem
        sol_file = output_dir / f"{prefix}.sol"

        if not sol_file.exists():
            print(f"警告: 未找到对应的.sol文件: {sol_file}")
            continue

        print(f"分析文件对: {prefix}")
        print(f"  JSON: {json_file}")
        print(f"  SOL: {sol_file}")

        # 分析合约
        analysis_result = analyze_contract_storage(sol_file, json_file)

        if analysis_result:
            # 生成.slot文件内容
            slot_content = generate_slot_file_content(analysis_result)

            # 写入.slot文件
            slot_file = output_dir / f"{prefix}.slot"
            with open(slot_file, 'w', encoding='utf-8') as f:
                f.write(slot_content)

            print(f"生成槽位分析文件: {slot_file}")

            # 打印简要结果
            total_contaminated = len(analysis_result["contaminated_slots"])
            print(f"发现 {total_contaminated} 个被污染的存储槽位")
        else:
            print(f"分析失败: {prefix}")

        print()


if __name__ == "__main__":
    # 检查slither是否可用
    try:
        from slither import Slither

        main()
    except ImportError:
        print("错误: 未安装slither。请使用以下命令安装:")
        print("pip install slither-analyzer")
    except Exception as e:
        print(f"运行错误: {e}")
        import traceback

        traceback.print_exc()