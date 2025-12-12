import os
import re
import subprocess
import sys
from semantic_version import NpmSpec, Version
from slither import Slither

"""
使用方法：
solc_control.switch_solc_version("合约源码路径")
该方法会：
1 查找本地文件中的所有可用solc版本
2 读取合约中声明的solc版本，并自动进行切换

注意：
由于实验区域网络问题，该方法不会自动从网络上下载需要的版本，只会查找本地有的版本
"""

all_candidates = []


def get_all_candidates():
    print(f"all_candidates : {all_candidates}")
    return all_candidates


def switch_solc_version(content_path):  # 只切换一次，多次切换不用这个
    versions = get_local_solc_version()
    with open(content_path, 'r', encoding='utf-8') as f:
        content = f.read()

    """智能合并多个版本约束"""
    pragma_matches = re.findall(r'pragma\s+solidity\s+([^;]+);', content)
    if not pragma_matches:
        print("没有匹配的pragma_matches，尝试使用默认版本")
        fallback_versions = ['0.4.25', '0.5.17', '0.6.12', '0.7.6', '0.8.4']

        for ver in fallback_versions:
            try:
                # 切换版本
                subprocess.run(
                    f"solc-select use {ver}",
                    shell=True, check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"正在尝试版本: {ver}")

                # 验证版本是否切换成功
                version_check = subprocess.run(
                    "solc --version",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                current_ver = re.search(r'\d+\.\d+\.\d+', version_check.stdout).group(0)
                if current_ver != ver:
                    print(f"{ver}版本切换验证失败")
                    continue

                # 尝试分析
                slither_obj = Slither(
                    content_path,
                    disable_solc_warnings=True,
                    solc_arguments=[
                        "--allow-paths", ".",
                        "--evm-version", "byzantium"
                    ]
                )

                print(f"版本 {ver} 分析成功")
                return slither_obj  # 成功时退出循环

            except Exception as e:
                print(f"版本 {ver} 尝试失败: {str(e)}")
                continue

        raise Exception("所有备用版本尝试失败，终止分析")

    normalized_constraints = []
    for expr in pragma_matches:  # 捕获合约中得所有版本信息
        clean_expr = re.sub(r'\s+', '', expr)
        if clean_expr.startswith('v'):
            clean_expr = clean_expr[1:]
        if not re.match(r'^[\^~<>=]?\d+\.\d+\.\d+', clean_expr):
            continue
        normalized_constraints.append(clean_expr)

    if not normalized_constraints:
        return None

    try:
        # 生成复合约束
        combined_spec = NpmSpec(' '.join(normalized_constraints))
    except ValueError as e:
        print(f"约束合并失败: {normalized_constraints} - {str(e)}")
        return None

    # 获取匹配的solc版本
    valid_versions = []
    for ver_str in versions:
        try:
            ver = Version(ver_str)
            if combined_spec.match(ver):
                valid_versions.append(ver)
        except ValueError:
            continue

    if not valid_versions:
        return None

    # 按版本号降序排序（从高到低）
    valid_versions.sort(reverse=False)
    print(f"pragma约束求解后得到可用solc版本: {[str(v) for v in valid_versions]}")

    if not versions:
        print("错误: 本地未安装任何solc版本")
        return None

    candidates = [str(v) for v in valid_versions]
    global all_candidates
    all_candidates = candidates

    # 遍历所有候选版本尝试分析
    for ver in all_candidates:
        try:
            # 切换版本
            subprocess.run(
                f"solc-select use {ver}",
                shell=True, check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            # print(f"正在尝试版本: {ver}")

            # 验证版本是否切换成功
            version_check = subprocess.run(
                "solc --version",
                shell=True,
                capture_output=True,
                text=True
            )
            current_ver = re.search(r'\d+\.\d+\.\d+', version_check.stdout).group(0)
            if current_ver != ver:
                print(f"版本切换验证失败，当前版本: {current_ver}")
                continue

            # 尝试分析
            slither_obj = Slither(
                content_path,
                disable_solc_warnings=True,
                solc_arguments=[
                    "--allow-paths", ".",
                    "--evm-version", "byzantium"
                ]
            )

            print(f"切换版本 {ver} 成功")
            return slither_obj  # 成功时退出循环

        except subprocess.CalledProcessError as e:
            print(f"版本 {ver} 切换失败: {e.stderr.decode().strip()}")
        except Exception as e:
            print(f"版本 {ver} 分析失败: {str(e)}")

    return None


def search_current_solc_version():  # 查找当前使用的solc版本
    result = subprocess.run(
        f"solc --version",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    current_ver = re.search(r'\d+\.\d+\.\d+', result.stdout).group(0)
    return current_ver


def switch_single_solc_version(ver):  # 切换为指定solc版本
    subprocess.run(
        f"solc-select use {ver}",
        shell=True, check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    print(f"成功切换至: {ver}")


def get_local_solc_version():  # 获取已安装版本（优化性能）
    versions = []  # 保存本地solc版本
    import platform
    try:
        if platform.system() == "Windows":
            try:
                print("尝试使用PowerShell获取solc版本")
                ps_path = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                output = subprocess.check_output(
                    command,
                    shell=True,
                    executable=ps_path,
                    stderr=subprocess.STDOUT,
                    timeout=15
                )
            # 方法2：如果找不到 PowerShell，尝试使用 cmd
            except Exception:
                print("未找到PowerShell，尝试使用cmd")
                output = subprocess.check_output(
                    command,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    timeout=15
                )
        else:
            output = subprocess.check_output("solc-select versions",
                                             shell=True,
                                             stderr=subprocess.STDOUT,
                                             timeout=15)
        seen = set()
        for v in output.decode().split():
            if re.match(r'^\d+\.\d+\.\d+$', v) and v not in seen:
                seen.add(v)
                versions.append(v)
        # print(f"本地可用的solc versions:{versions}")
        return versions
    except Exception as e:
        print(f"获取安装版本失败cc: {str(e)}")
        return None

def generat_slot_used(source_code_path):
    if not os.path.exists(source_code_path):
        print(f"路径不存在: {source_code_path}")
        sys.exit(2)

    slitherT = switch_solc_version(source_code_path)
    return slitherT


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("使用方法: python solc_control.py <合约目录路径>")
        sys.exit(1)

    source_code_path = sys.argv[1]
    if not os.path.exists(source_code_path):
        print(f"路径不存在: {source_code_path}")
        sys.exit(2)

    slither = switch_solc_version(source_code_path)