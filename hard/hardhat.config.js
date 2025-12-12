require("@nomicfoundation/hardhat-toolbox");
const path = require("path");
const fs = require("fs");

function getAvailableLocalSolcVersions() {
  const solcBasePath = "/home/slot/.solc-select/artifacts";
  const availableVersions = new Map();
  
  try {
    if (fs.existsSync(solcBasePath)) {
      const items = fs.readdirSync(solcBasePath);
      
      items.forEach(item => {
        if (item.startsWith("solc-")) {
          const version = item.replace("solc-", "");
          const compilerPath = path.join(solcBasePath, item, item);
          
          // 只添加大于 0.5.12 的版本
          if (fs.existsSync(compilerPath) && compareVersions(version, "0.5.12") > 0) {
            try {
              fs.accessSync(compilerPath, fs.constants.X_OK);
              availableVersions.set(version, compilerPath);
            } catch (e) {
              console.log(`⚠️  损坏的编译器版本: ${version}`);
            }
          }
        }
      });
    }
  } catch (error) {
    console.log("❌ 错误:", error.message);
  }
  
  return availableVersions;
}

const localSolcVersions = getAvailableLocalSolcVersions();

// 比较两个版本号
function compareVersions(a, b) {
  const aParts = a.split('.').map(Number);
  const bParts = b.split('.').map(Number);
  
  for (let i = 0; i < 3; i++) {
    const aPart = aParts[i] || 0;
    const bPart = bParts[i] || 0;
    
    if (aPart > bPart) return 1;
    if (aPart < bPart) return -1;
  }
  
  return 0;
}

// 获取指定大版本范围内的最高可用版本
function getHighestAvailableVersion(constraint, availableVersions) {
  const versions = Array.from(availableVersions.keys());
  
  // 解析版本约束
  let minVersion = null;
  let maxVersion = null;
  let excludeMax = false;
  
  // 处理 >=X.X.X <Y.Y.Y 格式
  if (constraint.includes("<")) {
    const parts = constraint.split('<');
    minVersion = parts[0].replace('>=', '').trim();
    maxVersion = parts[1].trim();
    excludeMax = true;
  } 
  // 处理 >=X.X.X <=Y.Y.Y 格式
  else if (constraint.includes("<=")) {
    const parts = constraint.split('<=');
    minVersion = parts[0].replace('>=', '').trim();
    maxVersion = parts[1].trim();
    excludeMax = false;
  }
  // 处理简单的 >=X.X.X 格式
  else if (constraint.startsWith(">=")) {
    minVersion = constraint.slice(2).trim();
  }
  // 处理 ^X.X.X 格式
  else if (constraint.startsWith("^")) {
    minVersion = constraint.slice(1).trim();
    const [major, minor] = minVersion.split('.').map(Number);
    maxVersion = `${major + 1}.0.0`;
    excludeMax = true;
  }
  // 处理 ~X.X.X 格式
  else if (constraint.startsWith("~")) {
    minVersion = constraint.slice(1).trim();
    const [major, minor] = minVersion.split('.').map(Number);
    maxVersion = `${major}.${minor + 1}.0`;
    excludeMax = true;
  }
  
  // 确保最小版本不低于 0.5.13
  if (!minVersion || compareVersions(minVersion, "0.5.13") < 0) {
    minVersion = "0.5.13";
  }
  
  // 过滤满足条件的版本
  const validVersions = versions.filter(version => {
    // 确保版本大于 0.5.12
    if (compareVersions(version, "0.5.12") <= 0) {
      return false;
    }
    
    if (minVersion && compareVersions(version, minVersion) < 0) {
      return false;
    }
    if (maxVersion) {
      if (excludeMax && compareVersions(version, maxVersion) >= 0) {
        return false;
      }
      if (!excludeMax && compareVersions(version, maxVersion) > 0) {
        return false;
      }
    }
    return true;
  });
  
  if (validVersions.length === 0) {
    return null;
  }
  
  // 按版本号降序排序并返回最高版本
  validVersions.sort((a, b) => compareVersions(b, a));
  return validVersions[0];
}

function createCompilersConfig() {
  const compilers = [];
  
  // 只使用本地可用的编译器版本，且版本大于 0.5.12
  const localVersions = Array.from(localSolcVersions.keys());
  
  localVersions.forEach(version => {
    compilers.push({
      version: version,
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        },
        outputSelection: {
          "*": {
            "*": [
              "storageLayout",
              "evm.bytecode", 
              "evm.deployedBytecode",
              "abi"
            ]
          }
        }
      }
    });
  });
  
  return compilers;
}

module.exports = {
  solidity: {
    compilers: createCompilersConfig(),
    overrides: {}
  },
  
  paths: {
    sources: "./contracts",
    tests: "./test", 
    cache: "./cache",
    artifacts: "./artifacts"
  }
};

const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");
const { TASK_COMPILE_SOLIDITY_GET_COMPILATION_JOB_FOR_FILE } = require("hardhat/builtin-tasks/task-names");

// 重写编译任务，处理版本选择逻辑
task(TASK_COMPILE_SOLIDITY_GET_COMPILATION_JOB_FOR_FILE, async (args, hre, runSuper) => {
  const job = await runSuper(args);
  
  if (!job || !job.solidityVersion) {
    return job;
  }
  
  // 处理版本约束（>=X.X.X, >=X.X.X <Y.Y.Y, ^X.X.X, ~X.X.X 等）
  if (job.solidityVersion.startsWith(">=") || 
      job.solidityVersion.startsWith("^") || 
      job.solidityVersion.startsWith("~")) {
    
    const highestVersion = getHighestAvailableVersion(job.solidityVersion, localSolcVersions);
    
    if (highestVersion) {
      console.log(`🔄 版本重映射: ${job.solidityVersion} -> ${highestVersion}`);
      job.solidityVersion = highestVersion;
    } else {
      console.log(`❌ 没有找到满足约束 ${job.solidityVersion} 且大于 0.5.12 的本地编译器版本`);
      throw new Error(`没有找到满足约束 ${job.solidityVersion} 且大于 0.5.12 的本地编译器版本`);
    }
  } else {
    // 对于固定版本，检查是否大于 0.5.12
    if (compareVersions(job.solidityVersion, "0.5.12") <= 0) {
      console.log(`❌ 版本 ${job.solidityVersion} 不符合要求（必须大于 0.5.12）`);
      throw new Error(`版本 ${job.solidityVersion} 不符合要求（必须大于 0.5.12）`);
    }
    
    // 检查本地是否有该版本
    if (!localSolcVersions.has(job.solidityVersion)) {
      console.log(`❌ 未找到本地 solc 版本: ${job.solidityVersion}`);
      throw new Error(`未找到本地 solc 版本: ${job.solidityVersion}`);
    }
  }
  
  return job;
});

task(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  const { solcVersion } = args;
  
  if (localSolcVersions.has(solcVersion)) {
    const compilerPath = localSolcVersions.get(solcVersion);
    console.log(`🎯 Use local solc: ${solcVersion}`);
    
    return {
      compilerPath: compilerPath,
      isSolcJs: false,
      version: solcVersion,
      longVersion: solcVersion
    };
  }
  
  console.log(`❌ 未找到本地 solc 版本: ${solcVersion}`);
  throw new Error(`未找到本地 solc 版本: ${solcVersion}`);
});

task("list-local-solc", "列出所有可用的本地 solc 版本", async () => {
  console.log("\n📋 可用的本地 solc 版本（大于 0.5.12）:");
  if (localSolcVersions.size === 0) {
    console.log("   未找到大于 0.5.12 的本地 solc 编译器");
  } else {
    localSolcVersions.forEach((path, version) => {
      console.log(`   ✅ solc ${version}`);
    });
  }
});

const { TASK_COMPILE } = require("hardhat/builtin-tasks/task-names");

task(TASK_COMPILE, async (args, hre, runSuper) => {
  console.log("compiling...");
  
  // 检查是否有可用的编译器
  if (localSolcVersions.size === 0) {
    console.log("❌ 没有找到大于 0.5.12 的本地 solc 编译器，无法编译");
    throw new Error("没有找到大于 0.5.12 的本地 solc 编译器");
  }
  
  return runSuper();
});
