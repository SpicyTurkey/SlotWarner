// scripts/analyzeStorage.js
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function analyzeStorage() {
    console.log("开始编译合约...");
    
    // 编译合约
    await hre.run("compile");
    
    console.log("编译完成！");
    
    // 读取编译后的 artifacts 来获取存储布局
    const artifactPath = path.join(
        __dirname,
        "..",
        "artifacts",
        "contracts",
        "Lock.sol",
        "StorageLayoutExample.json"
    );
    
    if (fs.existsSync(artifactPath)) {
        const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
        
        console.log("=== 合约信息 ===");
        console.log("合约名称:", artifact.contractName);
        console.log("编译器版本:", artifact._format);
        
        if (artifact.storageLayout) {
            console.log("\n=== 存储布局 ===");
            console.log("存储变量:");
            
            artifact.storageLayout.storage.forEach((item, index) => {
                console.log(`[${index}] ${item.label} (${item.type}):`);
                console.log(`    Slot: ${item.slot}`);
                console.log(`    Offset: ${item.offset}`);
                console.log(`    Type: ${item.type}`);
            });
            
            console.log("\n=== 类型定义 ===");
            Object.entries(artifact.storageLayout.types).forEach(([typeName, typeInfo]) => {
                console.log(`类型: ${typeName}`);
                console.log(`  标签: ${typeInfo.label}`);
                console.log(`  编码: ${typeInfo.encoding}`);
                console.log(`  大小: ${typeInfo.numberOfBytes} bytes`);
                console.log('---');
            });
        } else {
            console.log("未找到存储布局信息");
            console.log("可用的键:", Object.keys(artifact));
        }
    } else {
        console.log("Artifact 文件不存在:", artifactPath);
    }
}

analyzeStorage().catch(console.error);
