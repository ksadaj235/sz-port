/**
 * 深圳口岸通 CCTV 监控图片客户端
 *
 * 获取各口岸的实时监控摄像头截图地址
 */

const crypto = require('crypto');
const axios = require('axios');
const { sm2, sm3, sm4 } = require('sm-crypto');
const fs = require('fs');

// ==================== 配置 ====================

const CONFIG = {
    baseUrl: 'https://i.ka.sz.gov.cn',
    aepAppKey: 'ysxt',
    aepSecret: '791685057029865473',
    sm2PublicKey: '04957D171CF9866FAD456FC18578E2F31D07244EC9828E17B990BB7A6F1EF520255A776ADAFC64FD8B9ECA59F4159402DCE0AB6E3AB1D74DCD60B363280F1443E8'
};

// ==================== 工具函数 ====================

/**
 * 生成 UUID
 * @returns {string} UUID 字符串
 */
function generateUUID() {
    const hex = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
    return `${hex()}${hex()}-${hex()}-${hex()}-${hex()}-${hex()}${hex()}${hex()}`;
}

/**
 * 生成随机十六进制字符串
 * @param {number} length - 字符串长度
 * @returns {string} 随机十六进制字符串
 */
function randomHex(length) {
    let result = '';
    while (result.length < length) {
        const rand = (Math.random() * Math.pow(10, 10)).toString(16);
        result += rand.substring(0, rand.indexOf('.'));
    }
    return result.slice(0, length).padStart(length, '0');
}

// ==================== 签名函数 ====================

/**
 * 生成 AEP 签名 (SHA256)
 */
function generateAepSignature(timestamp, appKey, nonce, secret) {
    const signStr = timestamp + appKey + nonce + secret + timestamp;
    return crypto.createHash('sha256').update(signStr).digest('hex').toUpperCase();
}

/**
 * 生成 AEP 请求头
 */
function generateAepHeaders() {
    const timestamp = (Date.now() / 1000).toFixed(3);
    const nonce = generateUUID();
    const signature = generateAepSignature(timestamp, CONFIG.aepAppKey, nonce, CONFIG.aepSecret);

    return {
        'x-aep-appkey': CONFIG.aepAppKey,
        'x-aep-timestamp': timestamp,
        'x-aep-nonce': nonce,
        'x-aep-signature': signature
    };
}

/**
 * 生成 KA 签名 (SM3)
 */
function generateKaSignature(nonce, timestamp) {
    const signStr = timestamp + nonce + timestamp;
    return sm3(signStr).toUpperCase();
}

/**
 * SM2 加密密钥
 */
function encryptKeyWithSm2(key, iv) {
    const plaintext = key + '&' + iv;
    const ciphertext = sm2.doEncrypt(plaintext, CONFIG.sm2PublicKey, 1);
    return '04' + ciphertext.toUpperCase();
}

/**
 * 生成 KA 请求头和加密密钥
 */
function generateKaHeaders() {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateUUID();
    const signature = generateKaSignature(nonce, timestamp);

    const key = randomHex(32);
    const iv = randomHex(32);
    const encryptedKey = encryptKeyWithSm2(key, iv);

    return {
        headers: {
            'x-ka-timestamp': timestamp.toString(),
            'x-ka-nonce': nonce,
            'x-ka-signature': signature,
            'x-ka-t': encryptedKey
        },
        key,
        iv
    };
}

// ==================== SM4 加解密 ====================

/**
 * SM4-CBC 加密
 */
function sm4Encrypt(data, key, iv) {
    const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
    return sm4.encrypt(plaintext, key, {
        mode: 'cbc',
        padding: 'pkcs#5',
        iv: iv
    });
}

/**
 * SM4-CBC 解密
 */
function sm4Decrypt(ciphertext, key, iv) {
    return sm4.decrypt(ciphertext, key, {
        mode: 'cbc',
        padding: 'pkcs#5',
        iv: iv
    });
}

// ==================== API 请求 ====================

/**
 * 发送加密请求
 * @param {string} path - API 路径
 * @param {object} data - 请求数据
 * @returns {Promise<object>} 解密后的响应数据
 */
async function request(path, data = {}) {
    const aepHeaders = generateAepHeaders();
    const { headers: kaHeaders, key, iv } = generateKaHeaders();
    const encryptedData = sm4Encrypt(data, key, iv);

    const headers = {
        ...aepHeaders,
        ...kaHeaders,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*',
        'Origin': CONFIG.baseUrl,
        'Referer': CONFIG.baseUrl
    };

    const response = await axios({
        method: 'POST',
        url: `${CONFIG.baseUrl}/local/ika-api${path}`,
        headers,
        data: encryptedData,
        timeout: 30000
    });

    if (typeof response.data === 'string' && response.data.length > 0) {
        const decryptedData = sm4Decrypt(response.data, key, iv);
        return JSON.parse(decryptedData);
    }

    return response.data;
}

// ==================== CCTV 接口 ====================

/**
 * 获取口岸列表
 * @returns {Promise<Array>} 口岸列表
 */
async function getPortList() {
    const result = await request('/open/port', {
        pageNum: 1,
        pageSize: 20
    });
    return result.rows || [];
}

/**
 * 获取单个口岸详情（包含摄像头信息）
 * @param {string} portId - 口岸ID
 * @returns {Promise<object>} 口岸详情
 */
async function getPortDetail(portId) {
    const result = await request('/open/port', {
        id: portId
    });

    // 返回的是数组，取第一个
    if (result.rows && result.rows.length > 0) {
        return result.rows[0];
    }
    return null;
}

/**
 * 获取监控摄像头图片
 * @param {string} portId - 口岸ID
 * @param {string} cameraCode - 摄像头编码
 * @param {string} cameraType - 摄像头类型 (1=出境, 2=入境)
 * @returns {Promise<object>} 包含图片URL的响应
 */
async function getMonitorPic(portId, cameraCode, cameraType) {
    return request('/open/port/getPortMonitorPic', {
        portId: portId,
        code: cameraCode,
        type: cameraType
    });
}

/**
 * 获取口岸所有摄像头的图片地址
 * @param {object} port - 口岸对象 (从 getPortList 获取)
 * @returns {Promise<object>} 摄像头图片列表
 */
async function getPortCCTVImages(port) {
    if (!port) {
        throw new Error('口岸对象不能为空');
    }

    const cameras = [];

    // 解析摄像头列表
    let entryAndExitList = [];
    if (typeof port.entryAndExitJson === 'string') {
        try {
            entryAndExitList = JSON.parse(port.entryAndExitJson);
        } catch (e) {
            entryAndExitList = [];
        }
    } else if (Array.isArray(port.entryAndExitJson)) {
        entryAndExitList = port.entryAndExitJson;
    }

    // 获取每个摄像头的图片
    for (const camera of entryAndExitList) {
        try {
            const picResult = await getMonitorPic(port.id, camera.code, camera.type);
            cameras.push({
                name: camera.name,
                code: camera.code,
                type: camera.type === '1' ? '出境' : '入境',
                imageUrl: picResult.data?.picUrl || picResult.videoPic || null
            });
        } catch (e) {
            cameras.push({
                name: camera.name,
                code: camera.code,
                type: camera.type === '1' ? '出境' : '入境',
                imageUrl: null,
                error: e.message
            });
        }
    }

    return {
        portId: port.id,
        portName: port.portName,
        smoothness: port.smoothness,
        exit: port.exit,
        entry: port.entry,
        exitClearanceTime: port.exitClearanceTime,
        entryClearanceTime: port.entryClearanceTime,
        cameras: cameras
    };
}

/**
 * 获取所有口岸的 CCTV 图片地址
 * @returns {Promise<Array>} 所有口岸的摄像头信息
 */
async function getAllPortsCCTV() {
    const ports = await getPortList();
    const results = [];

    for (const port of ports) {
        console.log(`正在获取: ${port.portName}...`);
        try {
            const cctvData = await getPortCCTVImages(port);
            results.push(cctvData);
        } catch (e) {
            results.push({
                portId: port.id,
                portName: port.portName,
                error: e.message,
                cameras: []
            });
        }
    }

    return results;
}

// ==================== 主函数 ====================

async function main() {
    console.log('========================================');
    console.log('  深圳口岸通 CCTV 监控图片获取工具');
    console.log('========================================\n');

    try {
        // 获取所有口岸的 CCTV 数据
        const allCCTV = await getAllPortsCCTV();

        // 保存到文件
        const outputPath = require('path').join(__dirname, 'cctv-data.json');
        fs.writeFileSync(outputPath, JSON.stringify(allCCTV, null, 2), 'utf8');
        console.log('\n数据已保存到 cctv-data.json\n');

        // 打印摘要
        console.log('========================================');
        console.log('  CCTV 摄像头摘要');
        console.log('========================================\n');

        for (const port of allCCTV) {
            console.log(`【${port.portName}】`);
            if (port.smoothness) {
                console.log(`  状态: ${port.smoothness}`);
            }
            if (port.exitClearanceTime) {
                console.log(`  出境: ${port.exit} (${port.exitClearanceTime})`);
            }
            if (port.entryClearanceTime) {
                console.log(`  入境: ${port.entry} (${port.entryClearanceTime})`);
            }

            if (port.cameras && port.cameras.length > 0) {
                console.log(`  摄像头数量: ${port.cameras.length}`);
                for (const cam of port.cameras) {
                    console.log(`    - [${cam.type}] ${cam.name}`);
                    if (cam.imageUrl) {
                        console.log(`      ${cam.imageUrl}`);
                    }
                }
            } else {
                console.log('  摄像头: 无');
            }
            console.log('');
        }

    } catch (error) {
        console.error('获取失败:', error.message);
    }
}

// 导出模块
module.exports = {
    getPortList,
    getPortDetail,
    getMonitorPic,
    getPortCCTVImages,
    getAllPortsCCTV
};

// 直接运行
if (require.main === module) {
    main();
}
