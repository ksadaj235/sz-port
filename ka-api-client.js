/**
 * 深圳口岸通 API 加密客户端
 *
 * 加密机制：
 * - AEP 层签名: SHA256(timestamp + appkey + nonce + secret + timestamp)
 * - KA 层签名: SM3(timestamp + nonce + timestamp)
 * - 密钥传输: SM2 公钥加密 (key&iv)
 * - 数据加密: SM4-CBC 模式
 */

const crypto = require('crypto');
const axios = require('axios');
const { sm2, sm3, sm4 } = require('sm-crypto');

// ==================== 配置 ====================

const CONFIG = {
    baseUrl: 'https://i.ka.sz.gov.cn',
    aepAppKey: 'ysxt',
    aepSecret: '791685057029865473', // AEP 密钥 (从 version.json 解密获取)
    // SM2 公钥 (从前端代码提取)
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

// ==================== AEP 层签名 ====================

/**
 * 生成 AEP 签名 (SHA256)
 * @param {string} timestamp - 时间戳
 * @param {string} appKey - 应用标识
 * @param {string} nonce - 随机数
 * @param {string} secret - 密钥
 * @returns {string} 签名字符串
 */
function generateAepSignature(timestamp, appKey, nonce, secret) {
    const signStr = timestamp + appKey + nonce + secret + timestamp;
    return crypto.createHash('sha256').update(signStr).digest('hex').toUpperCase();
}

/**
 * 生成 AEP 请求头
 * @returns {object} AEP 请求头对象
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

// ==================== KA 层签名 ====================

/**
 * 生成 KA 签名 (SM3)
 * @param {string} nonce - 随机数
 * @param {number} timestamp - 时间戳 (秒)
 * @returns {string} SM3 签名
 */
function generateKaSignature(nonce, timestamp) {
    const signStr = timestamp + nonce + timestamp;
    return sm3(signStr).toUpperCase();
}

/**
 * SM2 加密密钥
 * @param {string} key - SM4 密钥
 * @param {string} iv - SM4 初始向量
 * @returns {string} SM2 加密后的密文
 */
function encryptKeyWithSm2(key, iv) {
    const plaintext = key + '&' + iv;
    const ciphertext = sm2.doEncrypt(plaintext, CONFIG.sm2PublicKey, 1);
    return '04' + ciphertext.toUpperCase();
}

/**
 * 生成 KA 请求头和加密密钥
 * @returns {object} { headers, key, iv }
 */
function generateKaHeaders() {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateUUID();
    const signature = generateKaSignature(nonce, timestamp);

    // 生成随机 SM4 密钥和 IV (各16字节 = 32个十六进制字符)
    const key = randomHex(32);
    const iv = randomHex(32);

    // SM2 加密密钥
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
 * @param {object|string} data - 待加密数据
 * @param {string} key - 密钥 (十六进制)
 * @param {string} iv - 初始向量 (十六进制)
 * @returns {string} 加密后的十六进制字符串
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
 * @param {string} ciphertext - 密文 (十六进制)
 * @param {string} key - 密钥 (十六进制)
 * @param {string} iv - 初始向量 (十六进制)
 * @returns {string} 解密后的明文
 */
function sm4Decrypt(ciphertext, key, iv) {
    return sm4.decrypt(ciphertext, key, {
        mode: 'cbc',
        padding: 'pkcs#5',
        iv: iv
    });
}

// ==================== API 请求封装 ====================

/**
 * 发送加密请求
 * @param {string} path - API 路径
 * @param {object} data - 请求数据
 * @param {string} method - 请求方法
 * @returns {Promise<object>} 解密后的响应数据
 */
async function request(path, data = {}, method = 'POST') {
    // 生成 AEP 层请求头
    const aepHeaders = generateAepHeaders();

    // 生成 KA 层请求头和加密密钥
    const { headers: kaHeaders, key, iv } = generateKaHeaders();

    // SM4 加密请求体
    const encryptedData = sm4Encrypt(data, key, iv);

    // 合并请求头
    const headers = {
        ...aepHeaders,
        ...kaHeaders,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*',
        'Origin': CONFIG.baseUrl,
        'Referer': CONFIG.baseUrl
    };

    console.log('\n========== 请求信息 ==========');
    console.log('URL:', `${CONFIG.baseUrl}/local/ika-api${path}`);
    console.log('Method:', method);
    console.log('原始数据:', JSON.stringify(data, null, 2));
    console.log('加密后数据:', encryptedData);
    console.log('SM4 Key:', key);
    console.log('SM4 IV:', iv);
    console.log('请求头:', JSON.stringify(headers, null, 2));

    try {
        const response = await axios({
            method,
            url: `${CONFIG.baseUrl}/local/ika-api${path}`,
            headers,
            data: encryptedData,
            timeout: 30000
        });

        console.log('\n========== 响应信息 ==========');
        console.log('状态码:', response.status);
        console.log('加密响应:', typeof response.data === 'string'
            ? response.data.substring(0, 200) + '...'
            : response.data);

        // 解密响应
        if (typeof response.data === 'string' && response.data.length > 0) {
            const decryptedData = sm4Decrypt(response.data, key, iv);
            console.log('解密后响应:', decryptedData);

            try {
                return JSON.parse(decryptedData);
            } catch {
                return decryptedData;
            }
        }

        return response.data;
    } catch (error) {
        console.error('\n========== 请求错误 ==========');
        console.error('错误信息:', error.message);
        if (error.response) {
            console.error('响应状态:', error.response.status);
            console.error('响应数据:', error.response.data);
        }
        throw error;
    }
}

// ==================== API 接口 ====================

/**
 * 获取口岸数据
 * @returns {Promise<object>} 口岸列表数据
 */
async function getPortList() {
    return request('/open/port', {
        pageNum: 1,
        pageSize: 20
    });
}

/**
 * 下载文件
 * @param {string} fileId - 文件ID
 * @returns {Promise<Buffer>} 文件数据
 */
async function downloadFile(fileId) {
    const aepHeaders = generateAepHeaders();
    const { headers: kaHeaders, key, iv } = generateKaHeaders();

    const headers = {
        ...aepHeaders,
        ...kaHeaders,
        'Content-Type': 'application/json',
        'x-ka-fileid': fileId
    };

    const encryptedData = sm4Encrypt({}, key, iv);

    const response = await axios({
        method: 'POST',
        url: `${CONFIG.baseUrl}/local/ika-api/file/download`,
        headers,
        data: encryptedData,
        responseType: 'arraybuffer'
    });

    return response.data;
}

// ==================== 主函数 ====================

async function main() {
    console.log('========================================');
    console.log('  深圳口岸通 API 加密客户端');
    console.log('========================================');

    try {
        console.log('\n正在请求口岸数据...');
        const result = await getPortList();

        if (result && result.rows) {
            console.log(`\n成功获取 ${result.rows.length} 个口岸数据`);
            result.rows.forEach((port, index) => {
                console.log(`${index + 1}. ${port.portName} - ${port.smoothness || '未知'}`);
            });

            // 清理敏感数据：将所有 appId 置为空字符串
            const cleanData = JSON.parse(JSON.stringify(result));
            const clearAppId = (obj) => {
                if (typeof obj === 'object' && obj !== null) {
                    if (Array.isArray(obj)) {
                        obj.forEach(item => clearAppId(item));
                    } else {
                        if ('appId' in obj) {
                            obj.appId = '';
                        }
                        Object.values(obj).forEach(value => clearAppId(value));
                    }
                }
            };
            clearAppId(cleanData);

            // 保存到文件
            const fs = require('fs');
            const outputPath = require('path').join(__dirname, 'port-data.json');
            fs.writeFileSync(outputPath, JSON.stringify(cleanData, null, 2), 'utf8');
            console.log('\n数据已保存到 port-data.json\n');
        }
    } catch (error) {
        console.error('请求失败:', error.message);
    }
}

// 导出模块
module.exports = {
    request,
    getPortList,
    downloadFile,
    generateAepHeaders,
    generateKaHeaders,
    sm4Encrypt,
    sm4Decrypt
};

// 直接运行
if (require.main === module) {
    main();
}
