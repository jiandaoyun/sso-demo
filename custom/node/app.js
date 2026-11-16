const { randomUUID } = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');

const config = {
    // acs：简道云中生成的认证返回地址
    acs: 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs',
    // 未传入登出回程地址时，跳回租户登录页。
    logoutReturnUrl: 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/signin',
    // secret：认证密钥
    secret: 'fHVI4PztDMHShqZzkLbuS8hn',
    // issuer：Issuer URL
    issuer: 'com.angelmsger',
    // 与简道云中配置的认证算法保持一致
    algorithm: 'HS256',
    // username：需要进行单点登录的成员ID
    username: 'R-3VjoSB7G'
};

const app = express();
// 演示用的 IdP 会话记录，进程重启后清空。
const sessions = new Map();

function verifyRequest(request, expectedType) {
    const decoded = jwt.verify(request, config.secret, {
        algorithms: ['HS256', 'HS384', 'HS512'],
        // 简道云中未配置 Issuer URL 时，注释以下一行
        audience: config.issuer,
        issuer: 'com.jiandaoyun',
        clockTolerance: 3600
    });
    if (decoded.type !== expectedType) {
        throw new Error('Wrong Type.');
    }
    return decoded;
}

function getResponse(request, callback) {
    // Should be Asynchronous in Prod
    try {
        verifyRequest(request, 'sso_req');
        const sessionId = randomUUID();
        const encoded = jwt.sign({
            type: 'sso_res',
            username: config.username
        }, config.secret, {
            algorithm: config.algorithm,
            expiresIn: 60000,
            // 简道云将 jti 记录为 SSO 会话索引，用于发起单点登出。
            jwtid: sessionId,
            audience: 'com.jiandaoyun',
            // 简道云中未配置 Issuer URL 时，注释以下一行
            issuer: config.issuer
        });
        sessions.set(sessionId, config.username.trim());
        callback(undefined, encoded);
    } catch (e) {
        callback(e);
    }
}

app.get('/sso', (req, res) => {
    const { query } = req;
    const { request, state } = query;
    getResponse(request, (e, response) => {
        if (e) {
            console.error(e);
            res.status(400);
            res.send('Bad Request.');
        } else {
            const responseQuery = new URLSearchParams({
                response,
                state
            }).toString();
            res.redirect(`${ config.acs }?${ responseQuery }`);
        }
    });
});

app.get('/logout', (req, res) => {
    const { request, redirect_uri: redirectUri } = req.query;
    res.set('Cache-Control', 'no-store');
    try {
        const decoded = verifyRequest(request, 'slo_req');
        if (!Number.isFinite(decoded.exp)) {
            throw new Error('Missing expiration.');
        }
        const { index, nameId } = decoded;
        const sessionUsername = sessions.get(index);
        if (sessionUsername !== undefined && sessionUsername !== nameId) {
            throw new Error('Session member does not match.');
        }
        // 已清理或进程重启过时，delete 不会影响其他会话。
        sessions.delete(index);
    } catch {
        return res.status(400).send('无效的单点登出请求。');
    }

    if (redirectUri === undefined) {
        return res.redirect(303, config.logoutReturnUrl);
    }

    try {
        if (typeof redirectUri !== 'string') {
            throw new Error('Invalid redirect URI.');
        }
        const target = new URL(redirectUri);
        if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
            throw new Error('Invalid redirect URI.');
        }
        return res.redirect(303, target.href);
    } catch {
        return res.status(400).send('无效的登出返回地址。');
    }
});

app.listen(8080);
