const express = require('express');
const jwt = require('jsonwebtoken');

const config = {
    // acs：简道云中生成的认证返回地址
    acs: 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs',
    // secret：认证密钥
    secret: 'fHVI4PztDMHShqZzkLbuS8hn',
    // issuer：Issuer URL
    issuer: 'com.angelmsger',
    // username：需要进行单点登录的成员ID
    username: 'angelmsger'
};

const app = express();

function getResponse(request, callback) {
    // Should be Asynchronous in Prod
    try {
        const decoded = jwt.verify(request, config.secret, {
            algorithms: ['HS256', 'HS384', 'HS512'],
            // 简道云中未配置 Issuer URL 时，注释以下一行
            audience: config.issuer,
            issuer: 'com.jiandaoyun',
            clockTolerance: 3600
        });
        if (decoded.type !== 'sso_req') {
            throw new Error('Wrong Type.');
        }
        const encoded = jwt.sign({
            type: 'sso_res',
            username: config.username
        }, config.secret, {
            // 与简道云中配置的 认证加密算法 保持一致
            algorithm: 'HS256',
            expiresIn: 60000,
            audience: 'com.jiandaoyun',
            // 简道云中未配置 Issuer URL 时，注释以下一行
            issuer: config.issuer
        });
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

app.listen(8080);
