from datetime import datetime, timedelta
from flask import Flask, abort, redirect, request
import jwt

from jwt import InvalidTokenError


class Const:
    # ACS：简道云中生成的认证返回地址
    ACS = 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs'
    # SECRET：认证密钥
    SECRET = 'fHVI4PztDMHShqZzkLbuS8hn'
    # ISSUER：Issuer URL
    ISSUER = 'com.angelmsger'
    # USERNAME：需要进行单点登录的成员ID
    USERNAME = 'angelmsger'


app = Flask(__name__)


def valid_token(query):
    try:
        token = jwt.decode(
            query, Const.SECRET,
            # 简道云中未配置 Issuer URL 时，注释以下一行
            audience=Const.ISSUER,
            issuer='com.jiandaoyun',
            # 与简道云中配置的 认证加密算法 保持一致
            algorithms=['HS256']
        )
        return token.get('type') == 'sso_req'
    except InvalidTokenError as e:
        return False


def get_token_from_username(username):
    now = datetime.utcnow()
    return jwt.encode({
        "type": "sso_res",
        'username': username,
        # 简道云中未配置 Issuer URL 时，注释以下一行
        'iss': Const.ISSUER,
        "aud": "com.jiandaoyun",
        "nbf": now,
        "iat": now,
        "exp": now + timedelta(seconds=60),
    }, 
    # algorithm 与简道云中配置的 认证加密算法 保持一致
    Const.SECRET, algorithm='HS256')


@app.route('/sso', methods=['GET'])
def handler():
    query = request.args.get('request', default='')
    state = request.args.get('state')
    if valid_token(query):
        token = get_token_from_username(Const.USERNAME)
        state_query = "" if not state else f"&state={state}"
        return redirect(f'{Const.ACS}?response={token}{state_query}')
    else:
        return abort(403)


if __name__ == '__main__':
    app.run(port=8080)
