from datetime import datetime, timedelta
from urllib.parse import urlsplit
from uuid import uuid4

from flask import Flask, abort, after_this_request, redirect, request
import jwt
from jwt import InvalidTokenError


class Const:
    # ACS：简道云中生成的认证返回地址
    ACS = 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs'
    # 未传入登出回程地址时，跳回租户登录页。
    LOGOUT_RETURN_URL = 'https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/signin'
    # SECRET：认证密钥
    SECRET = 'fHVI4PztDMHShqZzkLbuS8hn'
    # ISSUER：Issuer URL
    ISSUER = 'com.angelmsger'
    # 与简道云中配置的认证算法保持一致。
    ALGORITHM = 'HS256'
    # USERNAME：需要进行单点登录的成员ID
    USERNAME = 'angelmsger'


app = Flask(__name__)
# 演示用的 IdP 会话记录。
sessions = {}


def valid_token(query, expected_type):
    try:
        token = jwt.decode(
            query, Const.SECRET,
            # 简道云中未配置 Issuer URL 时，注释以下一行
            audience=Const.ISSUER,
            issuer='com.jiandaoyun',
            # 与简道云中配置的 认证加密算法 保持一致
            algorithms=['HS256']
        )
        return token if token.get('type') == expected_type else None
    except (InvalidTokenError, ValueError, OverflowError):
        return None


def get_token_from_username(username):
    now = datetime.utcnow()
    session_id = str(uuid4())
    encoded = jwt.encode({
        "type": "sso_res",
        'username': username,
        # 简道云将 jti 记录为 SSO 会话索引，用于发起单点登出。
        'jti': session_id,
        # 简道云中未配置 Issuer URL 时，注释以下一行
        'iss': Const.ISSUER,
        "aud": "com.jiandaoyun",
        "nbf": now,
        "iat": now,
        "exp": now + timedelta(seconds=60),
    }, Const.SECRET, algorithm=Const.ALGORITHM)
    # 签名成功后记录 jti 对应的成员。
    sessions[session_id] = username.strip()
    return encoded


@app.route('/sso', methods=['GET'])
def handler():
    query = request.args.get('request', default='')
    state = request.args.get('state')
    if valid_token(query, 'sso_req'):
        token = get_token_from_username(Const.USERNAME)
        state_query = "" if not state else f"&state={state}"
        return redirect(f'{Const.ACS}?response={token}{state_query}')
    else:
        return abort(403)


@app.route('/logout', methods=['GET'])
def logout():
    @after_this_request
    def disable_cache(response):
        response.headers['Cache-Control'] = 'no-store'
        return response

    queries = request.args.getlist('request')
    token = valid_token(queries[0], 'slo_req') if len(queries) == 1 else None
    if token is None:
        return '无效的单点登出请求。', 400

    # 清除会话。
    session_id = token.get('index')
    if isinstance(session_id, str):
        session_username = sessions.get(session_id)
        if session_username is not None and session_username != token.get('nameId'):
            return '无效的单点登出请求。', 400
        sessions.pop(session_id, None)

    redirect_uris = request.args.getlist('redirect_uri')
    if not redirect_uris:
        return redirect(Const.LOGOUT_RETURN_URL, code=303)

    # 校验登出地址
    try:
        if len(redirect_uris) != 1:
            raise ValueError('Expected one return URL.')
        target = urlsplit(redirect_uris[0])
        if (target.scheme not in ('http', 'https') or not target.hostname
                or target.username is not None or target.password is not None
                or any(character.isspace() for character in target.netloc)
                or '\\' in target.netloc):
            raise ValueError('Invalid return URL.')
        _ = target.port
        return redirect(target.geturl(), code=303)
    except ValueError:
        return '无效的登出返回地址。', 400


if __name__ == '__main__':
    app.run(port=8080)
