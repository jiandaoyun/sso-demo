from datetime import datetime, timedelta
from math import isfinite
from threading import Lock
from urllib.parse import urlencode, urlsplit
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
# 演示用的 IdP 会话记录，进程重启后清空。
sessions = {}
sessions_lock = Lock()


def verify_request(encoded, expected_type):
    token = jwt.decode(
        encoded, Const.SECRET,
        # 简道云中未配置 Issuer URL 时，注释以下一行
        audience=Const.ISSUER,
        issuer='com.jiandaoyun',
        algorithms=['HS256', 'HS384', 'HS512'],
        leeway=3600
    )
    if token.get('type') != expected_type:
        raise InvalidTokenError('Wrong type.')
    return token


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
    with sessions_lock:
        sessions[session_id] = username.strip()
    return encoded


@app.route('/sso', methods=['GET'])
def handler():
    query = request.args.get('request', default='')
    try:
        verify_request(query, 'sso_req')
    except (InvalidTokenError, ValueError, OverflowError):
        return abort(403)

    params = {'response': get_token_from_username(Const.USERNAME)}
    state = request.args.get('state')
    if state:
        params['state'] = state
    return redirect(f'{Const.ACS}?{urlencode(params)}')


@app.route('/logout', methods=['GET'])
def logout():
    @after_this_request
    def disable_cache(response):
        response.headers['Cache-Control'] = 'no-store'
        return response

    try:
        queries = request.args.getlist('request')
        if len(queries) != 1:
            raise InvalidTokenError('Expected one logout request.')
        token = verify_request(queries[0], 'slo_req')
        expiration = token.get('exp')
        if type(expiration) not in (int, float) or not isfinite(expiration):
            raise InvalidTokenError('Missing expiration.')

        session_id = token.get('index')
        if isinstance(session_id, str):
            with sessions_lock:
                session_username = sessions.get(session_id)
                if session_username is not None and session_username != token.get('nameId'):
                    raise InvalidTokenError('Session member does not match.')
                sessions.pop(session_id, None)
    except (InvalidTokenError, ValueError, OverflowError):
        return '无效的单点登出请求。', 400

    redirect_uris = request.args.getlist('redirect_uri')
    if not redirect_uris:
        return redirect(Const.LOGOUT_RETURN_URL, code=303)

    try:
        if len(redirect_uris) != 1:
            raise ValueError('Expected one return URL.')
        target = urlsplit(redirect_uris[0])
        if (target.scheme not in ('http', 'https') or not target.hostname
                or target.username is not None or target.password is not None
                or any(character.isspace() for character in target.netloc)
                or '\\' in target.netloc):
            raise ValueError('Invalid return URL.')
        # urlsplit 延迟校验端口，读取时才会拒绝无效值。
        _ = target.port
        return redirect(target.geturl(), code=303)
    except ValueError:
        return '无效的登出返回地址。', 400


if __name__ == '__main__':
    app.run(port=8080)
