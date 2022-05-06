from datetime import datetime, timedelta
from flask import Flask, abort, redirect, request
import jwt

from jwt import InvalidTokenError


class Const:
    ACS = 'https://www.jiandaoyun.com/sso/custom/5b4bf4398aa34804a574bfcb/acs'
    SECRET = 'fHVI4PztDMHShqZzkLbuS8hn'
    ISSUER = 'com.angelmsger'
    USERNAME = 'angelmsger'


app = Flask(__name__)


def valid_token(query):
    try:
        token = jwt.decode(
            query, Const.SECRET,
            audience=Const.ISSUER,
            issuer='com.jiandaoyun',
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
        'iss': Const.ISSUER,
        "aud": "com.jiandaoyun",
        "nbf": now,
        "iat": now,
        "exp": now + timedelta(seconds=60),
    }, Const.SECRET, algorithm='HS256')


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
