from datetime import datetime, timedelta
from django.http import HttpRequest
from jose import jwt
from ninja.security import HttpBearer


def generate_token(username: str, expire_minutes: int=1):
    '''
    生成token
    :param username: 用户名
    :param expire_minutes: 过期时间
    :return 编码后jwt字符串
    '''
    expire = datetime.now() + timedelta(minutes=expire_minutes)
    to_encode = {'sub': username, 'exp': expire}
    encoded_jwt = jwt.encode(to_encode, 'ninja_vue', algorithm='HS256')

    return encoded_jwt


class TokenAuth(HttpBearer):
    def authenticate(self, request: HttpRequest, token: str) -> jwt.Any | None:
        payload = jwt.decode(token, 'ninja_vue', algorithm='HS256')
        username: str = payload.get('sub')

