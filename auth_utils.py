from fastapi_csrf_protect.core import CsrfProtect
import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response
from env import JWT_KEY, ACCESS_TOKEN_KEY


class AuthJwtCsrf():
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    def generate_hashed_pw(self, password: str) -> str:
        return self.pwd_ctx.hash(password)

    def verify_pw(self, plain_pw: str, hashed_pw: str) -> bool:
        return self.pwd_ctx.verify(plain_pw, hashed_pw)

    def encode_jwt(self, email: str) -> str:
        payload = {
            "exp": datetime.utcnow()+timedelta(days=0, minutes=5),
            "iat": datetime.utcnow(),
            "sub": email
        }
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm="HS256"
        )

    def decode_jwt(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="The JWT has expired")
        except jwt.InvalidAudienceError:
            raise HTTPException(status_code=401, detail="JWT is not valid")

    def verify_jwt(self, request: Request) -> str:
        token = request.cookies.get(ACCESS_TOKEN_KEY)
        if not token:
            raise HTTPException(
                status_code=401, detail="No JWT exist: may not set yet or detail")
        _, _, value = token.partition(" ")
        subject = self.decode_jwt(value)
        return subject

    def verify_update_jwt(self, request: Request) -> tuple[str, str]:
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token, subject

    def veryfy_csrf_update_jwt(self, request: Request, csrf_protect: CsrfProtect, headers: Headers) -> str:
        csrf_token = csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token


def set_cookie_new_token(response: Response, new_token: str):
    response.set_cookie(
        key=ACCESS_TOKEN_KEY, value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
