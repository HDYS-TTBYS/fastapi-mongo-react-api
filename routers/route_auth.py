from fastapi import APIRouter, Request, Response, Depends
from fastapi.encoders import jsonable_encoder
from fastapi_csrf_protect.core import CsrfProtect
from schemas import Csrf, UserBody, SuccessMsg, UserInfo
from databse import db_signup, db_login
from auth_utils import AuthJwtCsrf
from auth_utils import set_cookie_new_token
from env import ACCESS_TOKEN_KEY

router = APIRouter()
auth = AuthJwtCsrf()


@router.get("/api/csrftoken", response_model=Csrf)
async def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.generate_csrf()
    return {"csrf_token": csrf_token}


@router.post("/api/register", response_model=UserInfo)
async def signup(request: Request, json_user: UserBody, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(json_user)
    new_user = await db_signup(user)
    return new_user


@router.post("/api/login", response_model=SuccessMsg)
async def login(request: Request, response: Response, json_user: UserBody, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(json_user)
    new_token = await db_login(user)
    set_cookie_new_token(response, new_token)
    return {"message": "Successfully logined-in"}


@router.post("/api/logout", response_model=SuccessMsg)
async def logout(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    response.set_cookie(key=ACCESS_TOKEN_KEY, value="",
                        httponly=True, samesite="none", secure=True)
    return {"message": "Successfully logged-out"}


@router.get("/api/user", response_model=UserInfo)
async def get_user_refresh_jwt(request: Request, response: Response):
    new_token, subject = auth.verify_update_jwt(request)
    set_cookie_new_token(response, new_token)
    return {"email": subject}
