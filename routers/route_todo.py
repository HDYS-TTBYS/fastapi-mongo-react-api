from typing import List
from fastapi import APIRouter, Request, Response, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi_csrf_protect.core import CsrfProtect
from schemas import SuccessMsg, Todo, TodoBody
from databse import db_create_todo, db_get_todos, db_get_single_todo, db_daleta_todo, db_update_todo
from starlette.status import HTTP_201_CREATED
from auth_utils import AuthJwtCsrf, set_cookie_new_token

router = APIRouter()
auth = AuthJwtCsrf()


@router.post("/api/todo", response_model=Todo)
async def create_todo(request: Request, response: Response, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    new_token = auth.veryfy_csrf_update_jwt(
        request, csrf_protect, request.headers)
    todo = jsonable_encoder(data)
    res = await db_create_todo(todo)
    response.status_code = HTTP_201_CREATED
    set_cookie_new_token(response, new_token)
    if res:
        return res
    raise HTTPException(
        status_code=404, detail="Create task failed"
    )


@router.get("/api/todo", response_model=List[Todo])
async def get_todos(request: Request):
    # auth.verify_jwt(request)
    res = await db_get_todos()
    return res


@router.get("/api/todo/{id}", response_model=Todo)
async def get_single_todo(request: Request, response: Response, id: str):
    new_token, _ = auth.verify_update_jwt(request)
    res = await db_get_single_todo(id)
    set_cookie_new_token(response, new_token)
    if res:
        return res
    raise HTTPException(
        status_code=404, detail=f"Task of ID:{id} doesen't exist")


@router.put("/api/todo/{id}", response_model=Todo)
async def update_todo(request: Request, response: Response, id: str, data: TodoBody, csrf_protect: CsrfProtect = Depends()):
    new_token = auth.veryfy_csrf_update_jwt(
        request, csrf_protect, request.headers)
    todo = jsonable_encoder(data)
    res = await db_update_todo(id, todo)
    set_cookie_new_token(response, new_token)
    if res:
        return res
    raise HTTPException(
        status_code=404, detail="Update task failed"
    )


@router.delete("/api/todo/{id}", response_model=SuccessMsg)
async def delete_todo(request: Request, response: Response, id: str, csrf_protect: CsrfProtect = Depends()):
    new_token = auth.veryfy_csrf_update_jwt(
        request, csrf_protect, request.headers)
    res = await db_daleta_todo(id)
    set_cookie_new_token(response, new_token)
    if res:
        return{"message": "Successfully deleted"}
    raise HTTPException(
        status_code=404, detail="Delete task failed"
    )
