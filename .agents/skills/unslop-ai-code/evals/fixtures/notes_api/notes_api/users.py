"""User resource handlers.

Each handler takes a parsed `Request` and returns a `Response`. Validation
errors raise `ApiError`, which the router turns into a 4xx; everything else
is allowed to propagate so the top-level handler can log it and return 500.
"""
from .db import query_one, query_all, execute
from .errors import ApiError
from .response import Response
from .log import log


def get_user(req):
    log.info("get_user", user_id=req.path_params["id"])
    row = query_one("SELECT id, email, name FROM users WHERE id = ?", req.path_params["id"])
    if row is None:
        raise ApiError(404, "user not found")
    return Response.ok(row)


def list_users(req):
    log.info("list_users", limit=req.query.get("limit", 50))
    rows = query_all("SELECT id, email, name FROM users ORDER BY id LIMIT ?",
                     req.query.get("limit", 50))
    return Response.ok({"users": rows})


def create_user(req):
    email = req.body.get("email")
    if not email or "@" not in email:
        raise ApiError(400, "valid email is required")
    log.info("create_user", email=email)
    execute("INSERT INTO users (email, name) VALUES (?, ?)",
            email, req.body.get("name", ""))
    return Response.created({"email": email})
