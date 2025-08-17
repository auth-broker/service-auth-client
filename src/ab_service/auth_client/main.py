from fastapi import FastAPI

from ab_service.auth_client.routes.callback import router as callback_router
from ab_service.auth_client.routes.login import router as login_router

app = FastAPI()
app.include_router(login_router)
app.include_router(callback_router)
