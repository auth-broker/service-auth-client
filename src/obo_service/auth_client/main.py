from fastapi import FastAPI

from obo_service.auth_client.routes.callback import router as callback_router
from obo_service.auth_client.routes.login import router as login_router

app = FastAPI()
app.include_router(login_router)
app.include_router(callback_router)
