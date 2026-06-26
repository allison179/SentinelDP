from fastapi import FastAPI, Depends
from libs.core.auth import role_required

app = FastAPI(title="SentinelDP API")

@app.get("/compliance/reports")
async def get_reports(user = Depends(role_required("Auditor"))):
    return {"message": "Access granted to sensitive compliance data"}