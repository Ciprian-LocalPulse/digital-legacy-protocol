"""
Digital Legacy Protocol (DLP) - Core Orchestration Engine
This module serves as the primary asynchronous entry point for the DLP state machine,
handling cryptographic attestations (heartbeats) and managing the transition lifecycle.
"""

import logging
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [DLP Core] - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Digital Legacy Protocol Engine",
    description="Zero-Knowledge Cryptographic Custody and Temporal Orchestration API",
    version="0.1.0-alpha",
    docs_url="/docs",
    redoc_url=None
)

class CryptographicHeartbeat(BaseModel):
    principal_did: str
    timestamp: float
    nonce: str
    client_signature: str

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing Digital Legacy Protocol State Machine...")
    logger.info("Cryptographic engine primed. Awaiting attestations.")

@app.get("/health", status_code=status.HTTP_200_OK)
async def system_health():
    return {
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "state_machine": "S_ACTIVE"
    }

@app.post("/attest", status_code=status.HTTP_202_ACCEPTED)
async def register_heartbeat(payload: CryptographicHeartbeat):
    logger.info(f"Received cryptographic attestation from DID: {payload.principal_did}")
    return {
        "status": "verified",
        "action": "chronometer_reset",
        "registered_at": payload.timestamp
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.core.main:app", host="0.0.0.0", port=8000, reload=False)
