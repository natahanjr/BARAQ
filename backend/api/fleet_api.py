"""Fleet Configuration API — agent profile management."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from backend.security import require_auth
from backend.fleet.config_profiles import ConfigProfileManager

router = APIRouter(prefix="/api/fleet", tags=["fleet"], dependencies=[Depends(require_auth)])

_manager = ConfigProfileManager()


class ProfileBody(BaseModel):
    name: str
    settings: dict = {}
    description: str = ""


class HostBody(BaseModel):
    host_id: str


@router.get("/profiles")
async def list_profiles():
    """List all fleet configuration profiles."""
    return {"items": [p.model_dump() for p in _manager.list_profiles()]}


@router.post("/profiles")
async def create_profile(body: ProfileBody):
    """Create a new fleet configuration profile."""
    if not body.name.strip():
        raise HTTPException(400, "Profile name cannot be empty")
    if len(body.name) > 64:
        raise HTTPException(400, "Profile name must be 64 characters or less")
    try:
        profile = _manager.create_profile(body.name.strip(), body.settings, body.description)
        return profile.model_dump()
    except Exception as e:
        raise HTTPException(500, f"Failed to create profile: {type(e).__name__}")


@router.post("/profiles/{profile_id}/assign")
async def assign_host(profile_id: str, body: HostBody):
    """Assign a host to a fleet configuration profile."""
    ok = _manager.assign_host(profile_id, body.host_id)
    if not ok:
        raise HTTPException(404, "Profile not found")
    return {"ok": True}


@router.post("/profiles/{profile_id}/unassign")
async def unassign_host(profile_id: str, body: HostBody):
    """Remove a host from a fleet configuration profile."""
    profile = _manager.get_profile(profile_id)
    if not profile:
        raise HTTPException(404, "Profile not found")
    if body.host_id in profile.hosts:
        profile.hosts.remove(body.host_id)
    return {"ok": True}


@router.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: str):
    """Delete a fleet configuration profile (cannot delete default)."""
    ok = _manager.delete_profile(profile_id)
    if not ok:
        raise HTTPException(404, "Profile not found or is default")
    return {"ok": True}
