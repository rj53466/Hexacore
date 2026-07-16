"""Request/response models for the API."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ScopeIn(BaseModel):
    allow_domains: list[str] = Field(default_factory=list)
    allow_cidrs: list[str] = Field(default_factory=list)
    deny_list: list[str] = Field(default_factory=list)
    max_action_class: str = "active-scan"


class AuthorizationIn(BaseModel):
    authorizer_name: str
    authorizer_email: str
    method: str = "click-sign"
    document_ref: Optional[str] = None
    verified_by: Optional[str] = None


class SeedsIn(BaseModel):
    domains: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


class EngagementCreate(BaseModel):
    name: str
    client: str
    scope: ScopeIn
    authorization: Optional[AuthorizationIn] = None
    autonomy_profile: str = "supervised"
    model_profile: str = "local"
    seeds: Optional[SeedsIn] = None

    def to_mapping(self) -> dict:
        data: dict = {
            "name": self.name,
            "client": self.client,
            "scope": self.scope.model_dump(),
            "autonomy_profile": self.autonomy_profile,
            "model_profile": self.model_profile,
        }
        if self.authorization is not None:
            data["authorization"] = self.authorization.model_dump()
        if self.seeds is not None:
            data["seeds"] = self.seeds.model_dump()
        return data


class ApprovalResolve(BaseModel):
    decision: str          # "approve" | "deny"
    decided_by: str
    limits: dict = Field(default_factory=dict)


class KillRequest(BaseModel):
    engagement_id: Optional[str] = None   # None = global


class LoginRequest(BaseModel):
    username: str
    password: str


class ScheduleCreate(BaseModel):
    cron: str   # standard 5-field cron, validated with croniter at the endpoint


class TenantConfigModel(BaseModel):
    alert_webhook: Optional[str] = None

class DockerRunnerModel(BaseModel):
    image: str = "hexacore/kali-tools:latest"
    network: str = "hexacore_toolnet"
    docker_bin: str = "docker"
    runtime: Optional[str] = None


class VMRunnerModel(BaseModel):
    host: str = ""
    user: str = "kali"
    port: int = 22
    key_path: Optional[str] = None
    password: Optional[str] = None
    connect_timeout: int = 10


class RunnerConfigModel(BaseModel):
    backend: str = "dryrun"
    docker: DockerRunnerModel = Field(default_factory=DockerRunnerModel)
    vm: VMRunnerModel = Field(default_factory=VMRunnerModel)
