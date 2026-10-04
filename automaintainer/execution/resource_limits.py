from pydantic import BaseModel, Field

class SandboxResourceLimits(BaseModel):
    """Resource controls enforced on untrusted repository execution."""
    cpu_cores: float = Field(default=2.0, description="Max CPU cores quota")
    memory_mb: int = Field(default=2048, description="Max memory in MB (e.g. 2GB)")
    max_pids: int = Field(default=64, description="PID limit to prevent fork bombs")
    wall_clock_timeout_seconds: int = Field(default=300, description="Max runtime timeout (5 mins)")
    disk_quota_mb: int = Field(default=1024, description="Max writable disk quota in MB")
    allow_network_egress: bool = Field(default=False, description="Default deny external egress")
