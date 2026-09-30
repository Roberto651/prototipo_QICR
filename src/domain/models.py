from pydantic import BaseModel, Field
from typing import List, Set, Optional

class Intent(BaseModel):
    src: str
    dst: str
    src_type: str = "group"
    dst_type: str = "endpoint"
    filters: Set[int] = Field(default_factory=set)
    sfc: List[str] = Field(default_factory=list)
    permit: Set[int] = Field(default_factory=set)
    deny: Set[int] = Field(default_factory=set)
    
    # QoS Parameters
    bandwidth: Optional[float] = None
    latency: Optional[float] = None
    packet_loss: Optional[float] = None
    priority: Optional[int] = None

    def __str__(self):
        lines = [f"define intent Intent_{self.src}_{self.dst}:"]
        lines.append(f"  from {self.src_type}('{self.src}')")
        lines.append(f"  to {self.dst_type}('{self.dst}')")
        if self.sfc:
            sfc_str = ", ".join([f"middlebox('{x}')" for x in self.sfc])
            lines.append(f"  add {sfc_str}")
        if self.permit:
            permit_str = ", ".join([f"traffic('{x}')" for x in self.permit])
            lines.append(f"  allow {permit_str}")
        if self.deny:
            deny_str = ", ".join([f"traffic('{x}')" for x in self.deny])
            lines.append(f"  block {deny_str}")
        if self.bandwidth is not None:
            lines.append(f"  demand bandwidth('{self.bandwidth}')")
        if self.latency is not None:
            lines.append(f"  demand latency('{self.latency}')")
        if self.packet_loss is not None:
            lines.append(f"  demand packet_loss('{self.packet_loss}')")
        if self.priority is not None:
            lines.append(f"  set priority('{self.priority}')")
        return "\n".join(lines)
