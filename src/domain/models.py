from pydantic import BaseModel, Field
from typing import List, Set

class Intent(BaseModel):
    src: str
    dst: str
    filters: Set[int] = Field(default_factory=set)
    sfc: List[str] = Field(default_factory=list)
    permit: Set[int] = Field(default_factory=set)
    deny: Set[int] = Field(default_factory=set)

    def __str__(self):
        lines = [f"define intent Intent_{self.src}_{self.dst}:"]
        lines.append(f"  from group('{self.src}')")
        lines.append(f"  to endpoint('{self.dst}')")
        if self.sfc:
            sfc_str = ", ".join([f"middlebox('{x}')" for x in self.sfc])
            lines.append(f"  add {sfc_str}")
        if self.permit:
            permit_str = ", ".join([f"traffic('{x}')" for x in self.permit])
            lines.append(f"  allow {permit_str}")
        if self.deny:
            deny_str = ", ".join([f"traffic('{x}')" for x in self.deny])
            lines.append(f"  block {deny_str}")
        return "\n".join(lines)
