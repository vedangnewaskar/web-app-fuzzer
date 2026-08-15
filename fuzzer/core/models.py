from dataclasses import dataclass
from typing import Dict

@dataclass
class HTTPResult:
    url: str
    method: str  #get or post
    status_code: int
    response_length: int
    response_time: float
    headers: Dict[str, str]  #{"Content-Type": "text/html"}