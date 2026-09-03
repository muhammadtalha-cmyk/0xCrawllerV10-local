from __future__ import annotations

from typing import Any, Dict, List, Optional
from .base import BaseModule
from .subdomains.runner import SubdomainDiscoveryModule
from .technologies.runner import TechnologyDetectionModule
from .ports.runner import PortScannerModule
from .endpoints.runner import EndpointDiscoveryModule
from .screenshots.runner import ScreenshotCollectionModule
from .cve.runner import CVEDetectionModule
from .waf.runner import WAFDetectionModule
from .ssl.runner import SSLCertificateModule
from .dns_hygiene.runner import DNSHygieneModule
from .takeover.runner import SubdomainTakeoverModule
from .headers.runner import SecurityHeadersModule

_MODULES: Dict[str, BaseModule] = {
    SubdomainDiscoveryModule.id: SubdomainDiscoveryModule(),
    TechnologyDetectionModule.id: TechnologyDetectionModule(),
    PortScannerModule.id: PortScannerModule(),
    EndpointDiscoveryModule.id: EndpointDiscoveryModule(),
    ScreenshotCollectionModule.id: ScreenshotCollectionModule(),
    CVEDetectionModule.id: CVEDetectionModule(),
    WAFDetectionModule.id: WAFDetectionModule(),
    SSLCertificateModule.id: SSLCertificateModule(),
    DNSHygieneModule.id: DNSHygieneModule(),
    SubdomainTakeoverModule.id: SubdomainTakeoverModule(),
    SecurityHeadersModule.id: SecurityHeadersModule(),
}


def get_module(module_id: str) -> Optional[BaseModule]:
    return _MODULES.get(module_id.lower().strip())


def list_modules() -> List[Dict[str, Any]]:
    return [
        {
            "id": mod.id,
            "name": mod.name,
            "description": mod.description,
            "category": mod.category,
            "icon": mod.icon,
            "status": "ready",
        }
        for mod in _MODULES.values()
    ]


def all_modules() -> Dict[str, BaseModule]:
    return dict(_MODULES)
