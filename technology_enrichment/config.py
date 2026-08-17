from __future__ import annotations

import os
from dataclasses import dataclass


def auto_workers(requested: int | str | None, *, ceiling: int, floor: int = 1) -> int:
    if isinstance(requested, int):
        return max(floor, min(ceiling, requested))
    text = str(requested or "auto").strip().lower()
    if text and text != "auto":
        try:
            return max(floor, min(ceiling, int(text)))
        except ValueError:
            pass
    cpu = os.cpu_count() or 4
    return max(floor, min(ceiling, max(2, cpu // 2)))


@dataclass(frozen=True)
class EnrichmentConfig:
    max_mode: bool = False
    lane_workers: int = 5
    http_workers: int = 6
    js_workers: int = 8
    service_workers: int = 4
    whatweb_threads: int = 10
    whatweb_aggression: int = 1
    wappalyzer_next_full_workers: int = 2
    wappalyzer_next_balanced_workers: int = 8
    wappalyzer_next_full_target_cap: int = 12
    wappalyzer_next_page_timeout: int = 25
    request_timeout: float = 10.0
    lane_timeout: int = 900
    max_web_targets: int = 100
    max_service_targets: int = 100
    max_js_urls: int = 300
    max_http_bytes: int = 1_000_000
    max_js_bytes: int = 5_000_000
    user_agent: str = "0xCrawllerV9.2-Authorized-Technology-Intelligence/1.0"
    whatweb_image: str = "0xcrawller/whatweb:0.6.4"
    retirejs_image: str = "0xcrawller/retirejs:5.4.3"
    zgrab2_image: str = "ghcr.io/zmap/zgrab2:latest"
    wappalyzer_next_image: str = "0xcrawller/wappalyzer-next:2.0.0"
    nuclei_image: str = "projectdiscovery/nuclei:latest"
    nuclei_workers: int = 10
    nuclei_severity: tuple[str, ...] = ()
    nuclei_templates: str | None = None

    @classmethod
    def create(
        cls,
        *,
        max_mode: bool,
        workers: int | str | None,
        http_workers: int | str | None,
        js_workers: int | str | None,
        service_workers: int | str | None,
        whatweb_threads: int | str | None,
        request_timeout: float,
        lane_timeout: int,
        whatweb_image: str | None,
        retirejs_image: str | None,
        zgrab2_image: str | None,
        wappalyzer_next_image: str | None = None,
        wappalyzer_next_workers: int | str | None = "auto",
        wappalyzer_next_balanced_workers: int | str | None = "auto",
        wappalyzer_next_full_target_cap: int | None = None,
        wappalyzer_next_page_timeout: int = 25,
        nuclei_image: str | None = None,
        nuclei_workers: int | str | None = "auto",
        nuclei_severity: tuple[str, ...] | list[str] | None = None,
        nuclei_templates: str | None = None,
    ) -> "EnrichmentConfig":
        lane_workers = auto_workers(workers, ceiling=5, floor=1)
        return cls(
            max_mode=max_mode,
            lane_workers=lane_workers,
            http_workers=auto_workers(http_workers, ceiling=16, floor=1),
            js_workers=auto_workers(js_workers, ceiling=20, floor=1),
            service_workers=auto_workers(service_workers, ceiling=8, floor=1),
            whatweb_threads=auto_workers(whatweb_threads, ceiling=50, floor=1),
            whatweb_aggression=3 if max_mode else 1,
            wappalyzer_next_full_workers=auto_workers(wappalyzer_next_workers, ceiling=3, floor=1),
            wappalyzer_next_balanced_workers=auto_workers(wappalyzer_next_balanced_workers, ceiling=20, floor=1),
            wappalyzer_next_full_target_cap=max(1, min(50, int(wappalyzer_next_full_target_cap or (30 if max_mode else 12)))),
            wappalyzer_next_page_timeout=max(5, min(120, int(wappalyzer_next_page_timeout))),
            request_timeout=max(2.0, min(60.0, float(request_timeout))),
            lane_timeout=max(60, int(lane_timeout)),
            max_web_targets=250 if max_mode else 100,
            max_service_targets=250 if max_mode else 100,
            max_js_urls=1000 if max_mode else 300,
            max_http_bytes=2_000_000 if max_mode else 1_000_000,
            max_js_bytes=8_000_000 if max_mode else 5_000_000,
            whatweb_image=whatweb_image or cls.whatweb_image,
            retirejs_image=retirejs_image or cls.retirejs_image,
            zgrab2_image=zgrab2_image or cls.zgrab2_image,
            wappalyzer_next_image=wappalyzer_next_image or cls.wappalyzer_next_image,
            nuclei_image=nuclei_image or cls.nuclei_image,
            nuclei_workers=auto_workers(nuclei_workers, ceiling=25, floor=1),
            nuclei_severity=tuple(nuclei_severity) if nuclei_severity else cls.nuclei_severity,
            nuclei_templates=nuclei_templates,
        )
