from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


# Load webapp/backend/.env
load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


@dataclass(frozen=True)
class Settings:
    backend_dir: Path
    project_root: Path
    recon_root: Path
    database_path: Path
    database_url: str | None

    frontend_origins: tuple[str, ...]

    max_concurrent_scans: int
    mock_scanner: bool
    api_key: str | None
    skip_shodan: bool

    # Authentication
    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_minutes: int
    auth_cookie_name: str
    auth_cookie_secure: bool
    auth_cookie_samesite: str


    @classmethod
    def load(cls) -> "Settings":
        backend_dir = Path(__file__).resolve().parents[1]

        default_project_root = backend_dir.parents[1]

        project_root = Path(
            os.getenv(
                "CRAWLLER_PROJECT_ROOT",
                str(default_project_root),
            )
        ).resolve()

        recon_root = Path(
            os.getenv(
                "CRAWLLER_RECON_ROOT",
                str(project_root / "recon_runs"),
            )
        ).resolve()

        database_path = Path(
            os.getenv(
                "CRAWLLER_DATABASE_PATH",
                str(backend_dir / "data" / "crawller_web.db"),
            )
        ).resolve()

        database_url = (
            os.getenv("CRAWLLER_DATABASE_URL")
            or os.getenv("DATABASE_URL")
            or None
        )

        origins = tuple(
            value.strip().rstrip("/")
            for value in os.getenv(
                "CRAWLLER_FRONTEND_ORIGINS",
                "http://localhost:3000,http://127.0.0.1:3000",
            ).split(",")
            if value.strip()
        )

        # --------------------------------------------------------------
        # JWT
        # --------------------------------------------------------------

        jwt_secret = (
            os.getenv("CRAWLLER_JWT_SECRET")
            or os.getenv("JWT_SECRET")
            or ""
        ).strip()

        if not jwt_secret:
            raise RuntimeError(
                "CRAWLLER_JWT_SECRET is not set. "
                "Generate a strong random secret and add it to "
                "webapp/backend/.env."
            )

        jwt_algorithm = (
            os.getenv(
                "CRAWLLER_JWT_ALGORITHM",
                "HS256",
            ).strip()
            or "HS256"
        )

        jwt_expire_minutes = max(
            5,
            int(
                os.getenv(
                    "CRAWLLER_JWT_EXPIRE_MINUTES",
                    "60",
                )
            ),
        )

        # --------------------------------------------------------------
        # Authentication cookie
        # --------------------------------------------------------------

        auth_cookie_name = (
            os.getenv(
                "CRAWLLER_AUTH_COOKIE_NAME",
                "access_token",
            ).strip()
            or "access_token"
        )

        auth_cookie_secure = _bool(
            "CRAWLLER_AUTH_COOKIE_SECURE",
            False,
        )

        auth_cookie_samesite = (
            os.getenv(
                "CRAWLLER_AUTH_COOKIE_SAMESITE",
                "lax",
            )
            .strip()
            .lower()
        )

        if auth_cookie_samesite not in {
            "lax",
            "strict",
            "none",
        }:
            raise RuntimeError(
                "CRAWLLER_AUTH_COOKIE_SAMESITE must be "
                "'lax', 'strict', or 'none'."
            )

        if auth_cookie_samesite == "none" and not auth_cookie_secure:
            raise RuntimeError(
                "CRAWLLER_AUTH_COOKIE_SECURE must be true when "
                "CRAWLLER_AUTH_COOKIE_SAMESITE=none."
            )

        # --------------------------------------------------------------
        # Return settings
        # --------------------------------------------------------------

        return cls(
            backend_dir=backend_dir,
            project_root=project_root,
            recon_root=recon_root,
            database_path=database_path,
            database_url=database_url,
            frontend_origins=origins,

            max_concurrent_scans=max(
                1,
                int(
                    os.getenv(
                        "CRAWLLER_MAX_CONCURRENT_SCANS",
                        "1",
                    )
                ),
            ),

            mock_scanner=_bool(
                "CRAWLLER_MOCK_SCANNER",
                False,
            ),

            api_key=os.getenv(
                "CRAWLLER_API_KEY"
            ) or None,

            skip_shodan=_bool(
                "CRAWLLER_SKIP_SHODAN",
                False,
            ),

            jwt_secret=jwt_secret,
            jwt_algorithm=jwt_algorithm,
            jwt_expire_minutes=jwt_expire_minutes,
            auth_cookie_name=auth_cookie_name,
            auth_cookie_secure=auth_cookie_secure,
            auth_cookie_samesite=auth_cookie_samesite,


        )


settings = Settings.load()