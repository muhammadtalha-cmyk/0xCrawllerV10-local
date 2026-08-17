"""Static configuration and conservative defaults for Smart Recon V8.4."""

from __future__ import annotations

IMAGES = {
    "subfinder": "projectdiscovery/subfinder:latest",
    "bbot": "blacklanternsecurity/bbot:stable",
    "gobuster": "ghcr.io/oj/gobuster:latest",
    "amass": "owaspamass/amass:latest",
    "katana": "projectdiscovery/katana:latest",
    "dnsx": "projectdiscovery/dnsx:latest",
    "httpx": "projectdiscovery/httpx:latest",
}

COMMON_WORDS = [
    "www", "app", "apps", "web", "portal", "admin", "dashboard", "login", "auth",
    "api", "apis", "backend", "frontend", "server", "panel", "console", "account",
    "user", "users", "client", "clients", "customer", "customers", "cms", "crm",
    "dev", "development", "test", "testing", "qa", "uat", "stage", "staging", "prod",
    "production", "demo", "sandbox", "preprod", "beta", "alpha", "old", "new",
    "mail", "email", "smtp", "imap", "pop", "mx", "ns", "dns", "cdn", "static", "assets",
    "files", "file", "storage", "s3", "bucket", "download", "uploads", "media", "img", "images",
    "docs", "doc", "vpn", "remote", "rdp", "ssh", "git", "gitlab", "jenkins", "ci", "cd",
    "monitor", "grafana", "kibana", "elastic", "logs", "status", "health", "metrics",
    "exam", "exams", "student", "students", "school", "schools", "question", "questions",
    "bank", "question-bank", "import", "review", "otp", "sms", "notification", "notify",
    "chat", "call", "xmpp", "sync", "reg", "register", "registration", "lms", "slac",
    "booking", "integration", "research", "support", "public", "private", "internal",
]

MUTATION_SUFFIXES = [
    "dev", "test", "qa", "uat", "stage", "staging", "prod", "demo", "old", "new",
    "api", "admin", "portal", "app", "web", "panel", "login", "backend", "frontend",
]

PRIORITY_CANDIDATE_LABELS = [
    "admin", "adminbackend", "backend", "api", "portal", "web", "mail",
    "email", "email.otp", "otp", "xmpp", "chat", "call", "file", "sync", "reg",
    "slac", "slac-admin", "api-slac", "slac-api", "exam", "exam-admin", "question-bank",
]

NOISE_WORDS = {
    "http", "https", "html", "htm", "com", "net", "org", "www", "static", "chunks", "chunk",
    "css", "js", "json", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2", "ttf",
    "latest", "dist", "assets", "cdn", "cdnjs", "npm", "core", "main", "layout", "page",
    "polyfills", "webpack", "font", "fonts", "googleapis", "cloudflare", "beacon", "script",
    "scripts", "challenge", "platform", "source", "sans", "nastaliq", "urdu", "sweetalert",
    "tabler", "mathjax", "next", "root", "index", "beta", "min", "map",
    "oasis", "openoffice", "spreadsheetml", "drawingml", "wordprocessingml", "presentationml",
    "officedocument", "schemas", "schema", "worksheet", "worksheets", "workbook", "rels",
    "relationship", "relationships", "vba", "vml", "xml", "xmlns", "w3", "purl",
    "amp", "cur", "swap", "threaded", "wght", "css2", "webfont", "u0026display", "u0026family",
    "display", "family", "es5", "mml", "chtml", "tex", "beta20", "width", "height",
}

# Normal and --max are intentionally bounded. Full low-confidence generation requires --exhaustive.
DEFAULT_NORMAL_CANDIDATE_LIMIT = 25_000
DEFAULT_MAX_CANDIDATE_LIMIT = 100_000
DEFAULT_DNSX_CHUNK_SIZE = 25_000
DEFAULT_DNSX_WORKERS = 3
DEFAULT_DNSX_THREADS = 50
DEFAULT_DNSX_RATE_LIMIT = 100
DEFAULT_DNSX_RETRIES = 2
DEFAULT_WILDCARD_PROBES = 3
DEFAULT_MAX_WILDCARD_ZONES = 25

DEFAULT_KATANA_CONCURRENCY = 10
DEFAULT_KATANA_RATE_LIMIT = 50
DEFAULT_KATANA_DURATION = "10m"
DEFAULT_KATANA_MAX_RESPONSE_SIZE = 5_242_880

# Optional edge/WAF enrichment. Passive HTTPX/Wappalyzer detection is always
# collected; WAFW00F active fingerprinting requires --active-waf.
DEFAULT_WAF_LIMIT = 20
DEFAULT_WAF_REQUEST_TIMEOUT = 7
DEFAULT_WAF_STAGE_TIMEOUT = 900

# Active port enumeration is opt-in. Naabu defaults to a TCP CONNECT scan for
# predictable behavior under Docker Desktop/Windows. Nmap only validates ports
# already reported open by Naabu and does not run NSE scripts or OS detection.
DEFAULT_PORT_SCAN_LIMIT = 50
DEFAULT_NAABU_TOP_PORTS = "100"
DEFAULT_NAABU_RATE = 100
DEFAULT_NAABU_THREADS = 25
DEFAULT_NAABU_RETRIES = 2
DEFAULT_NAABU_SOCKET_TIMEOUT_MS = 1500
DEFAULT_PORT_SCAN_STAGE_TIMEOUT = 1800
DEFAULT_NMAP_WORKERS = 2
DEFAULT_NMAP_HOST_TIMEOUT = "5m"
NAABU_IMAGE = "projectdiscovery/naabu:latest"
NMAP_IMAGE = "smartrecon/nmap:debian12"

KATANA_EXCLUDED_EXTENSIONS = (
    "png,jpg,jpeg,gif,svg,ico,webp,bmp,woff,woff2,ttf,eot,otf,mp3,mp4,avi,mov,mkv,zip,rar,7z,pdf"
)

THIRD_PARTY_PROVIDERS = {
    "hubspot.net": "HubSpot",
    "hscoscdn20.net": "HubSpot",
    "googlehosted.com": "Google",
    "github.io": "GitHub Pages",
    "sendgrid.net": "SendGrid",
    "cloudfront.net": "Amazon CloudFront",
    "featurebase.app": "Featurebase",
    "webflow.com": "Webflow",
    "stspg-customer.com": "Atlassian Statuspage",
    "herokudns.com": "Heroku",
    "hippovideo.io": "Hippo Video",
    "amazonaws.com": "Amazon Web Services",
    "azurewebsites.net": "Microsoft Azure",
    "trafficmanager.net": "Microsoft Azure",
    "azurefd.net": "Microsoft Azure Front Door",
    "windows.net": "Microsoft Azure / Entra ID",
    "outlook.com": "Microsoft 365 / Outlook",
    "outlook.cloud.microsoft": "Microsoft 365 / Outlook",
    "office.com": "Microsoft 365",
    "cloud.microsoft": "Microsoft 365",
    "manage.microsoft.com": "Microsoft Intune",
    "microsoftonline.com": "Microsoft Entra ID",
    "msidentity.com": "Microsoft Entra ID",
    "akadns.net": "Akamai DNS / Microsoft service delivery",
    "fastly.net": "Fastly",
    "samanage.com": "SolarWinds Service Desk",
}

RELEVANT_EXTERNAL_HOST_SUFFIXES = tuple(THIRD_PARTY_PROVIDERS)

# Passive Shodan defaults. The stage is opt-in and never submits on-demand scans.
DEFAULT_SHODAN_MAX_QUERY_CREDITS = 10
DEFAULT_SHODAN_DOMAIN_PAGES = 1
DEFAULT_SHODAN_MAX_DORKS = 12
DEFAULT_SHODAN_PAGES_PER_QUERY = 1
DEFAULT_SHODAN_RESULTS_PER_QUERY = 100
DEFAULT_SHODAN_MAX_HOST_LOOKUPS = 100
DEFAULT_SHODAN_TIMEOUT = 20
DEFAULT_SHODAN_API_RPS = 1.0
DEFAULT_SHODAN_CACHE_TTL_HOURS = 24

# Bounded recursive recon expansion. The root is level 0 and at most three
# descendant levels are followed. Per-level crawling is parallel; DNS/HTTP
# validation remains batched to avoid duplicate work.
DEFAULT_RECURSIVE_DEPTH = 3
DEFAULT_RECURSIVE_WORKERS = 4
DEFAULT_RECURSIVE_MAX_HOSTS = 250
DEFAULT_RECURSIVE_KATANA_DEPTH = 3
DEFAULT_RECURSIVE_KATANA_DURATION = "2m"
DEFAULT_RECURSIVE_KATANA_CONCURRENCY = 5
DEFAULT_RECURSIVE_KATANA_RATE_LIMIT = 20
DEFAULT_RECURSIVE_STAGE_TIMEOUT = 900
