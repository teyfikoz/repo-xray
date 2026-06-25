"""
API Surface Extractor — static analysis, zero AI tokens.
Detects HTTP route definitions across major frameworks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from .fetcher import RepoData

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY", "ALL", "WS"}


@dataclass
class ApiEndpoint:
    method: str       # GET | POST | etc.
    path: str         # /users/{id}
    file: str
    line: int
    framework: str    # FastAPI | Express | Django | Flask | etc.

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
        }


@dataclass
class ApiSurfaceReport:
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    summary: str = ""

    @property
    def count(self) -> int:
        return len(self.endpoints)

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "frameworks": self.frameworks,
            "summary": self.summary,
            "endpoints": [e.as_dict() for e in self.endpoints],
        }


# ── Framework-specific regex patterns ────────────────────────────────────────
# Each: (framework_name, http_method_or_None, path_group_index, compiled_regex)
_PATTERNS: list[tuple[str, str | None, int, re.Pattern]] = [

    # FastAPI / Starlette: @app.get("/path") / @router.post("/path")
    ("FastAPI", None, 2,
     re.compile(r'@(?:\w+)\.(get|post|put|patch|delete|head|options|websocket)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Flask: @app.route("/path", methods=["GET"])  /  @blueprint.route(...)
    ("Flask", None, 1,
     re.compile(r'@(?:\w+)\.route\s*\(\s*["\']([^"\']+)["\'](?:.*methods\s*=\s*\[([^\]]+)\])?',
                re.IGNORECASE)),

    # Express.js: app.get('/path') / router.post('/path') / app.all('/path')
    ("Express", None, 2,
     re.compile(r'(?:app|router)\.(get|post|put|patch|delete|head|options|all|ws)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Fastify: fastify.get('/path', ...) / server.post(...)
    ("Fastify", None, 2,
     re.compile(r'(?:fastify|server)\.(get|post|put|patch|delete|head|options)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Django: path('endpoint/', view, name=...) / re_path(...)
    ("Django", "ANY", 1,
     re.compile(r'(?:path|re_path)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)),

    # Django urls.py: url(r'^pattern/$', view)
    ("Django", "ANY", 1,
     re.compile(r'url\s*\(\s*r?["\']([^"\']+)["\']', re.IGNORECASE)),

    # Gin (Go): r.GET("/path") / r.POST("/path")
    ("Gin", None, 2,
     re.compile(r'[rR]\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Echo (Go): e.GET("/path") / g.POST("/path")
    ("Echo", None, 2,
     re.compile(r'[eg]\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Fiber (Go): app.Get("/path")
    ("Fiber", None, 2,
     re.compile(r'app\.(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Rails routes.rb: get '/path', to: ... / resources :name
    ("Rails", "GET", 1,
     re.compile(r'^\s*get\s+["\']([^"\']+)["\']', re.IGNORECASE | re.MULTILINE)),
    ("Rails", "POST", 1,
     re.compile(r'^\s*post\s+["\']([^"\']+)["\']', re.IGNORECASE | re.MULTILINE)),
    ("Rails", "RESOURCE", 1,
     re.compile(r'^\s*resources?\s+:(\w+)', re.IGNORECASE | re.MULTILINE)),

    # Next.js API routes: files under pages/api/ or app/api/ are routes
    # Handled separately below via path detection

    # Spring (Java): @GetMapping/@PostMapping/@RequestMapping
    ("Spring", None, 2,
     re.compile(r'@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\']',
                re.IGNORECASE)),

    # ASP.NET: [HttpGet("/path")] / [Route("/path")]
    ("ASP.NET", None, 2,
     re.compile(r'\[(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\s*\(\s*["\']([^"\']*)["\']',
                re.IGNORECASE)),

    # Laravel (PHP): Route::get('/path', ...) / Route::post(...)
    ("Laravel", None, 2,
     re.compile(r'Route::(get|post|put|patch|delete|any|match)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),

    # Actix-web (Rust): #[get("/path")] / #[post("/path")]
    ("Actix-web", None, 2,
     re.compile(r'#\[(get|post|put|patch|delete|head|options)\s*\(\s*["\']([^"\']+)["\']',
                re.IGNORECASE)),
]


def _normalize_method(raw: str) -> str:
    m = raw.upper()
    if m in ("ANY", "ALL", "RESOURCE"):
        return m
    return m if m in _HTTP_METHODS else "ANY"


def _extract_fastapi_method(match_group_1: str) -> str:
    return match_group_1.upper()


def _spring_method(annotation: str) -> str:
    mapping = {
        "GETMAPPING": "GET",
        "POSTMAPPING": "POST",
        "PUTMAPPING": "PUT",
        "PATCHMAPPING": "PATCH",
        "DELETEMAPPING": "DELETE",
        "REQUESTMAPPING": "ANY",
    }
    return mapping.get(annotation.upper(), "ANY")


def extract_api_surface(repo: RepoData) -> ApiSurfaceReport:
    """Detect all HTTP endpoints from known framework patterns."""
    endpoints: list[ApiEndpoint] = []
    detected_frameworks: set[str] = set()

    for repo_file in repo.files:
        path = repo_file.path.lower()
        content = repo_file.content
        lines = content.splitlines()

        # Next.js: files under pages/api/ or app/api/ are implicit GET endpoints
        if ("pages/api/" in path or "app/api/" in path) and path.endswith((".js", ".ts", ".tsx")):
            # Detect exported HTTP method handlers: export async function GET
            for line_no, line in enumerate(lines, 1):
                m = re.search(r'export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(', line, re.IGNORECASE)
                if m:
                    route_path = "/" + repo_file.path.replace("pages/api/", "api/").replace("app/api/", "api/")
                    route_path = re.sub(r'\.(js|ts|tsx)$', '', route_path)
                    route_path = re.sub(r'/index$', '', route_path)
                    endpoints.append(ApiEndpoint(m.group(1).upper(), route_path, repo_file.path, line_no, "Next.js"))
                    detected_frameworks.add("Next.js")
            # If no explicit method exports, treat as ANY
            if not any(e.file == repo_file.path for e in endpoints):
                route_path = "/" + repo_file.path.replace("pages/api/", "api/").replace("app/api/", "api/")
                route_path = re.sub(r'\.(js|ts|tsx)$', '', route_path)
                route_path = re.sub(r'/index$', '', route_path)
                endpoints.append(ApiEndpoint("ANY", route_path, repo_file.path, 1, "Next.js"))
                detected_frameworks.add("Next.js")
            continue

        for framework, fixed_method, path_group_idx, pattern in _PATTERNS:
            for match in pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1

                if framework == "FastAPI":
                    method = match.group(1).upper()
                    route_path = match.group(2)
                elif framework in ("Flask",):
                    route_path = match.group(1)
                    # Try to extract methods from inline methods= clause
                    methods_raw = match.group(2) if match.lastindex and match.lastindex >= 2 else None
                    if methods_raw:
                        for mth in re.findall(r'["\'](\w+)["\']', methods_raw):
                            endpoints.append(ApiEndpoint(mth.upper(), route_path, repo_file.path, line_no, framework))
                        detected_frameworks.add(framework)
                        continue
                    method = "GET"  # Flask default
                elif framework == "Spring":
                    method = _spring_method(match.group(1))
                    route_path = match.group(2) or "/"
                elif fixed_method:
                    method = fixed_method
                    route_path = match.group(path_group_idx)
                else:
                    method = _normalize_method(match.group(1))
                    route_path = match.group(2) if match.lastindex and match.lastindex >= 2 else "/"

                if not route_path:
                    continue

                endpoints.append(ApiEndpoint(method, route_path, repo_file.path, line_no, framework))
                detected_frameworks.add(framework)

    # De-duplicate exact same method+path+file
    seen: set[tuple] = set()
    unique: list[ApiEndpoint] = []
    for e in endpoints:
        key = (e.method, e.path, e.file)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    # Sort: by framework, then method, then path
    unique.sort(key=lambda x: (x.framework, x.method, x.path))

    frameworks = sorted(detected_frameworks)

    if not unique:
        summary = "No API route definitions detected (may use a framework we don't scan, or this is a library/CLI project)."
    else:
        summary = f"{len(unique)} endpoint(s) detected across {len(frameworks)} framework(s): {', '.join(frameworks)}."

    return ApiSurfaceReport(endpoints=unique, frameworks=frameworks, summary=summary)
