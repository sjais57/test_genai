"""
DSP-FD2: Unified Front Door Service
Intelligently routes requests either directly to modules or through APISIX gateway
based on manifest configuration
"""

import asyncio
import hashlib
import importlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from enum import Enum

# Add project root and src directory to Python path
project_root = Path(__file__).parent.parent
src_dir = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logs_dir = Path("logs")
logs_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/front_door.log", mode="a")
    ]
)
logger = logging.getLogger("DSP-FD2")

import httpx
from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field

# Import APISIX client
from apisix import APISIXClient

# Prometheus imports
try:
    from prometheus_fastapi_instrumentator import Instrumentator, metrics
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("Prometheus not available - metrics will be disabled")

# Optional imports
try:
    import redis
except ImportError:
    redis = None
    logger.info("Redis not available - caching will be disabled")

# Import base module interface if available
try:
    from src.modules.base import BaseModule, ModuleConfig, ModuleType
except ImportError:
    logger.warning("Base module not found - direct module routing may be limited")
    BaseModule = None


class RoutingMode(Enum):
    """Routing mode for a project"""
    DIRECT = "direct"  # Direct module routing
    APISIX = "apisix"  # Route through APISIX gateway
    HYBRID = "hybrid"  # Use APISIX for some routes, direct for others


class UnifiedFrontDoorConfig(BaseModel):
    """Configuration for unified Front Door service"""
    # Control Tower
    control_tower_url: str = Field(..., description="Control Tower API URL")
    control_tower_secret: Optional[str] = Field(None, description="Control Tower auth secret")
    
    # APISIX (optional)
    apisix_admin_url: Optional[str] = Field(None, description="APISIX Admin API URL")
    apisix_admin_key: Optional[str] = Field(None, description="APISIX Admin API key")
    apisix_gateway_url: Optional[str] = Field(None, description="APISIX Gateway URL")
    
    # Module management
    module_pool_size: int = Field(default=10, description="Maximum modules in pool")
    
    # Prometheus metrics
    enable_metrics: bool = Field(default=True, description="Enable Prometheus metrics")
    metrics_port: int = Field(default=8081, description="Port for metrics endpoint")
    
    # General settings
    environment: str = Field(default="production")
    request_timeout: float = Field(default=30.0)
    redis_url: Optional[str] = Field(None, description="Redis URL for caching")
    auto_configure_apisix: bool = Field(default=False, description="Auto-configure APISIX on startup")
    cache_ttl: int = Field(default=300, description="Cache TTL in seconds")


class MetricsCollector:
    """Collects and manages Prometheus metrics for Front Door service"""
    
    def __init__(self, config: UnifiedFrontDoorConfig):
        self.config = config
        self.enabled = config.enable_metrics and PROMETHEUS_AVAILABLE
        
        if not self.enabled:
            logger.info("Prometheus metrics are disabled")
            return
        
        # Custom metrics for Front Door service
        self.request_count = Counter(
            'front_door_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status_code', 'project_id', 'routing_mode']
        )
        
        self.request_duration = Histogram(
            'front_door_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint', 'project_id', 'routing_mode']
        )
        
        self.request_size = Histogram(
            'front_door_request_size_bytes',
            'Request size in bytes',
            ['method', 'endpoint', 'project_id']
        )
        
        self.response_size = Histogram(
            'front_door_response_size_bytes',
            'Response size in bytes',
            ['method', 'endpoint', 'project_id', 'status_code']
        )
        
        self.active_requests = Gauge(
            'front_door_active_requests',
            'Number of active requests',
            ['project_id']
        )
        
        self.routing_mode_requests = Counter(
            'front_door_routing_requests_total',
            'Requests by routing mode',
            ['routing_mode', 'project_id']
        )
        
        self.module_pool_size = Gauge(
            'front_door_module_pool_size',
            'Module pool size and usage',
            ['type']
        )
        
        self.apisix_requests = Counter(
            'front_door_apisix_requests_total',
            'APISIX routing requests',
            ['project_id', 'status_code']
        )
        
        self.direct_requests = Counter(
            'front_door_direct_requests_total',
            'Direct routing requests',
            ['project_id', 'status_code']
        )
        
        # JWT-specific metrics
        self.jwt_token_requests = Counter(
            'front_door_jwt_token_requests_total',
            'JWT token requests',
            ['project_id', 'jwt_module_name', 'status_code']
        )
        
        self.jwt_token_duration = Histogram(
            'front_door_jwt_token_duration_seconds',
            'JWT token generation duration',
            ['project_id', 'jwt_module_name']
        )
        
        logger.info("Prometheus metrics initialized")
    
    def record_request_metrics(self, method: str, endpoint: str, status_code: int, 
                             project_id: str, routing_mode: str, duration: float,
                             request_size: int = 0, response_size: int = 0):
        """Record metrics for a completed request"""
        if not self.enabled:
            return
        
        # Normalize endpoint to avoid high cardinality
        normalized_endpoint = self._normalize_endpoint(endpoint, project_id)
        
        # Record metrics
        self.request_count.labels(
            method=method,
            endpoint=normalized_endpoint,
            status_code=str(status_code),
            project_id=project_id or "unknown",
            routing_mode=routing_mode or "unknown"
        ).inc()
        
        self.request_duration.labels(
            method=method,
            endpoint=normalized_endpoint,
            project_id=project_id or "unknown",
            routing_mode=routing_mode or "unknown"
        ).observe(duration)
        
        if request_size > 0:
            self.request_size.labels(
                method=method,
                endpoint=normalized_endpoint,
                project_id=project_id or "unknown"
            ).observe(request_size)
        
        if response_size > 0:
            self.response_size.labels(
                method=method,
                endpoint=normalized_endpoint,
                project_id=project_id or "unknown",
                status_code=str(status_code)
            ).observe(response_size)
        
        self.routing_mode_requests.labels(
            routing_mode=routing_mode or "unknown",
            project_id=project_id or "unknown"
        ).inc()
    
    def record_jwt_token_metrics(self, project_id: str, jwt_module_name: str, 
                               status_code: int, duration: float):
        """Record metrics for JWT token requests"""
        if not self.enabled:
            return
        
        self.jwt_token_requests.labels(
            project_id=project_id,
            jwt_module_name=jwt_module_name,
            status_code=str(status_code)
        ).inc()
        
        self.jwt_token_duration.labels(
            project_id=project_id,
            jwt_module_name=jwt_module_name
        ).observe(duration)
    
    def update_module_pool_metrics(self, current_size: int, max_size: int):
        """Update module pool metrics"""
        if not self.enabled:
            return
        
        self.module_pool_size.labels(type="current").set(current_size)
        self.module_pool_size.labels(type="max").set(max_size)
    
    def update_active_requests(self, project_id: str, increment: bool = True):
        """Update active requests gauge"""
        if not self.enabled:
            return
        
        if increment:
            self.active_requests.labels(project_id=project_id or "unknown").inc()
        else:
            self.active_requests.labels(project_id=project_id or "unknown").dec()
    
    def _normalize_endpoint(self, endpoint: str, project_id: str) -> str:
        """Normalize endpoint to avoid high cardinality from dynamic parameters"""
        if not endpoint:
            return "unknown"
        
        # Replace project_id in path
        if project_id and endpoint.startswith(f"/{project_id}"):
            endpoint = endpoint.replace(f"/{project_id}", "/{project_id}")
        
        # Replace common dynamic patterns
        patterns = [
            (r'/[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '/{uuid}'),
            (r'/\d+', '/{id}'),
            (r'/[a-zA-Z0-9_-]+/token', '/{jwt_module_name}/token'),
        ]
        
        import re
        for pattern, replacement in patterns:
            endpoint = re.sub(pattern, replacement, endpoint)
        
        return endpoint


class ModuleManager:
    """Manages direct module lifecycle and pooling"""
    
    def __init__(self, config: UnifiedFrontDoorConfig, metrics_collector: MetricsCollector):
        self.config = config
        self.metrics_collector = metrics_collector
        self.modules: Dict[str, BaseModule] = {}
        self.module_metadata: Dict[str, Dict] = {}
        self.lock = asyncio.Lock()
    
    async def get_or_create_module(
        self, 
        manifest: Dict[str, Any],
        runtime_refs: Dict[str, Any]
    ) -> BaseModule:
        """Get existing module or create new one"""
        if BaseModule is None:
            raise RuntimeError("Direct module routing not available - BaseModule not found")
            
        module_key = self._get_module_key(manifest)
        
        async with self.lock:
            # Check if module exists and is healthy
            if module_key in self.modules:
                module = self.modules[module_key]
                health = await module.health_check()
                if health.get("status") == "ready":
                    self.module_metadata[module_key]["last_used"] = datetime.utcnow()
                    return module
                else:
                    await self._remove_module(module_key)
            
            # Create new module
            module = await self._create_module(manifest, runtime_refs)
            
            # Manage pool size
            if len(self.modules) >= self.config.module_pool_size:
                await self._evict_oldest_module()
            
            self.modules[module_key] = module
            self.module_metadata[module_key] = {
                "created_at": datetime.utcnow(),
                "last_used": datetime.utcnow(),
                "manifest": manifest
            }
            
            # Update metrics
            self.metrics_collector.update_module_pool_metrics(
                len(self.modules), 
                self.config.module_pool_size
            )
            
            return module
    
    async def _create_module(
        self,
        manifest: Dict[str, Any],
        runtime_refs: Dict[str, Any]
    ) -> BaseModule:
        """Dynamically create and initialize a module"""
        runtime = manifest.get("runtime", {})
        implementation = runtime.get("implementation")
        
        if not implementation:
            raise ValueError(f"No implementation specified in manifest")
        
        # Dynamic import
        module_path, class_name = implementation.rsplit(".", 1)
        module = importlib.import_module(module_path)
        module_class = getattr(module, class_name)
        
        # Create instance
        instance = module_class()
        
        # Initialize with config
        config = ModuleConfig(
            module_id=self._get_module_key(manifest),
            module_type=ModuleType(manifest.get("module_type")),
            version=manifest.get("manifest_version", "1.0"),
            environment=manifest.get("environment", self.config.environment),
            backend_endpoints=manifest.get("endpoints", {}).get(self.config.environment, {}),
            runtime_references=runtime_refs,
            metadata=manifest.get("metadata", {})
        )
        
        await instance.initialize(config)
        return instance
    
    def _get_module_key(self, manifest: Dict[str, Any]) -> str:
        """Generate unique key for module instance"""
        key_data = f"{manifest.get('project')}:{manifest.get('module')}:{manifest.get('environment', self.config.environment)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    async def _remove_module(self, module_key: str):
        """Remove and shutdown a module"""
        if module_key in self.modules:
            module = self.modules[module_key]
            await module.shutdown()
            del self.modules[module_key]
            del self.module_metadata[module_key]
            
            # Update metrics
            self.metrics_collector.update_module_pool_metrics(
                len(self.modules), 
                self.config.module_pool_size
            )
    
    async def _evict_oldest_module(self):
        """Evict least recently used module"""
        if not self.module_metadata:
            return
        
        oldest_key = min(
            self.module_metadata.keys(),
            key=lambda k: self.module_metadata[k]["last_used"]
        )
        await self._remove_module(oldest_key)
    
    async def shutdown_all(self):
        """Shutdown all modules"""
        for module_key in list(self.modules.keys()):
            await self._remove_module(module_key)


class UnifiedFrontDoorService:
    """Unified Front Door service with intelligent routing"""
    
    def __init__(self, config: UnifiedFrontDoorConfig):
        self.config = config
        self.metrics_collector = MetricsCollector(config)
        self.module_manager = ModuleManager(config, self.metrics_collector) if BaseModule else None
        self.apisix_client = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.redis_client = None
        
        # Track configured projects and their routing modes
        self.project_routing: Dict[str, RoutingMode] = {}
        self.configured_apisix_projects: Dict[str, Any] = {}
        
        # Initialize APISIX client if configured
        if config.apisix_admin_url and config.apisix_admin_key:
            self.apisix_client = APISIXClient(
                admin_url=config.apisix_admin_url,
                admin_key=config.apisix_admin_key
            )
    
    async def initialize(self):
        """Initialize service connections"""
        self.http_client = httpx.AsyncClient(timeout=self.config.request_timeout)
        
        # Redis for caching (optional)
        if redis and self.config.redis_url:
            try:
                self.redis_client = redis.from_url(self.config.redis_url)
                await self.redis_client.ping()
                logger.info("Redis connection successful")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")
                self.redis_client = None
        
        # Auto-configure APISIX routes if enabled
        if self.config.auto_configure_apisix and self.apisix_client:
            logger.info("Auto-configuring APISIX routes from Control Tower manifests")
            await self.sync_manifests()
    
    async def shutdown(self):
        """Cleanup resources"""
        if self.redis_client:
            await self.redis_client.close()
        if self.http_client:
            await self.http_client.aclose()
        if self.module_manager:
            await self.module_manager.shutdown_all()
        if self.apisix_client:
            await self.apisix_client.close()
    
    async def sync_manifests(self):
        """Synchronize manifests and determine routing modes"""
        try:
            # Get all manifests from Control Tower
            headers = {}
            if self.config.control_tower_secret:
                headers["X-DSPAI-Client-Secret"] = self.config.control_tower_secret
            
            response = await self.http_client.get(
                f"{self.config.control_tower_url}/manifests",
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch manifests: {response.status_code}")
                return
            
            manifests = response.json().get("manifests", [])
            
            for manifest_info in manifests:
                project_id = manifest_info.get("project_id")
                if project_id:
                    await self.analyze_and_configure_project(project_id)
        
        except Exception as e:
            logger.error(f"Failed to sync manifests: {str(e)}")
    
    async def analyze_and_configure_project(self, project_id: str):
        """Analyze project manifest and configure routing accordingly"""
        try:
            # Get full manifest from Control Tower
            headers = {}
            if self.config.control_tower_secret:
                headers["X-DSPAI-Client-Secret"] = self.config.control_tower_secret
            
            response = await self.http_client.get(
                f"{self.config.control_tower_url}/manifests/{project_id}?resolve_env=true",
                headers=headers
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch manifest for {project_id}: {response.status_code}")
                return
            
            manifest = response.json()
            
            # Check for APISIX gateway module
            has_apisix = False
            modules = manifest.get("modules", [])
            
            for module in modules:
                module_type = module.get("module_type", "").lower()
                module_name = module.get("name", "").lower()
                
                # Check if this is an APISIX gateway module
                if module_type == "api_gateway" and "apisix" in module_name:
                    has_apisix = True
                    break
            
            # Determine routing mode
            if has_apisix and self.apisix_client:
                # Use APISIX routing
                self.project_routing[project_id] = RoutingMode.APISIX
                
                # Configure APISIX
                result = await self.apisix_client.configure_from_manifest(manifest)
                self.configured_apisix_projects[project_id] = {
                    "manifest": manifest,
                    "apisix_config": result,
                    "configured_at": datetime.utcnow().isoformat()
                }
                
                if result.get("errors"):
                    logger.warning(f"Project {project_id} configured with errors: {result['errors']}")
                else:
                    logger.info(f"Successfully configured APISIX for project {project_id}")
            
            else:
                # Use direct module routing
                self.project_routing[project_id] = RoutingMode.DIRECT
                logger.info(f"Project {project_id} configured for direct routing")
                
                # Cache the manifest for direct routing
                if self.redis_client:
                    cache_key = f"manifest:{project_id}"
                    await self.redis_client.setex(
                        cache_key,
                        self.config.cache_ttl,
                        json.dumps(manifest)
                    )
        
        except Exception as e:
            logger.error(f"Failed to configure project {project_id}: {str(e)}")
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming request with intelligent routing"""
        start_time = time.time()
        project_id = None
        routing_mode = None
        
        try:
            # Extract project ID from request
            project_id = self.extract_project_id(request)
            
            if not project_id:
                raise HTTPException(status_code=400, detail="Cannot determine project ID from request")
            
            # Update active requests
            self.metrics_collector.update_active_requests(project_id, increment=True)
            
            # Get routing mode for project
            routing_mode = self.project_routing.get(project_id)
            
            if routing_mode is None:
                # Try to configure project on-the-fly
                await self.analyze_and_configure_project(project_id)
                routing_mode = self.project_routing.get(project_id)
            
            if routing_mode == RoutingMode.APISIX:
                # Route through APISIX gateway
                response = await self.route_through_apisix(request, project_id)
                
            elif routing_mode == RoutingMode.DIRECT:
                # Route directly to module
                response = await self.route_to_module(request, project_id)
                
            else:
                # Unknown routing mode or project not found
                raise HTTPException(status_code=404, detail=f"Project {project_id} not configured")
            
            # Calculate request metrics
            duration = time.time() - start_time
            request_size = int(request.headers.get("content-length", 0))
            response_size = len(response.body) if hasattr(response, 'body') else 0
            
            # Record metrics
            self.metrics_collector.record_request_metrics(
                method=request.method,
                endpoint=request.url.path,
                status_code=response.status_code,
                project_id=project_id,
                routing_mode=routing_mode.value if routing_mode else "unknown",
                duration=duration,
                request_size=request_size,
                response_size=response_size
            )
            
            return response
        
        except HTTPException as e:
            # Record error metrics
            duration = time.time() - start_time
            self.metrics_collector.record_request_metrics(
                method=request.method,
                endpoint=request.url.path,
                status_code=e.status_code,
                project_id=project_id or "unknown",
                routing_mode=routing_mode.value if routing_mode else "unknown",
                duration=duration
            )
            raise
        
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            self.metrics_collector.record_request_metrics(
                method=request.method,
                endpoint=request.url.path,
                status_code=500,
                project_id=project_id or "unknown",
                routing_mode=routing_mode.value if routing_mode else "unknown",
                duration=duration
            )
            logger.error(f"Request handling error: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error")
        
        finally:
            # Decrement active requests
            if project_id:
                self.metrics_collector.update_active_requests(project_id, increment=False)
    
    async def route_through_apisix(self, request: Request, project_id: str) -> Response:
        """Route request through APISIX gateway"""
        if not self.apisix_client or not self.config.apisix_gateway_url:
            raise HTTPException(status_code=503, detail="APISIX gateway not configured")
        
        # Build gateway URL with project prefix
        path = request.url.path
        if not path.startswith(f"/{project_id}"):
            path = f"/{project_id}{path}"
        
        gateway_url = f"{self.config.apisix_gateway_url}{path}"
        
        # Forward headers
        headers = dict(request.headers)
        headers.pop("host", None)  # Remove host header
        
        # Get request body if present
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        try:
            # Forward request to APISIX gateway
            apisix_response = await self.http_client.request(
                method=request.method,
                url=gateway_url,
                headers=headers,
                params=dict(request.query_params),
                content=body
            )
            
            # Record APISIX-specific metrics
            if self.metrics_collector.enabled:
                self.metrics_collector.apisix_requests.labels(
                    project_id=project_id,
                    status_code=str(apisix_response.status_code)
                ).inc()
            
            # Return response from APISIX
            return Response(
                content=apisix_response.content,
                status_code=apisix_response.status_code,
                headers=dict(apisix_response.headers)
            )
        
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Gateway timeout")
        except httpx.RequestError as e:
            logger.error(f"APISIX request error: {str(e)}")
            raise HTTPException(status_code=502, detail="Bad gateway")
    
    async def route_to_module(self, request: Request, project_id: str) -> Response:
        """Route request directly to module"""
        if not self.module_manager:
            raise HTTPException(status_code=503, detail="Direct module routing not available")
        
        try:
            # Get manifest
            manifest = await self.get_manifest(project_id)
            
            if not manifest:
                raise HTTPException(status_code=404, detail=f"Manifest for project {project_id} not found")
            
            # Get runtime references
            runtime_refs = await self.get_runtime_references(manifest)
            
            # Get or create module
            module = await self.module_manager.get_or_create_module(manifest, runtime_refs)
            
            # Process request through module
            response_data = await module.process_request({
                "method": request.method,
                "path": request.url.path,
                "headers": dict(request.headers),
                "query_params": dict(request.query_params),
                "body": await request.body() if request.method in ["POST", "PUT", "PATCH"] else None
            })
            
            # Record direct routing metrics
            if self.metrics_collector.enabled:
                self.metrics_collector.direct_requests.labels(
                    project_id=project_id,
                    status_code=str(response_data.get("status_code", 200))
                ).inc()
            
            return Response(
                content=response_data.get("content"),
                status_code=response_data.get("status_code", 200),
                headers=response_data.get("headers", {})
            )
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Module routing error: {str(e)}")
            raise HTTPException(status_code=500, detail="Module processing error")
    
    def extract_project_id(self, request: Request) -> Optional[str]:
        """Extract project ID from request"""
        # Try path-based first: /{project_id}/...
        path_parts = request.url.path.strip("/").split("/")
        if path_parts and path_parts[0]:
            return path_parts[0]
        
        # Try header-based
        project_id = request.headers.get("X-Project-Id")
        if project_id:
            return project_id
        
        # Try subdomain-based
        host = request.headers.get("host", "")
        if "." in host:
            subdomain = host.split(".")[0]
            if subdomain and subdomain != "www":
                return subdomain
        
        return None
    
    async def get_manifest(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Get manifest with caching"""
        # Try cache first
        if self.redis_client:
            try:
                cache_key = f"manifest:{project_id}"
                cached = await self.redis_client.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception as e:
                logger.warning(f"Cache error: {e}")
        
        # Fetch from Control Tower
        try:
            headers = {}
            if self.config.control_tower_secret:
                headers["X-DSPAI-Client-Secret"] = self.config.control_tower_secret
            
            response = await self.http_client.get(
                f"{self.config.control_tower_url}/manifests/{project_id}?resolve_env=true",
                headers=headers
            )
            
            if response.status_code == 200:
                manifest = response.json()
                
                # Cache it
                if self.redis_client:
                    try:
                        cache_key = f"manifest:{project_id}"
                        await self.redis_client.setex(
                            cache_key,
                            self.config.cache_ttl,
                            json.dumps(manifest)
                        )
                    except Exception as e:
                        logger.warning(f"Cache write error: {e}")
                
                return manifest
        
        except Exception as e:
            logger.error(f"Failed to get manifest: {e}")
        
        return None
    
    async def get_runtime_references(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Get runtime references for modules"""
        refs = {}
        
        # Extract cross-references from manifest
        for module in manifest.get("modules", []):
            cross_refs = module.get("cross_references", {})
            for ref_name, ref_config in cross_refs.items():
                refs[ref_name] = ref_config.get("module_name")
        
        return refs
    
    async def get_status(self) -> Dict[str, Any]:
        """Get service status"""
        status = {
            "service": "dsp-fd2",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "routing_modes": {},
            "metrics_enabled": self.metrics_collector.enabled
        }
        
        # Count projects by routing mode
        for project_id, mode in self.project_routing.items():
            mode_name = mode.value
            if mode_name not in status["routing_modes"]:
                status["routing_modes"][mode_name] = []
            status["routing_modes"][mode_name].append(project_id)
        
        # Add APISIX status if available
        if self.apisix_client:
            try:
                apisix_health = await self.apisix_client.health_check()
                status["apisix"] = apisix_health
            except Exception as e:
                status["apisix"] = {"status": "error", "error": str(e)}
        
        # Add module manager status if available
        if self.module_manager:
            status["modules"] = {
                "loaded": len(self.module_manager.modules),
                "pool_size": self.config.module_pool_size
            }
        
        return status


# FastAPI app with lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await app.state.front_door.initialize()
    
    # Initialize Prometheus instrumentator if available
    if PROMETHEUS_AVAILABLE and app.state.front_door.config.enable_metrics:
        # Create instrumentator with custom configuration
        instrumentator = Instrumentator(
            should_group_status_codes=False,
            should_ignore_untemplated=True,
            should_respect_env_var=True,
            should_instrument_requests_inprogress=True,
            excluded_handlers=["/metrics", "/health", "/status"],
            env_var_name="ENABLE_METRICS",
            inprogress_name="inprogress",
            inprogress_labels=True,
        )
        
        # Add default metrics
        instrumentator.add(
            metrics.requests(
                should_include_handler=True,
                should_include_method=True,
                should_include_status=True,
                metric_namespace="front_door",
                metric_subsystem="http",
            )
        ).add(
            metrics.latency(
                should_include_handler=True,
                should_include_method=True,
                should_include_status=True,
                metric_namespace="front_door",
                metric_subsystem="http",
            )
        )
        
        # Instrument the app
        instrumentator.instrument(app)
        app.state.instrumentator = instrumentator
        
        logger.info("Prometheus instrumentator initialized")
    
    yield
    
    # Shutdown
    await app.state.front_door.shutdown()


# Create FastAPI app
app = FastAPI(
    title="DSP-FD2 Front Door",
    description="Front Door service with intelligent routing",
    version="3.0.0",
    lifespan=lifespan
)

# Initialize unified Front Door service
config = UnifiedFrontDoorConfig(
    control_tower_url=os.getenv("CONTROL_TOWER_URL", "http://localhost:8000"),
    control_tower_secret=os.getenv("CONTROL_TOWER_SECRET"),
    apisix_admin_url=os.getenv("APISIX_ADMIN_URL", "http://apisix:9180"),
    apisix_admin_key=os.getenv("APISIX_ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1"),
    apisix_gateway_url=os.getenv("APISIX_GATEWAY_URL", "http://apisix:9080"),
    module_pool_size=int(os.getenv("MODULE_POOL_SIZE", "10")),
    enable_metrics=os.getenv("ENABLE_METRICS", "true").lower() == "true",
    metrics_port=int(os.getenv("METRICS_PORT", "8081")),
    environment=os.getenv("ENVIRONMENT", "production"),
    redis_url=os.getenv("REDIS_URL"),
    auto_configure_apisix=os.getenv("AUTO_CONFIGURE_APISIX", "false").lower() == "true",
    cache_ttl=int(os.getenv("CACHE_TTL", "300"))
)

app.state.front_door = UnifiedFrontDoorService(config)


# Health and status endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    status = await app.state.front_door.get_status()
    return status


@app.get("/status")
async def service_status():
    """Detailed service status"""
    return await app.state.front_door.get_status()


# Metrics endpoint
@app.get("/metrics")
async def metrics_endpoint():
    """Prometheus metrics endpoint"""
    if not PROMETHEUS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Prometheus metrics are not available")
    
    from prometheus_client import CONTENT_TYPE_LATEST
    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST
    )


# Admin endpoints
@app.post("/admin/sync")
async def sync_manifests():
    """Manually sync manifests from Control Tower"""
    await app.state.front_door.sync_manifests()
    
    return {
        "status": "success",
        "message": "Manifests synced",
        "projects": {
            mode.value: [p for p, m in app.state.front_door.project_routing.items() if m == mode]
            for mode in RoutingMode
        }
    }


@app.post("/admin/configure/{project_id}")
async def configure_project(project_id: str):
    """Configure routing for a specific project"""
    await app.state.front_door.analyze_and_configure_project(project_id)
    
    routing_mode = app.state.front_door.project_routing.get(project_id)
    
    return {
        "project_id": project_id,
        "routing_mode": routing_mode.value if routing_mode else None,
        "status": "configured" if routing_mode else "failed"
    }


@app.get("/admin/projects")
async def list_projects():
    """List all configured projects and their routing modes"""
    projects = {}
    
    for project_id, mode in app.state.front_door.project_routing.items():
        projects[project_id] = {
            "routing_mode": mode.value,
            "apisix_configured": project_id in app.state.front_door.configured_apisix_projects
        }
    
    return {"projects": projects, "total": len(projects)}


@app.get("/admin/apisix/projects/{project_id}/resources")
async def list_project_apisix_resources(project_id: str):
    """List APISIX resources for a project (if using APISIX routing)"""
    if not app.state.front_door.apisix_client:
        raise HTTPException(status_code=503, detail="APISIX not configured")
    
    if app.state.front_door.project_routing.get(project_id) != RoutingMode.APISIX:
        raise HTTPException(status_code=400, detail=f"Project {project_id} not using APISIX routing")
    
    resources = await app.state.front_door.apisix_client.list_project_resources(project_id)
    return resources


@app.get("/admin/apisix/services")
async def list_all_apisix_services():
    """List all APISIX services"""
    if not app.state.front_door.apisix_client:
        raise HTTPException(status_code=503, detail="APISIX not configured")
    
    try:
        services = await app.state.front_door.apisix_client.list_services()
        return {
            "services": services,
            "count": len(services)
        }
    except Exception as e:
        logger.error(f"Failed to list APISIX services: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list services: {str(e)}")


@app.get("/admin/apisix/consumers")
async def list_all_apisix_consumers():
    """List all APISIX consumers"""
    if not app.state.front_door.apisix_client:
        raise HTTPException(status_code=503, detail="APISIX not configured")
    
    try:
        consumers = await app.state.front_door.apisix_client.list_consumers()
        return {
            "consumers": consumers,
            "count": len(consumers)
        }
    except Exception as e:
        logger.error(f"Failed to list APISIX consumers: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list consumers: {str(e)}")


@app.delete("/admin/apisix/projects/{project_id}/resources")
async def cleanup_project_apisix_resources(project_id: str):
    """Clean up all APISIX resources for a project"""
    if not app.state.front_door.apisix_client:
        raise HTTPException(status_code=503, detail="APISIX not configured")
    
    try:
        result = await app.state.front_door.apisix_client.cleanup_project_resources(project_id)
        return result
    except Exception as e:
        logger.error(f"Failed to cleanup project resources: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup resources: {str(e)}")


# JWT Token endpoint with metrics
@app.post("/{project_id}/{jwt_module_name}/token")
async def get_jwt_token(
    project_id: str,
    jwt_module_name: str,
    request: Request
):
    """
    Get JWT token using configuration from Control Tower manifest
    
    URL Pattern: /{project_id}/{jwt_module_name}/token
    Example: /sas2py/simple-auth/token
    
    Request Body:
    {
        "username": "user",
        "password": "password"
    }
    """
    start_time = time.time()
    
    try:
        # Get manifest from Control Tower with environment resolution
        headers = {}
        if app.state.front_door.config.control_tower_secret:
            headers["X-DSPAI-Client-Secret"] = app.state.front_door.config.control_tower_secret
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{app.state.front_door.config.control_tower_url}/manifests/{project_id}?resolve_env=true",
                headers=headers
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
            
            manifest = response.json()
        
        # Find the JWT module by name
        jwt_module = None
        modules = manifest.get("modules", [])
        
        # Debug: log all modules with their configs
        logger.info(f"Looking for JWT module '{jwt_module_name}' in {len(modules)} modules")
        for idx, module in enumerate(modules):
            mod_name = module.get('name')
            mod_type = module.get('module_type')
            logger.info(f"  Module {idx}: name={mod_name}, type={mod_type}")
            
            # Log config keys for debugging
            if mod_name == jwt_module_name:
                config_keys = list(module.get('config', {}).keys())
                logger.info(f"    Config keys: {config_keys}")
            
            if mod_name == jwt_module_name and mod_type == "jwt_config":
                jwt_module = module
                logger.info(f"  [OK] Found matching JWT module at index {idx}")
                break
        
        if not jwt_module:
            raise HTTPException(
                status_code=404, 
                detail=f"JWT module '{jwt_module_name}' not found in project {project_id}"
            )
        
        # Get JWT service URL from module config
        jwt_config = jwt_module.get("config", {})
        jwt_service_url = jwt_config.get("service_url")
        
        # Debug logging
        logger.info(f"JWT module config: {jwt_config}")
        logger.info(f"JWT service URL: {jwt_service_url}")
        
        if not jwt_service_url:
            raise HTTPException(
                status_code=500,
                detail=f"JWT service URL not configured in module {jwt_module_name}. Config: {jwt_config}"
            )
        
        # Get request body (username/password)
        body = await request.json()
        
        # Prepare api_key_config (exclude service_url as it's not needed by JWT service)
        api_key_config = {k: v for k, v in jwt_config.items() if k != "service_url"}
        
        # Debug: Log the api_key_config being sent
        logger.info(f"Sending api_key_config to JWT service:")
        logger.info(f"  Keys: {list(api_key_config.keys())}")
        if 'jwe_config' in api_key_config:
            logger.info(f"  JWE config present: {api_key_config['jwe_config']}")
        else:
            logger.info(f"  No JWE config found in api_key_config")
        
        # Prepare request to JWT service with inline api_key_config
        jwt_request = {
            "username": body.get("username"),
            "password": body.get("password"),
            "api_key_config": api_key_config
        }
        
        # Forward to JWT service
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{jwt_service_url}/token",
                json=jwt_request
            )
            
            duration = time.time() - start_time
            
            # Record JWT-specific metrics
            app.state.front_door.metrics_collector.record_jwt_token_metrics(
                project_id=project_id,
                jwt_module_name=jwt_module_name,
                status_code=response.status_code,
                duration=duration
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.json() if response.headers.get("content-type") == "application/json" else response.text
                )
            
            return response.json()
    
    except HTTPException as e:
        duration = time.time() - start_time
        # Record error metrics for JWT
        app.state.front_door.metrics_collector.record_jwt_token_metrics(
            project_id=project_id,
            jwt_module_name=jwt_module_name,
            status_code=e.status_code,
            duration=duration
        )
        raise
    
    except Exception as e:
        duration = time.time() - start_time
        # Record error metrics for JWT
        app.state.front_door.metrics_collector.record_jwt_token_metrics(
            project_id=project_id,
            jwt_module_name=jwt_module_name,
            status_code=500,
            duration=duration
        )
        logger.error(f"Error getting JWT token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get JWT token: {str(e)}")


# Catch-all route for request handling
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def route_request(request: Request):
    """Route all requests based on project configuration"""
    return await app.state.front_door.handle_request(request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("front_door:app", host="0.0.0.0", port=8080, reload=True)
