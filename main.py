#!/usr/bin/env python3
"""
lm9dem - ABG Migration Dashboard Service
A FastAPI service providing web interface for Alpha-Beta-Gamma migration management
"""

from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import redis
import subprocess
import json
import os
import logging
import pickle
import base64
import uuid
import time
from urllib.parse import quote
from typing import Dict, List, Optional
from pydantic import BaseModel
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_DB = int(os.getenv('REDIS_DB', '2'))
NAMESPACE = os.getenv('NAMESPACE', 'system-experio')
INGRESS = os.getenv('INGRESS', 'system-ingress')

# Infrastructure Configuration (NO DEFAULTS - FAIL FAST)
def get_required_env(key: str) -> str:
    """Get required environment variable or fail fast with NO fallback"""
    value = os.getenv(key)
    if not value:
        raise RuntimeError(f"CRITICAL: Required configuration {key} is missing. Application cannot start.")
    return value

# LoadBalancer IPs
FULL_ACCESS_LB_IP = get_required_env('FULL_ACCESS_LB_IP')
BACKUP_ONLY_LB_IP = get_required_env('BACKUP_ONLY_LB_IP')

# Deployment Server
MS_SERVER_IP = get_required_env('MS_SERVER_IP')
CP_SERVER_IP = get_required_env('CP_SERVER_IP')

# Domain Configuration
MAIN_DOMAIN = get_required_env('MAIN_DOMAIN')
DOWNLOADS_DOMAIN = get_required_env('DOWNLOADS_DOMAIN')
MAILING_DOMAIN = get_required_env('MAILING_DOMAIN')

# Ceph Storage Paths
CEPH_DATA_PATH = get_required_env('CEPH_DATA_PATH')
CEPH_BACKUP_PATH = get_required_env('CEPH_BACKUP_PATH')
DOWNLOADS_BASE_PATH = get_required_env('DOWNLOADS_BASE_PATH')
TOKENS_PATH = get_required_env('TOKENS_PATH')

# Script Paths
BACKUP_SCRIPT_PATH = get_required_env('BACKUP_SCRIPT_PATH')
DISCOVERY_SCRIPT_PATH = get_required_env('DISCOVERY_SCRIPT_PATH')

# SSH Configuration
SSH_USERNAME = get_required_env('SSH_USERNAME')

# Email Configuration
ADMIN_EMAIL = get_required_env('ADMIN_EMAIL')
MAILING_SERVICE_URL = get_required_env('MAILING_SERVICE_URL')
MAILING_TOKEN = get_required_env('MAILING_TOKEN')

# Backup system configuration
def load_trusted_emails():
    """Load trusted emails from ConfigMap"""
    try:
        emails_file = "/app/config/emails/emails.properties"
        trusted_emails = {}
        trusted_email_list = []
        
        if os.path.exists(emails_file):
            with open(emails_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        name, email = line.split('=', 1)
                        trusted_emails[email.strip()] = name.strip()
                        trusted_email_list.append(email.strip())
            logger.info(f"Loaded {len(trusted_emails)} trusted emails from ConfigMap")
        else:
            logger.warning("Trusted emails ConfigMap not found - no trusted emails configured")
        
        return trusted_emails, trusted_email_list
    except Exception as e:
        logger.error(f"Failed to load trusted emails: {e}")
        return {}, []

# Load trusted emails on startup
TRUSTED_EMAILS_DICT, TRUSTED_EMAILS = load_trusted_emails()

logger.info(f"Configuration loaded - Admin: {ADMIN_EMAIL}, Mailing URL: {MAILING_SERVICE_URL}")

app = FastAPI(title="lm9dem", description="ABG Migration Dashboard", version="0.1.0")

# Security functions
def is_internal_ip(ip: str) -> bool:
    """Check if IP address is from internal network"""
    if not ip:
        return False
    return ip.startswith(("10.", "172.", "192.168.", "127."))

def validate_host_access(host: str, path: str, client_ip: str) -> bool:
    """Validate access based on host and path"""
    # Private domains - require internal IP
    private_domains = [f"backup.{MAIN_DOMAIN}", f"lm9dem.{MAIN_DOMAIN}"]
    if host in private_domains:
        return is_internal_ip(client_ip)
    
    # Default: allow for now (existing functionality)
    return True

# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    host = request.headers.get("host", "")
    path = request.url.path
    client_ip = request.client.host
    
    # Allow health checks from internal IPs (Kubernetes probes) - no logging
    if path == "/health":
        response = await call_next(request)
        return response
    
    # Access Level 1: {FULL_ACCESS_LB_IP} - Full access to everything (minimal logging)
    if host == FULL_ACCESS_LB_IP:
        # Only log non-routine requests (not API polling)
        if not path.startswith("/api/"):
            logger.info(f"Full access via LoadBalancer: ip={client_ip}, path={path}")
        # No restrictions - allow everything
        pass
    
    # Access Level 2: {BACKUP_ONLY_LB_IP} - Only /backup access with auto-redirect
    elif host == BACKUP_ONLY_LB_IP:
        # Auto-redirect root path to /backup
        if path == "/":
            logger.info(f"Backup LoadBalancer - redirecting root to /backup: ip={client_ip}")
            return RedirectResponse(url="/backup", status_code=302)
        
        if (path.startswith("/backup") or 
            path.startswith("/api/backup") or 
            path.startswith("/api/databases") or 
            path.startswith("/static/") or 
            path == "/health"):
            # Only log page loads, not API polling
            if not path.startswith("/api/"):
                logger.info(f"Backup access via LoadBalancer: ip={client_ip}, path={path}")
            # Allow backup dashboard and required API endpoints
            pass
        else:
            logger.warning(f"Backup LoadBalancer - blocked path: {path}, ip={client_ip}")
            return Response("Access restricted to backup functionality only", status_code=403, media_type="text/plain")
    
    # Access Level 3: {DOWNLOADS_DOMAIN} - Only download access
    elif host == DOWNLOADS_DOMAIN:
        # Only allow exact token-based download URLs, nothing else
        if path.startswith("/downloads/") and len(path) > 11:  # "/downloads/" + token
            # Validate token format (UUID-like + timestamp)
            token = path[11:]  # Remove "/downloads/" prefix
            if len(token) >= 40 and "_" in token:  # Basic token validation
                # Allow the request to proceed to the download endpoint for validation
                logger.info(f"Downloads domain access: token={token[:8]}..., ip={client_ip}")
                pass
            else:
                logger.warning(f"Downloads domain - invalid token format: {token[:20]}..., ip={client_ip}")
                return Response("Invalid download link", status_code=404, media_type="text/plain")
        else:
            # Block any other path on downloads domain
            logger.warning(f"Downloads domain - blocked path: {path}, ip={client_ip}")
            return Response("Not found", status_code=404, media_type="text/plain")
    
    # Any other host - deny access
    else:
        logger.warning(f"Access denied - unknown host: host={host}, path={path}, ip={client_ip}")
        return Response("Access denied", status_code=403, media_type="text/plain")
    
    response = await call_next(request)
    return response

# Ensure downloads directory structure exists with proper permissions
def ensure_downloads_directories():
    """Ensure downloads directories exist with proper permissions"""
    directories = [
        DOWNLOADS_BASE_PATH,
        f"{DOWNLOADS_BASE_PATH}/files", 
        f"{DOWNLOADS_BASE_PATH}/tokens", 
        f"{DOWNLOADS_BASE_PATH}/jobs"
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, mode=0o755, exist_ok=True)
            # Verify we can write to the directory
            test_file = os.path.join(directory, ".write_test")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            logger.info(f"Directory ready: {directory}")
        except Exception as e:
            logger.error(f"Failed to setup directory {directory}: {e}")
            # Don't fail startup, but log the issue
            
# Setup downloads directories
ensure_downloads_directories()

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("Starting up application...")
    ensure_downloads_directories()
    logger.info("Application startup complete")

# Templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic models
class DatabaseInfo(BaseModel):
    name: str
    version: str
    updated: Optional[str] = None

class SystemStatus(BaseModel):
    alpha_replicas: int
    beta_replicas: int
    gamma_replicas: int
    alpha_image: str
    beta_image: str
    gamma_image: str
    redis_status: str

class DatabaseVersionUpdate(BaseModel):
    version: str

# Redis helper class (ported from bash script)
class RedisHelper:
    def __init__(self):
        self.redis_client = None
        self._connect()
    
    def _connect(self):
        try:
            self.redis_client = redis.StrictRedis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Test connection
            self.redis_client.ping()
            logger.info(f"Connected to Redis: {REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis_client = None
    
    def get(self, key: str) -> Optional[str]:
        try:
            if not self.redis_client:
                self._connect()
            return self.redis_client.get(key)
        except Exception as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            return None
    
    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        try:
            if not self.redis_client:
                self._connect()
            return self.redis_client.set(key, value, ex=ex)
        except Exception as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        try:
            if not self.redis_client:
                self._connect()
            return bool(self.redis_client.delete(key))
        except Exception as e:
            logger.error(f"Redis DELETE error for key {key}: {e}")
            return False
    
    def keys(self, pattern: str) -> List[str]:
        try:
            if not self.redis_client:
                self._connect()
            return self.redis_client.keys(pattern)
        except Exception as e:
            logger.error(f"Redis KEYS error for pattern {pattern}: {e}")
            return []
    
    def scan_delete(self, pattern: str) -> int:
        try:
            if not self.redis_client:
                self._connect()
            count = 0
            cursor = 0
            while True:
                cursor, keys = self.redis_client.scan(cursor, match=pattern, count=100)
                if keys:
                    count += self.redis_client.delete(*keys)
                if cursor == 0:
                    break
            return count
        except Exception as e:
            logger.error(f"Redis SCAN_DELETE error for pattern {pattern}: {e}")
            return 0

    def get_active_sessions_count(self) -> int:
        """Safely count active user sessions in Redis DB 1 without modifying them"""
        try:
            # Create a separate connection to DB 1 (sessions database)
            sessions_client = redis.StrictRedis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=1,  # DB 1 is for user sessions
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Use DBSIZE command which is safe and doesn't modify data
            session_count = sessions_client.dbsize()
            logger.info(f"Active sessions count: {session_count}")
            return session_count
        except Exception as e:
            logger.error(f"Failed to count active sessions: {e}")
            return 0

    def ping(self) -> bool:
        """Check if Redis connection is alive"""
        try:
            if not self.redis_client:
                self._connect()
            return self.redis_client.ping()
        except Exception as e:
            logger.error(f"Redis PING failed: {e}")
            return False

    def analyze_sessions(self) -> Dict:
        """Analyze session data from Redis DB 1 safely"""
        try:
            # Connect to sessions database (DB 1)
            sessions_client = redis.StrictRedis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=1,
                decode_responses=False,  # Keep binary for pickle
                socket_timeout=10,
                socket_connect_timeout=5
            )
            
            total_keys = sessions_client.dbsize()
            active_sessions = 0
            databases = {}
            
            cursor = 0
            while True:
                cursor, keys = sessions_client.scan(cursor, count=50)
                
                for key in keys:
                    try:
                        # Check if key exists and has TTL (active)
                        ttl = sessions_client.ttl(key)
                        if ttl > 0:
                            active_sessions += 1
                            
                            # Try to decode session data safely
                            session_data = sessions_client.get(key)
                            if session_data:
                                try:
                                    # Safely decode pickle data
                                    decoded = pickle.loads(session_data)
                                    if isinstance(decoded, dict):
                                        db_name = decoded.get('db', 'unknown') or 'unknown'
                                        user_id = decoded.get('uid', 'unknown') or 'unknown'
                                        login = decoded.get('login', 'unknown') or 'unknown'
                                        
                                        if db_name not in databases:
                                            databases[db_name] = {
                                                'sessions': [],
                                                'user_count': set()
                                            }
                                        
                                        databases[db_name]['sessions'].append({
                                            'key': key.decode('utf-8') if isinstance(key, bytes) else str(key),
                                            'user_id': user_id,
                                            'login': login,
                                            'ttl': ttl
                                        })
                                        databases[db_name]['user_count'].add(user_id)
                                        
                                except (pickle.UnpicklingError, AttributeError) as e:
                                    # Skip corrupted session data
                                    logger.warning(f"Could not decode session {key}: {e}")
                                    continue
                    except Exception as e:
                        logger.warning(f"Error analyzing session {key}: {e}")
                        continue
                
                if cursor == 0:
                    break
            
            # Convert sets to counts
            for db_name in databases:
                databases[db_name]['user_count'] = len(databases[db_name]['user_count'])
            
            return {
                'total_keys': total_keys,
                'active_sessions': active_sessions,
                'databases': databases,
                'unique_users': sum(db['user_count'] for db in databases.values())
            }
            
        except Exception as e:
            logger.error(f"Session analysis failed: {e}")
            return {
                'total_keys': 0,
                'active_sessions': 0,
                'databases': {},
                'unique_users': 0
            }

    def get_database_distribution(self, databases: List[str] = None) -> Dict[str, int]:
        """Get database distribution across Alpha-Beta-Gamma deployments"""
        try:
            if not self.redis_client:
                self._connect()
            
            distribution = {
                'ALPHA': 0,
                'BETA': 0,
                'GAMMA': 0
            }
            
            # If no databases provided, we can't count properly
            if databases is None:
                logger.warning("No databases provided for distribution count")
                return distribution
            
            logger.info(f"Checking distribution for {len(databases)} actual databases")
            
            # Count only existing databases
            for db in databases:
                version = self.get(f'db_version:{db}')
                if version:
                    version_upper = version.upper()
                    if version_upper in distribution:
                        distribution[version_upper] += 1
                else:
                    # Default to ALPHA for unversioned databases
                    distribution['ALPHA'] += 1
            
            logger.info(f"Database distribution: {distribution}")
            return distribution
            
        except Exception as e:
            logger.error(f"Failed to get database distribution: {e}")
            return {
                'ALPHA': 0,
                'BETA': 0,
                'GAMMA': 0
            }
    
    def cleanup_stale_database_versions(self, existing_databases: List[str]) -> int:
        """Remove stale db_version entries that don't correspond to existing databases"""
        try:
            if not self.redis_client:
                self._connect()
            
            # Get all db_version keys
            db_keys = self.keys('db_version:*')
            stale_count = 0
            
            for key in db_keys:
                # Extract database name from key (remove 'db_version:' prefix)
                db_name = key[11:]  # len('db_version:') = 11
                
                # If this database doesn't exist anymore, remove the Redis key
                if db_name not in existing_databases:
                    self.redis_client.delete(key)
                    stale_count += 1
                    logger.info(f"Removed stale db_version entry for: {db_name}")
            
            logger.info(f"Cleanup completed: removed {stale_count} stale entries")
            return stale_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup stale database versions: {e}")
            return 0

    def set_company_name(self, database: str, company_name: str) -> bool:
        """Set company name for a database"""
        try:
            if not self.redis_client:
                self._connect()
            
            key = f"company_name:{database}"
            return self.set(key, company_name)
        except Exception as e:
            logger.error(f"Failed to set company name for {database}: {e}")
            return False

    def get_company_name(self, database: str) -> str:
        """Get company name for a database"""
        try:
            if not self.redis_client:
                self._connect()
            
            key = f"company_name:{database}"
            company_name = self.get(key)
            return company_name if company_name else "Unknown"
        except Exception as e:
            logger.error(f"Failed to get company name for {database}: {e}")
            return "Unknown"

    def cleanup_stale_company_names(self, existing_databases: List[str]) -> int:
        """Remove stale company_name entries that don't correspond to existing databases"""
        try:
            if not self.redis_client:
                self._connect()
            
            # Get all company_name keys
            company_keys = self.keys('company_name:*')
            stale_count = 0
            
            for key in company_keys:
                # Extract database name from key (remove 'company_name:' prefix)
                db_name = key[13:]  # len('company_name:') = 13
                
                # If this database doesn't exist anymore, remove the Redis key
                if db_name not in existing_databases:
                    self.redis_client.delete(key)
                    stale_count += 1
                    logger.info(f"Removed stale company_name entry for: {db_name}")
            
            logger.info(f"Company cleanup completed: removed {stale_count} stale entries")
            return stale_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup stale company names: {e}")
            return 0

    def start_deployment(self, user="unknown"):
        """Start a deployment and lock it"""
        try:
            # Check if deployment is already running
            if self.redis_client.exists('deployment:active'):
                current_info = self.redis_client.hgetall('deployment:active')
                return {
                    "success": False, 
                    "error": f"Deployment already in progress by {current_info.get('user', 'unknown')}",
                    "started_at": current_info.get('started_at', ''),
                    "user": current_info.get('user', 'unknown')
                }
            
            # Set deployment lock with expiration (30 minutes max)
            deployment_info = {
                "user": user,
                "started_at": datetime.now().isoformat(),
                "status": "running"
            }
            self.redis_client.hset('deployment:active', mapping=deployment_info)
            self.redis_client.expire('deployment:active', 1800)  # 30 minutes
            
            return {"success": True, "message": "Deployment started"}
            
        except Exception as e:
            logger.error(f"Error starting deployment: {e}")
            return {"success": False, "error": str(e)}
    
    def finish_deployment(self, result_data=None):
        """Finish deployment and clear lock"""
        try:
            # Store deployment result
            if result_data:
                self.redis_client.hset('deployment:last_result', mapping={
                    "finished_at": datetime.now().isoformat(),
                    "success": str(result_data.get('success', False)),
                    "message": result_data.get('message', ''),
                    "output": result_data.get('output', '')[:5000]  # Limit size
                })
                self.redis_client.expire('deployment:last_result', 86400)  # 24 hours
            
            # Clear active deployment lock
            self.redis_client.delete('deployment:active')
            
        except Exception as e:
            logger.error(f"Error finishing deployment: {e}")
    
    def get_deployment_status(self):
        """Get current deployment status"""
        try:
            if self.redis_client.exists('deployment:active'):
                info = self.redis_client.hgetall('deployment:active')
                return {
                    "active": True,
                    "user": info.get('user', 'unknown'),
                    "started_at": info.get('started_at', ''),
                    "status": info.get('status', 'running')
                }
            else:
                # Check last result
                if self.redis_client.exists('deployment:last_result'):
                    result = self.redis_client.hgetall('deployment:last_result')
                    return {
                        "active": False,
                        "last_result": {
                            "finished_at": result.get('finished_at', ''),
                            "success": result.get('success', 'false') == 'true',
                            "message": result.get('message', '')
                        }
                    }
                else:
                    return {"active": False, "last_result": None}
                    
        except Exception as e:
            logger.error(f"Error getting deployment status: {e}")
            return {"active": False, "error": str(e)}


# Kubernetes helper class (ported from bash script)
class KubernetesHelper:
    def __init__(self):
        self.cached_alpha_pod = None
    
    def run_kubectl(self, args: List[str]) -> Optional[str]:
        """Execute kubectl command and return output"""
        try:
            cmd = ['kubectl'] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"kubectl failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            logger.error("kubectl command timed out")
            return None
        except Exception as e:
            logger.error(f"kubectl error: {e}")
            return None
    
    def get_cached_alpha_pod(self) -> Optional[str]:
        """Get cached alpha pod, refresh if needed"""
        # Check if cached pod is still valid
        if self.cached_alpha_pod:
            result = self.run_kubectl([
                'get', 'pod', self.cached_alpha_pod,
                '-n', NAMESPACE, '--no-headers'
            ])
            if result:
                return self.cached_alpha_pod
        
        # Get fresh pod
        result = self.run_kubectl([
            'get', 'pods', '-n', NAMESPACE,
            '-l', 'app=system-alpha',
            '--field-selector=status.phase=Running',
            '-o', 'jsonpath={.items[0].metadata.name}'
        ])
        
        if result:
            self.cached_alpha_pod = result
            return result
        return None
    
    def get_deployment_replicas(self, deployment_name: str) -> int:
        """Get deployment replica count"""
        result = self.run_kubectl([
            'get', 'deployment', deployment_name,
            '-n', NAMESPACE,
            '-o', 'jsonpath={.spec.replicas}'
        ])
        try:
            return int(result) if result else 0
        except (ValueError, TypeError):
            return 0
    
    def get_deployment_image(self, deployment_name: str) -> str:
        """Get deployment image - specifically the system container image"""
        # For ALPHA: get first container (system)
        # For BETA/GAMMA: get the system container (second container after sidecar-proxy)
        if deployment_name == "system-alpha":
            jsonpath = '{.spec.template.spec.containers[0].image}'
        else:
            # BETA and GAMMA have sidecar proxy first, system container second
            jsonpath = '{.spec.template.spec.containers[1].image}'
            
        result = self.run_kubectl([
            'get', 'deployment', deployment_name,
            '-n', NAMESPACE,
            '-o', f'jsonpath={jsonpath}'
        ])
        return result or "unknown"
    
    def get_ingress_status(self, ingress_name: str) -> Dict:
        """Get ingress status information"""
        # Get ingress basic info
        ingress_info = self.run_kubectl([
            'get', 'ingress', ingress_name,
            '-n', NAMESPACE,
            '-o', 'json'
        ])
        
        if not ingress_info:
            return {"name": ingress_name, "status": "not-found", "hosts": [], "class": "unknown", "target_service": "none"}
        
        try:
            import json
            ingress_data = json.loads(ingress_info)
            
            # Extract key information
            is_ready = bool(ingress_data.get("status", {}).get("loadBalancer", {}).get("ingress"))
            status = "ready" if is_ready else "pending"
            
            # Get hosts
            hosts = []
            target_services = set()
            
            for rule in ingress_data.get("spec", {}).get("rules", []):
                if "host" in rule:
                    hosts.append(rule["host"])
                
                # Check which services are being routed to
                for path in rule.get("http", {}).get("paths", []):
                    backend = path.get("backend", {})
                    if "service" in backend:
                        service_name = backend["service"].get("name", "")
                        if service_name.startswith("system-"):
                            target_services.add(service_name.replace("system-", ""))
            
            # Determine primary target
            if "alpha" in target_services:
                primary_target = "alpha"
            elif "beta" in target_services:
                primary_target = "beta" 
            elif "gamma" in target_services:
                primary_target = "gamma"
            elif len(target_services) > 0:
                primary_target = list(target_services)[0]
            else:
                primary_target = "unknown"
            
            # Get ingress class
            ingress_class = ingress_data.get("spec", {}).get("ingressClassName", "unknown")
            
            # Get load balancer info
            lb_ingress = ingress_data.get("status", {}).get("loadBalancer", {}).get("ingress", [])
            external_ips = [ing.get("ip", ing.get("hostname", "")) for ing in lb_ingress]
            
            return {
                "name": ingress_name,
                "status": status,
                "hosts": hosts,
                "class": ingress_class,
                "external_ips": external_ips,
                "target_service": primary_target,
                "all_targets": list(target_services),
                "path_count": len(ingress_data.get("spec", {}).get("rules", [])),
                "is_active": is_ready
            }
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse ingress info: {e}")
            return {"name": ingress_name, "status": "error", "hosts": [], "class": "unknown", "target_service": "error"}
    
    def exec_in_alpha_pod(self, command: List[str]) -> Optional[str]:
        """Execute command in alpha pod"""
        pod = self.get_cached_alpha_pod()
        if not pod:
            return None
        
        kubectl_args = [
            'exec', '-n', NAMESPACE, pod, '-c', 'system', '--'
        ] + command
        
        return self.run_kubectl(kubectl_args)

# Initialize helpers
redis_helper = RedisHelper()
k8s_helper = KubernetesHelper()

# Utility functions
# Database cache to avoid frequent discoveries
DATABASE_CACHE = {
    "databases": [],
    "last_updated": None,
    "cache_ttl": 300  # 5 minutes
}

def get_last_discovery_time() -> str:
    """Get formatted last discovery time"""
    if DATABASE_CACHE["last_updated"]:
        dt = datetime.fromtimestamp(DATABASE_CACHE["last_updated"])
        return dt.strftime("%d/%m/%y %H:%M:%S")
    return "Never"

def discover_databases() -> List[str]:
    """Discover databases using click-odoo-listdb in alpha pod with caching"""
    import time
    
    # Check cache first
    now = time.time()
    if (DATABASE_CACHE["last_updated"] and 
        DATABASE_CACHE["databases"] and 
        now - DATABASE_CACHE["last_updated"] < DATABASE_CACHE["cache_ttl"]):
        logger.info(f"Using cached database list ({len(DATABASE_CACHE['databases'])} databases)")
        return DATABASE_CACHE["databases"]
    
    logger.info("Discovering databases from PostgreSQL...")
    command = [
        'bash', '-c',
        '''
        # Create temporary odoo config with database connection info
        cat > /tmp/odoo.conf << EOF
[options]
db_host = $HOST
db_user = $USER
db_password = $PASSWORD
EOF
        
        # Try click-odoo-listdb first
        if command -v click-odoo-listdb >/dev/null 2>&1; then
            click-odoo-listdb --config=/tmp/odoo.conf 2>/dev/null
        else
            # Fallback to direct PostgreSQL query
            export PGPASSWORD="$PASSWORD"
            psql -h "$HOST" -U "$USER" -t -c "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1') ORDER BY datname;" 2>/dev/null | grep -E '^[a-zA-Z0-9_-]+$' | sed 's/^[ \t]*//;s/[ \t]*$//'
        fi
        '''
    ]
    
    result = k8s_helper.exec_in_alpha_pod(command)
    if result:
        databases = [db.strip() for db in result.split('\n') if db.strip() and not db.startswith('ERROR')]
        # Update cache
        DATABASE_CACHE["databases"] = databases
        DATABASE_CACHE["last_updated"] = now
        logger.info(f"Discovered {len(databases)} databases (cached for {DATABASE_CACHE['cache_ttl']}s)")
        return databases
    
    logger.warning("Database discovery failed, returning cached data if available")
    return DATABASE_CACHE["databases"] or []

def discover_databases_hard() -> List[str]:
    """Force database discovery bypassing cache"""
    import time
    
    logger.info("Forcing hard database discovery from PostgreSQL...")
    command = [
        'bash', '-c',
        '''
        # Create temporary odoo config with database connection info
        cat > /tmp/odoo.conf << EOF
[options]
db_host = $HOST
db_user = $USER
db_password = $PASSWORD
EOF
        
        # Try click-odoo-listdb first
        if command -v click-odoo-listdb >/dev/null 2>&1; then
            click-odoo-listdb --config=/tmp/odoo.conf 2>/dev/null
        else
            # Fallback to direct PostgreSQL query
            export PGPASSWORD="$PASSWORD"
            psql -h "$HOST" -U "$USER" -t -c "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1') ORDER BY datname;" 2>/dev/null | grep -E '^[a-zA-Z0-9_-]+$' | sed 's/^[ \t]*//;s/[ \t]*$//'
        fi
        '''
    ]
    
    result = k8s_helper.exec_in_alpha_pod(command)
    if result:
        databases = [db.strip() for db in result.split('\n') if db.strip() and not db.startswith('ERROR')]
        # Update cache with fresh data
        now = time.time()
        DATABASE_CACHE["databases"] = databases
        DATABASE_CACHE["last_updated"] = now
        logger.info(f"Hard discovery completed: {len(databases)} databases found and cached")
        return databases
    
    logger.error("Hard database discovery failed")
    return DATABASE_CACHE["databases"] or []

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/backup", response_class=HTMLResponse)
async def backup_dashboard(request: Request):
    """Backup management dashboard"""
    return templates.TemplateResponse("backup-dashboard.html", {"request": request})

@app.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request):
    """Sessions analytics page"""
    return templates.TemplateResponse("sessions.html", {"request": request})

@app.get("/logs", response_class=HTMLResponse) 
async def logs_page(request: Request):
    """Migration logs page"""
    return templates.TemplateResponse("logs.html", {"request": request})

@app.get("/api/sessions/analysis", response_class=HTMLResponse)
async def get_sessions_analysis(request: Request):
    """Get session analysis data"""
    analysis = redis_helper.analyze_sessions()
    
    html_content = f"""
    <div class="row mb-4">
        <div class="col-md-3 mb-3">
            <div class="card border-primary">
                <div class="card-body text-center">
                    <h5 class="card-title text-primary">Total Keys</h5>
                    <h2 class="display-6">{analysis['total_keys']}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3 mb-3">
            <div class="card border-success">
                <div class="card-body text-center">
                    <h5 class="card-title text-success">Active Sessions</h5>
                    <h2 class="display-6">{analysis['active_sessions']}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3 mb-3">
            <div class="card border-info">
                <div class="card-body text-center">
                    <h5 class="card-title text-info">Unique Users</h5>
                    <h2 class="display-6">{analysis['unique_users']}</h2>
                </div>
            </div>
        </div>
        <div class="col-md-3 mb-3">
            <div class="card border-warning">
                <div class="card-body text-center">
                    <h5 class="card-title text-warning">Databases</h5>
                    <h2 class="display-6">{len(analysis['databases'])}</h2>
                </div>
            </div>
        </div>
    </div>
    
    <div class="row">
        <div class="col-12">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead class="table-dark">
                        <tr>
                            <th>Database</th>
                            <th>Sessions</th>
                            <th>Users</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for db_name, db_data in analysis['databases'].items():
        # Skip databases with invalid names
        if not db_name or db_name == 'unknown':
            continue
            
        session_count = len(db_data['sessions'])
        user_count = db_data['user_count']
        
        # Create safe ID for HTML - more unique transformation
        safe_db_id = db_name.replace('_', '-').replace('.', 'dot').replace(' ', 'space').replace('/', 'slash')
        # Add length suffix to ensure uniqueness
        safe_db_id = f"{safe_db_id}-{len(db_name)}"
        
        html_content += f"""
                        <tr>
                            <td><strong>{db_name}</strong></td>
                            <td><span class="badge bg-primary">{session_count}</span></td>
                            <td><span class="badge bg-success">{user_count}</span></td>
                            <td>
                                <button class="btn btn-sm btn-outline-info view-sessions-btn" 
                                        data-db-name="{db_name}"
                                        data-target-id="details-{safe_db_id}-td">
                                    <i class="bi bi-eye"></i> View Sessions
                                </button>
                                <div id="loading-{safe_db_id}" class="htmx-indicator">
                                    <small class="text-muted">Loading...</small>
                                </div>
                            </td>
                        </tr>
                        <tr id="details-{safe_db_id}" style="display: none;">
                            <td id="details-{safe_db_id}-td" colspan="4" class="p-0">
                            </td>
                        </tr>
        """
    
    html_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """
    
    return HTMLResponse(content=html_content)

@app.get("/api/sessions/database/{database_name}", response_class=HTMLResponse)
async def get_database_sessions(database_name: str, request: Request):
    """Get detailed session information for a specific database"""
    analysis = redis_helper.analyze_sessions()
    
    if database_name not in analysis['databases']:
        return HTMLResponse(content='<p class="text-danger">Database not found</p>')
    
    db_data = analysis['databases'][database_name]
    sessions = db_data['sessions']
    
    html_content = f"""
    <div class="card mt-2 mb-2">
        <div class="card-header bg-light">
            <h6 class="mb-0"><i class="bi bi-database"></i> {database_name} - Session Details ({len(sessions)} sessions)</h6>
        </div>
        <div class="card-body p-2">
            <div class="table-responsive">
                <table class="table table-striped table-bordered mb-0">
                    <thead class="table-dark">
                        <tr>
                            <th style="width: 10%">User ID</th>
                            <th style="width: 30%">Login</th>
                            <th style="width: 45%">Session Key</th>
                            <th style="width: 15%">TTL</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for session in sessions:
        ttl_hours = session['ttl'] // 3600
        ttl_minutes = (session['ttl'] % 3600) // 60
        
        html_content += f"""
                        <tr>
                            <td><span class="badge bg-primary">{session['user_id']}</span></td>
                            <td><small class="text-muted">{session['login']}</small></td>
                            <td><small class="font-monospace text-muted">{session['key'][:40]}...</small></td>
                            <td><span class="badge bg-success">{ttl_hours}h {ttl_minutes}m</span></td>
                        </tr>
        """
    
    html_content += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """
    
    return HTMLResponse(content=html_content)

@app.get("/api/system/status", response_class=HTMLResponse)
async def get_system_status(request: Request):
    """Get overall system status"""
    alpha_replicas = k8s_helper.get_deployment_replicas("system-alpha")
    beta_replicas = k8s_helper.get_deployment_replicas("system-beta")
    gamma_replicas = k8s_helper.get_deployment_replicas("system-gamma")
    
    alpha_image = k8s_helper.get_deployment_image("system-alpha")
    beta_image = k8s_helper.get_deployment_image("system-beta")
    gamma_image = k8s_helper.get_deployment_image("system-gamma")
    
    # Get ingress status
    ingress_status = k8s_helper.get_ingress_status(INGRESS)
    
    # Check Redis status and get active sessions count
    redis_status = "connected" if redis_helper.redis_client else "disconnected"
    active_sessions = redis_helper.get_active_sessions_count()
    
    # Return HTML for htmx
    html_content = f"""
    <div class="col-md-3 mb-3">
        <div class="card deployment-card border-primary">
            <div class="card-body">
                <h5 class="card-title text-primary">
                    <span class="status-indicator {'status-running' if alpha_replicas > 0 else 'status-stopped'}"></span>
                    ALPHA (Production)
                </h5>
                <p class="card-text">
                    <strong>Replicas:</strong> <span class="badge bg-primary">{alpha_replicas}</span><br>
                    <strong>Image:</strong> <span class="text-muted">{alpha_image.split('/')[-1] if alpha_image else 'unknown'}</span>
                </p>
            </div>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="card deployment-card border-warning">
            <div class="card-body">
                <h5 class="card-title text-warning">
                    <span class="status-indicator {'status-running' if beta_replicas > 0 else 'status-stopped'}"></span>
                    BETA (Staging)
                </h5>
                <p class="card-text">
                    <strong>Replicas:</strong> <span class="badge bg-warning">{beta_replicas}</span><br>
                    <strong>Image:</strong> <span class="text-muted">{beta_image.split('/')[-1] if beta_image else 'unknown'}</span>
                </p>
            </div>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="card deployment-card border-danger">
            <div class="card-body">
                <h5 class="card-title text-danger">
                    <span class="status-indicator {'status-running' if gamma_replicas > 0 else 'status-stopped'}"></span>
                    GAMMA (Emergency)
                </h5>
                <p class="card-text">
                    <strong>Replicas:</strong> <span class="badge bg-danger">{gamma_replicas}</span><br>
                    <strong>Image:</strong> <span class="text-muted">{gamma_image.split('/')[-1] if gamma_image else 'unknown'}</span>
                </p>
            </div>
        </div>
    </div>
    <div class="col-md-3 mb-3">
        <div class="card deployment-card border-info">
            <div class="card-body">
                <h5 class="card-title text-info">
                    <span class="status-indicator {'status-running' if ingress_status['is_active'] else 'status-warning'}"></span>
                    {ingress_status['name']}
                </h5>
                <p class="card-text">
                    <strong>Active:</strong> <span class="badge bg-{'success' if ingress_status['is_active'] else 'warning'}">{('YES' if ingress_status['is_active'] else 'NO')}</span><br>
                    <strong>Routing to:</strong> <span class="badge bg-{'primary' if ingress_status['target_service'] == 'alpha' else 'warning' if ingress_status['target_service'] == 'beta' else 'danger' if ingress_status['target_service'] == 'gamma' else 'secondary'}">{ingress_status['target_service'].upper()}</span>
                </p>
            </div>
        </div>
    </div>
    """
    
    return HTMLResponse(content=html_content)

@app.get("/api/databases", response_class=HTMLResponse)
async def list_databases(request: Request):
    """Force hard database discovery and list all databases with their versions"""
    databases = discover_databases_hard()
    
    if not databases:
        return HTMLResponse(content='<p class="text-muted text-center">No databases found</p>')
    
    return await render_database_table(databases)

@app.get("/api/databases/versions", response_class=HTMLResponse) 
async def refresh_database_versions(request: Request):
    """Refresh only the database versions without rediscovering databases"""
    # Use cached databases if available, otherwise discover
    databases = DATABASE_CACHE.get("databases", [])
    if not databases:
        databases = discover_databases()
    
    if not databases:
        return HTMLResponse(content='<p class="text-muted text-center">No databases found</p>')
    
    # Check if request is from backup dashboard via referer
    referer = request.headers.get("referer", "")
    is_backup_dashboard = "/backup" in referer or request.headers.get("host") == f"backup.{MAIN_DOMAIN}"
    
    if is_backup_dashboard:
        return await render_backup_database_table(databases)
    else:
        return await render_database_table(databases)

async def render_database_table(databases: List[str]) -> HTMLResponse:
    """Render the database table HTML"""
    total_databases = len(databases)
    html = f'''<div class="table-responsive">
    <div class="mb-2">
        <small class="text-muted">Last Discovery: {get_last_discovery_time()} | Total Databases: {total_databases}</small>
    </div>
    <table class="table table-striped table-hover">'''
    html += '''
    <thead class="table-dark">
        <tr>
            <th>Database</th>
            <th>Company</th>
            <th>Version</th>
            <th>Last Updated</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
    '''
    
    for db in databases:
        version = redis_helper.get(f"db_version:{db}")
        updated = redis_helper.get(f"db_updated:{db}")
        company_name = redis_helper.get_company_name(db)
        
        version = version or "alpha"
        updated = updated or "Never"
        
        version_class = {
            "alpha": "primary",
            "beta": "warning", 
            "gamma": "danger"
        }.get(version, "secondary")
        
        html += f'''
        <tr>
            <td><strong>{db}</strong></td>
            <td><span class="text-primary">{company_name}</span></td>
            <td><span class="badge bg-{version_class}">{version.upper()}</span></td>
            <td class="text-muted">{updated.split('T')[0] if 'T' in updated else updated}</td>
            <td>
                <div class="btn-group btn-group-sm" role="group">
                    <button class="btn btn-outline-primary" 
                            hx-put="/api/databases/{db}"
                            hx-vals='{{"version": "alpha"}}'
                            hx-target="#operation-result"
                            title="Set to Alpha">α</button>
                    <button class="btn btn-outline-warning" 
                            hx-put="/api/databases/{db}"
                            hx-vals='{{"version": "beta"}}'
                            hx-target="#operation-result"
                            title="Set to Beta">β</button>
                    <button class="btn btn-outline-danger" 
                            hx-put="/api/databases/{db}"
                            hx-vals='{{"version": "gamma"}}'
                            hx-target="#operation-result"
                            title="Set to Gamma">γ</button>
                </div>
            </td>
        </tr>
        '''
    
    html += '</tbody></table></div>'
    return HTMLResponse(content=html)

async def render_backup_database_table(databases: List[str]) -> HTMLResponse:
    """Render the backup database table HTML with backup actions"""
    total_databases = len(databases)
    html = f'''<div class="table-responsive">
    <div class="mb-2">
        <small class="text-muted">Last Discovery: {get_last_discovery_time()} | Total Databases: {total_databases}</small>
    </div>
    <table class="table table-striped table-hover">'''
    html += '''
    <thead class="table-dark">
        <tr>
            <th>Database</th>
            <th>Company</th>
            <th>Version</th>
            <th>Last Updated</th>
            <th>Backup Actions</th>
        </tr>
    </thead>
    <tbody>
    '''
    
    for db in databases:
        version = redis_helper.get(f"db_version:{db}")
        updated = redis_helper.get(f"db_updated:{db}")
        company_name = redis_helper.get_company_name(db)
        
        version = version or "alpha"
        updated = updated or "Never"
        
        version_class = {
            "alpha": "primary",
            "beta": "warning", 
            "gamma": "danger"
        }.get(version, "secondary")
        
        html += f'''
        <tr>
            <td><strong>{db}</strong></td>
            <td><span class="text-primary">{company_name}</span></td>
            <td><span class="badge bg-{version_class}">{version.upper()}</span></td>
            <td class="text-muted">{updated.split('T')[0] if 'T' in updated else updated}</td>
            <td>
                <button class="btn btn-success btn-sm backup-btn" 
                        onclick="triggerBackup('{db}')"
                        title="Backup Database">
                    <i class="bi bi-cloud-download"></i> Backup
                </button>
            </td>
        </tr>
        '''
    
    html += '</tbody></table></div>'
    return HTMLResponse(content=html)

@app.get("/api/databases/distribution", response_class=HTMLResponse)
async def get_database_distribution():
    """Get database distribution across Alpha-Beta-Gamma deployments"""
    redis_helper = RedisHelper()
    
    # Get actual existing databases first
    databases = discover_databases()
    
    # Clean up stale Redis entries
    stale_count = redis_helper.cleanup_stale_database_versions(databases)
    if stale_count > 0:
        logger.info(f"Cleaned up {stale_count} stale database version entries")
    
    # Get distribution with actual databases only
    distribution = redis_helper.get_database_distribution(databases)
    
    html = f'''
    <div class="col-md-4 mb-3">
        <div class="card border-primary">
            <div class="card-body text-center">
                <h5 class="card-title text-primary">
                    <i class="bi bi-hdd-stack"></i> ALPHA
                </h5>
                <h3 class="text-primary mb-1">{distribution['ALPHA']}</h3>
                <small class="text-muted">Databases</small>
            </div>
        </div>
    </div>
    <div class="col-md-4 mb-3">
        <div class="card border-warning">
            <div class="card-body text-center">
                <h5 class="card-title text-warning">
                    <i class="bi bi-hdd-stack"></i> BETA
                </h5>
                <h3 class="text-warning mb-1">{distribution['BETA']}</h3>
                <small class="text-muted">Databases</small>
            </div>
        </div>
    </div>
    <div class="col-md-4 mb-3">
        <div class="card border-danger">
            <div class="card-body text-center">
                <h5 class="card-title text-danger">
                    <i class="bi bi-hdd-stack"></i> GAMMA
                </h5>
                <h3 class="text-danger mb-1">{distribution['GAMMA']}</h3>
                <small class="text-muted">Databases</small>
            </div>
        </div>
    </div>
    '''
    
    return HTMLResponse(content=html)

@app.get("/api/databases/{database}/status")
async def get_database_status(database: str) -> DatabaseInfo:
    """Get specific database status"""
    version = redis_helper.get(f"db_version:{database}")
    updated = redis_helper.get(f"db_updated:{database}")
    
    if version is None:
        # Database not found in Redis, check if it exists
        databases = discover_databases()
        if database not in databases:
            raise HTTPException(status_code=404, detail="Database not found")
        version = "alpha"  # Default
    
    return DatabaseInfo(
        name=database,
        version=version,
        updated=updated
    )

@app.put("/api/databases/{database}")
async def set_database_version(database: str, version: str = Form()):
    """Set database version (alpha/beta/gamma)"""
    if version not in ["alpha", "beta", "gamma"]:
        raise HTTPException(status_code=400, detail="Version must be alpha, beta, or gamma")
    
    # Check if database exists
    databases = discover_databases()
    if database not in databases:
        raise HTTPException(status_code=404, detail="Database not found")
    
    # Update Redis
    redis_helper.set(f"db_version:{database}", version)
    redis_helper.set(f"db_updated:{database}", datetime.now().isoformat())
    
    return {"message": f"Database {database} set to {version}", "success": True}

@app.post("/api/databases/reset")
async def reset_all_databases():
    """Reset all databases to alpha version"""
    databases = discover_databases()
    reset_count = 0
    
    for db in databases:
        redis_helper.set(f"db_version:{db}", "alpha")
        redis_helper.set(f"db_updated:{db}", datetime.now().isoformat())
        reset_count += 1
    
    return {"message": f"Reset {reset_count} databases to alpha", "count": reset_count}

@app.post("/api/databases/unlock")
async def unlock_migration():
    """Remove migration lock"""
    lock_key = "migration:lock:abg"
    deleted = redis_helper.delete(lock_key)
    
    return {
        "message": "Migration lock removed" if deleted else "No lock found",
        "success": True
    }

@app.post("/api/databases/discover-companies")
async def discover_companies():
    """Trigger company name discovery for all databases"""
    try:
        import subprocess
        import os
        
        # Path to the company discovery script
        script_path = DISCOVERY_SCRIPT_PATH
        
        # Check if script exists
        if not os.path.exists(script_path):
            error_msg = f"Discovery script not found: {script_path}"
            logger.error(error_msg)
            return {
                "status": "error", 
                "message": error_msg
            }
        
        logger.info("Starting company name discovery...")
        
        # Run the discovery script
        result = subprocess.run([script_path], 
                              capture_output=True, 
                              text=True, 
                              timeout=300)  # 5 minute timeout
        
        if result.returncode != 0:
            error_msg = f"Company discovery failed: {result.stderr}"
            logger.error(error_msg)
            return {
                "success": False,
                "message": "❌ Company discovery failed",
                "error": error_msg
            }
        
        # Parse the output and store in Redis
        lines = result.stdout.strip().split('\n')
        success_count = 0
        
        for line in lines:
            if ':' in line and not line.startswith('['):  # Skip log lines
                try:
                    database, company_name = line.split(':', 1)
                    redis_helper.set_company_name(database, company_name)
                    success_count += 1
                except ValueError:
                    continue  # Skip malformed lines
        
        # Clean up stale entries
        databases = discover_databases()
        stale_count = redis_helper.cleanup_stale_company_names(databases)
        
        logger.info(f"Company discovery completed: {success_count} companies stored")
        
        return {
            "success": True,
            "message": f"✅ Discovered {success_count} company names",
            "companies_found": success_count,
            "stale_cleaned": stale_count
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "❌ Company discovery timed out (5 minutes)",
            "error": "Timeout"
        }
    except Exception as e:
        error_msg = f"Company discovery error: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": "❌ Company discovery failed",
            "error": error_msg
        }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOGS ENDPOINTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/api/migrations")
async def get_migrations():
    """Get list of all migration directories"""
    try:
        import os
        import re
        from datetime import datetime
        
        logs_path = f"{CEPH_DATA_PATH}/infra/odoo/system-fs/alpha-beta-gamma"
        
        if not os.path.exists(logs_path):
            return {"migrations": []}
        
        migrations = []
        migration_pattern = re.compile(r'migration-(\d{8})_(\d{6})$')
        
        for item in sorted(os.listdir(logs_path), reverse=True):
            item_path = os.path.join(logs_path, item)
            
            if os.path.isdir(item_path) and migration_pattern.match(item):
                match = migration_pattern.match(item)
                if match:
                    date_str = match.group(1)
                    time_str = match.group(2)
                    
                    # Parse datetime
                    try:
                        dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
                        formatted_time = dt.strftime("%d/%m/%y %H:%M:%S")
                    except:
                        formatted_time = f"{date_str} {time_str}"
                    
                    # Read migration summary for metadata
                    summary_file = os.path.join(item_path, "migration-summary.log")
                    target_deployment = "unknown"
                    database_count = 0
                    deployed_image = "unknown"
                    
                    if os.path.exists(summary_file):
                        try:
                            with open(summary_file, 'r') as f:
                                content = f.read()
                                # Extract metadata
                                for line in content.split('\n'):
                                    if "Target:" in line:
                                        target_deployment = line.split("Target:")[1].strip()
                                    elif "Databases to process:" in line:
                                        try:
                                            database_count = int(line.split(":")[1].strip())
                                        except:
                                            pass
                                    elif "Deployed Image:" in line or "Deployed image:" in line:
                                        deployed_image = line.split(":", 1)[1].strip()
                        except:
                            pass
                    
                    # Count success/failure markers
                    success_count = len([f for f in os.listdir(item_path) if f.startswith('success-')])
                    fail_count = len([f for f in os.listdir(item_path) if f.startswith('fail-')])
                    
                    migrations.append({
                        "id": item,
                        "timestamp": formatted_time,
                        "target_deployment": target_deployment,
                        "deployed_image": deployed_image,
                        "database_count": database_count,
                        "success_count": success_count,
                        "fail_count": fail_count,
                        "status": "success" if fail_count == 0 else "partial" if success_count > 0 else "failed"
                    })
        
        return {"migrations": migrations}
        
    except Exception as e:
        logger.error(f"Error getting migrations: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting migrations: {str(e)}")

@app.get("/api/migrations/{migration_id}")
async def get_migration_logs(migration_id: str):
    """Get list of log files in a migration directory"""
    try:
        import os
        
        migration_path = f"{CEPH_DATA_PATH}/infra/odoo/system-fs/alpha-beta-gamma/{migration_id}"
        
        if not os.path.exists(migration_path):
            raise HTTPException(status_code=404, detail="Migration not found")
        
        logs = []
        success_files = set()
        fail_files = set()
        
        # Get success/fail markers
        for item in os.listdir(migration_path):
            if item.startswith('success-'):
                success_files.add(item.replace('success-', ''))
            elif item.startswith('fail-'):
                fail_files.add(item.replace('fail-', ''))
        
        # Process migration log files
        for item in sorted(os.listdir(migration_path)):
            if item.startswith('migrate-') and item.endswith('.log'):
                db_name = item.replace('migrate-', '').replace('.log', '')
                file_path = os.path.join(migration_path, item)
                file_size = os.path.getsize(file_path)
                
                # Determine status
                if db_name in success_files:
                    status = "success"
                elif db_name in fail_files:
                    status = "failed"
                else:
                    status = "unknown"
                
                logs.append({
                    "filename": item,
                    "database": db_name,
                    "status": status,
                    "size": file_size,
                    "size_mb": round(file_size / 1024 / 1024, 2)
                })
        
        # Add special files
        special_files = ["migration-summary.log", "original-sources.log"]
        for special_file in special_files:
            special_path = os.path.join(migration_path, special_file)
            if os.path.exists(special_path):
                file_size = os.path.getsize(special_path)
                logs.insert(0, {
                    "filename": special_file,
                    "database": special_file.replace(".log", "").replace("-", " ").title(),
                    "status": "info",
                    "size": file_size,
                    "size_mb": round(file_size / 1024 / 1024, 2)
                })
        
        return {"logs": logs, "migration_id": migration_id}
        
    except Exception as e:
        logger.error(f"Error getting migration logs for {migration_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting migration logs: {str(e)}")

@app.get("/api/migrations/{migration_id}/logs/{log_filename}")
async def get_log_content(migration_id: str, log_filename: str):
    """Get content of a specific log file"""
    try:
        import os
        
        # Security check - only allow .log files and prevent path traversal
        if not log_filename.endswith('.log') or '/' in log_filename or '..' in log_filename:
            raise HTTPException(status_code=400, detail="Invalid log filename")
        
        log_path = f"{CEPH_DATA_PATH}/infra/odoo/system-fs/alpha-beta-gamma/{migration_id}/{log_filename}"
        
        if not os.path.exists(log_path):
            raise HTTPException(status_code=404, detail="Log file not found")
        
        # Read log content with size limit for safety
        max_size = 10 * 1024 * 1024  # 10MB limit
        file_size = os.path.getsize(log_path)
        
        if file_size > max_size:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(max_size)
                content += f"\n\n[LOG TRUNCATED - File too large ({file_size:,} bytes, showing first {max_size:,} bytes)]"
        else:
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        
        return {
            "content": content,
            "filename": log_filename,
            "migration_id": migration_id,
            "size": file_size
        }
        
    except Exception as e:
        logger.error(f"Error getting log content for {migration_id}/{log_filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting log content: {str(e)}")

@app.get("/api/deployment/status")
async def get_deployment_status():
    """Get current deployment status"""
    try:
        return redis_helper.get_deployment_status()
    except Exception as e:
        logger.error(f"Error getting deployment status: {e}")
        return {"active": False, "error": str(e)}

@app.post("/api/deployment/trigger")
async def trigger_deployment(request: Request):
    """Trigger auto-deployment with concurrency control"""
    try:
        # Get user info (could be from headers, auth, etc.)
        user_ip = request.client.host if request.client else "unknown"
        user = f"user-{user_ip}"
        
        # Try to start deployment (this will fail if one is already running)
        start_result = redis_helper.start_deployment(user)
        if not start_result["success"]:
            return {
                "success": False,
                "message": f"🚫 Deployment blocked: {start_result['error']}",
                "alert_class": "alert alert-warning",
                "output": f"Another deployment is already in progress by {start_result.get('user', 'unknown')} since {start_result.get('started_at', 'unknown')}",
                "status": "blocked"
            }
        
        try:
            cmd = f'ssh -o StrictHostKeyChecking=no {SSH_USERNAME}@{MS_SERVER_IP} "/home/experio/workspace/Watcher/auto-deploy/check-and-deploy.sh"'
            
            # Execute command with real-time output capture
            process = subprocess.Popen(
                cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            output_lines = []
            deployment_status = "running"
            current_stage = "starting"
            
            # Read output line by line
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue
                    
                output_lines.append(line)
                
                # Parse deployment stages from script output
                if "Starting Auto-Deploy Check" in line:
                    current_stage = "initializing"
                elif "Updating local repository" in line:
                    current_stage = "updating_repo"
                elif "Latest release:" in line:
                    current_stage = "checking_versions"
                elif "Version mismatch detected" in line:
                    current_stage = "building"
                elif "Building docker image" in line:
                    current_stage = "building"
                elif "Pushing image to registry" in line:
                    current_stage = "pushing"
                elif "Deploying to k8s" in line:
                    current_stage = "deploying"
                elif "Deployment successful" in line:
                    current_stage = "completed"
                    deployment_status = "success"
                elif "No update needed" in line:
                    current_stage = "up_to_date"
                    deployment_status = "up_to_date"
                elif any(word in line.lower() for word in ["failed", "error"]):
                    deployment_status = "failed"
            
            process.stdout.close()
            return_code = process.wait()
            
            # Parse key information from output
            latest_version = "unknown"
            alpha_version = "unknown"
            beta_version = "unknown"
            gamma_version = "unknown"
            
            for line in output_lines:
                if "Latest release:" in line:
                    latest_version = line.split(":")[-1].strip()
                elif "Alpha deployment:" in line:
                    alpha_version = line.split(":")[-1].strip()
                elif "Beta deployment:" in line:
                    beta_version = line.split(":")[-1].strip()
                elif "Gamma deployment:" in line:
                    gamma_version = line.split(":")[-1].strip()
            
            # Format structured output
            if return_code == 0:
                if deployment_status == "up_to_date":
                    status_message = f"✅ System is up to date (v{latest_version})"
                    alert_class = "alert-info"
                else:
                    status_message = f"✅ Deployment successful! Updated to v{latest_version}"
                    alert_class = "alert-success"
            else:
                status_message = f"❌ Deployment failed (exit code: {return_code})"
                alert_class = "alert-danger"
            
            # Return structured output
            full_output = "\n".join(output_lines[-50:])  # Last 50 lines
            
            result_data = {
                "success": return_code == 0,
                "status": deployment_status,
                "stage": current_stage,
                "message": status_message,
                "latest_version": latest_version,
                "alpha_version": alpha_version,
                "beta_version": beta_version,
                "gamma_version": gamma_version,
                "return_code": return_code,
                "output": full_output,
                "alert_class": alert_class
            }
            
            # Finish deployment and store result
            redis_helper.finish_deployment(result_data)
            return result_data
            
        except subprocess.TimeoutExpired:
            result_data = {
                "success": False,
                "status": "timeout",
                "message": "⏱️ Deployment timed out after 5 minutes",
                "alert_class": "alert-warning"
            }
            redis_helper.finish_deployment(result_data)
            return result_data
        except Exception as e:
            result_data = {
                "success": False,
                "status": "error",
                "message": f"❌ Error: {str(e)}",
                "alert_class": "alert-danger"
            }
            redis_helper.finish_deployment(result_data)
            return result_data
            
    except Exception as e:
        result_data = {
            "success": False,
            "status": "error",
            "message": f"❌ Internal Error: {str(e)}",
            "alert_class": "alert-danger"
        }
        redis_helper.finish_deployment(result_data)
        return result_data
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BACKUP SYSTEM ENDPOINTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_download_token() -> str:
    """Generate secure download token with expiration"""
    token_id = str(uuid.uuid4())
    expiry = int(time.time()) + (6 * 3600)  # 6 hours from now
    return f"{token_id}_{expiry}"

def validate_download_token(token: str) -> bool:
    """Validate download token and check expiration"""
    try:
        token_id, expiry_str = token.split('_')
        expiry = int(expiry_str)
        return time.time() < expiry
    except (ValueError, IndexError):
        return False

def load_token_data(token: str) -> Optional[dict]:
    """Load token metadata from filesystem"""
    try:
        token_file = f"/app/downloads/tokens/{token}.json"
        if os.path.exists(token_file):
            with open(token_file, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load token data: {e}")
    return None

def save_token_data(token: str, data: dict) -> bool:
    """Save token metadata to filesystem"""
    try:
        token_file = f"{TOKENS_PATH}/{token}.json"
        with open(token_file, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save token data: {e}")
        return False

def load_backup_jobs() -> list:
    """Load backup jobs from filesystem"""
    try:
        jobs_file = f"{DOWNLOADS_BASE_PATH}/jobs/jobs.json"
        if os.path.exists(jobs_file):
            with open(jobs_file, 'r') as f:
                return json.load(f)
        else:
            # Create empty jobs file if it doesn't exist
            logger.info("Creating new jobs.json file")
            return []
    except Exception as e:
        logger.error(f"Failed to load backup jobs: {e}")
    return []

def save_backup_jobs(jobs: list) -> bool:
    """Save backup jobs to filesystem"""
    try:
        jobs_dir = f"{DOWNLOADS_BASE_PATH}/jobs"
        jobs_file = f"{jobs_dir}/jobs.json"
        
        # Ensure jobs directory exists
        os.makedirs(jobs_dir, mode=0o755, exist_ok=True)
        
        with open(jobs_file, 'w') as f:
            json.dump(jobs, f, indent=2)
        
        logger.info(f"Saved {len(jobs)} backup jobs to {jobs_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to save backup jobs: {e}")
        return False

@app.get("/downloads/{token}")
async def download_backup_file(token: str, request: Request):
    """Public download endpoint for backup files"""
    # Validate token format and expiration
    if not validate_download_token(token):
        raise HTTPException(status_code=410, detail="Download link expired or invalid")
    
    # Load token data
    token_data = load_token_data(token)
    if not token_data:
        raise HTTPException(status_code=404, detail="Download not found")
    
    # Check if file exists
    file_path = token_data.get("file_path", "")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    # Get file info
    database = token_data.get("database", "unknown")
    filename = token_data.get("filename", os.path.basename(file_path))
    
    # Log download attempt
    client_ip = request.client.host
    logger.info(f"Download request: database={database}, file={filename}, ip={client_ip}, token={token[:8]}...")
    
    # Return file with proper headers
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename=\"{filename}\"",
            "X-Database": database
        }
    )

@app.post("/api/backup/trigger")
async def trigger_backup(request: Request):
    """Trigger backup job for a database"""
    try:
        data = await request.json()
        database = data.get("database", "").strip()
        email = data.get("email", "").strip()
        
        # Validate inputs
        if not database:
            raise HTTPException(status_code=400, detail="Database name is required")
        
        if not email or email not in TRUSTED_EMAILS:
            raise HTTPException(status_code=400, detail="Invalid or untrusted email address")
        
        # Generate job ID
        job_id = f"backup_{database}_{int(time.time())}"
        
        # Load existing jobs
        jobs = load_backup_jobs()
        
        # Check for existing running backup of same database
        existing_job = next((job for job in jobs 
                           if job["database"] == database and job["status"] == "running"), None)
        
        if existing_job:
            return {
                "success": False,
                "message": f"Backup already running for {database}",
                "existing_job_id": existing_job["id"]
            }
        
        # Create new job entry
        new_job = {
            "id": job_id,
            "database": database,
            "email": email,
            "status": "running",
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "progress": "Initializing backup..."
        }
        
        jobs.append(new_job)
        save_backup_jobs(jobs)
        
        logger.info(f"Backup job started: {job_id}, database={database}, email={email}")
        
        # Start background backup process
        import asyncio
        import sys
        import os
        
        # Add scripts directory to Python path
        scripts_path = os.path.join(os.path.dirname(__file__), 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
        
        try:
            from scripts.backup_manager import backup_manager
            # Start backup in background
            asyncio.create_task(backup_manager.execute_backup(job_id, database, email))
        except ImportError as e:
            logger.error(f"Failed to import backup_manager: {e}")
            # Update job status to failed
            for job in jobs:
                if job["id"] == job_id:
                    job["status"] = "failed"
                    job["error"] = "Backup system not properly configured"
                    job["progress"] = "System error"
                    break
            save_backup_jobs(jobs)
            
            return {
                "success": False,
                "message": "Backup system not available",
                "job_id": job_id
            }
        
        return {
            "success": True,
            "message": f"Backup job started for {database}",
            "job_id": job_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start backup: {str(e)}")

@app.get("/api/backup/emails")
async def get_trusted_emails():
    """Get trusted email addresses with names"""
    return {"trusted_emails": TRUSTED_EMAILS_DICT}

@app.post("/api/backup/jobs/{job_id}/share")
async def share_backup_job(job_id: str, request: Request):
    """Share an existing backup with another user"""
    try:
        # Import required modules at the top
        import asyncio
        import sys
        import os
        
        form_data = await request.form()
        recipient_email = form_data.get("email")
        
        if not recipient_email or recipient_email not in TRUSTED_EMAILS:
            raise HTTPException(status_code=400, detail="Invalid email address")
        
        # Load jobs to find the target backup
        jobs = load_backup_jobs()
        job_to_share = None
        
        for job in jobs:
            if job["id"] == job_id and job.get("status") == "completed":
                job_to_share = job
                break
        
        if not job_to_share or not job_to_share.get("download_token"):
            raise HTTPException(status_code=404, detail="Backup not found or not ready")
        
        # Get the original file path from token
        original_token_data = load_token_data(job_to_share["download_token"])
        if not original_token_data or not original_token_data.get("file_path"):
            raise HTTPException(status_code=400, detail="Original backup file not accessible")
        
        file_path = original_token_data["file_path"]
        if not os.path.exists(file_path):
            raise HTTPException(status_code=400, detail="Backup file no longer exists")
        
        # Generate new token for sharing
        new_token = generate_download_token()
        
        # Create token data for the share
        share_token_data = {
            "database": job_to_share.get("database", "unknown"),
            "filename": original_token_data.get("filename", "backup.dump"),
            "file_path": file_path,
            "shared_from_job": job_id,
            "shared_to": recipient_email,
            "created": datetime.now().isoformat()
        }
        
        save_token_data(new_token, share_token_data)
        
        # Update job with share history
        if "shared_with" not in job_to_share:
            job_to_share["shared_with"] = []
        
        # Add share record
        share_record = {
            "email": recipient_email,
            "name": TRUSTED_EMAILS_DICT.get(recipient_email, recipient_email),
            "shared_at": datetime.now().isoformat(),
            "token": new_token
        }
        job_to_share["shared_with"].append(share_record)
        
        save_backup_jobs(jobs)
        
        # Send email notification
        database_name = job_to_share.get("database", "unknown")
        download_url = f"https://{DOWNLOADS_DOMAIN}/downloads/{new_token}"
        
        # Get file size and other job details
        file_size = job_to_share.get("progress", "Unknown size")
        if "MB)" in file_size:
            # Extract size from progress like "Backup completed (123MB)"
            size_mb = file_size.split("(")[1].split("MB)")[0] if "(" in file_size and "MB)" in file_size else "Unknown"
        else:
            size_mb = "Unknown"
        
        completed_at = job_to_share.get("updated", "")
        if completed_at:
            try:
                completed_date = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                completed_str = completed_date.strftime("%d/%m/%y %H:%M:%S")
            except:
                completed_str = completed_at
        else:
            completed_str = "Unknown"
        
        subject = f"✅ Database Backup Shared - {database_name}"
        body = f"""
<h3>Database Backup Shared With You</h3>
<p><strong>Database:</strong> {database_name}</p>
<p><strong>Shared by:</strong> {job_to_share.get('email', 'System')}</p>
<p><strong>File Size:</strong> {size_mb} MB</p>
<p><strong>Backup Completed:</strong> {completed_str}</p>
<p><strong>Download Link:</strong> <a href="{download_url}">{download_url}</a></p>
<br>
<p><em>Note: This download link will expire in 6 hours.</em></p>
<p><em>Shared at: {datetime.now().strftime("%d/%m/%y %H:%M:%S")}</em></p>
        """
        
        # Use existing email function
        scripts_path = os.path.join(os.path.dirname(__file__), 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
        
        try:
            from scripts.backup_manager import backup_manager
            email_success = await backup_manager.send_email(recipient_email, subject, body)
            
            if email_success:
                return {"success": True, "message": f"Backup shared with {TRUSTED_EMAILS_DICT.get(recipient_email, recipient_email)}"}
            else:
                # Remove the token if email failed
                try:
                    os.remove(f"{TOKENS_PATH}/{new_token}.json")
                    # Remove from job history
                    job_to_share["shared_with"].pop()
                    save_backup_jobs(jobs)
                except:
                    pass
                raise HTTPException(status_code=500, detail="Failed to send notification email")
                
        except ImportError:
            logger.error("Backup manager not available for email sending")
            raise HTTPException(status_code=500, detail="Email service not available")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to share backup {job_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to share backup: {str(e)}")

@app.get("/api/backup/jobs/{job_id}/history")
async def get_backup_share_history(job_id: str):
    """Get share history for a backup job"""
    try:
        jobs = load_backup_jobs()
        target_job = None
        
        for job in jobs:
            if job["id"] == job_id:
                target_job = job
                break
        
        if not target_job:
            raise HTTPException(status_code=404, detail="Backup job not found")
        
        return {
            "job_id": job_id,
            "database": target_job.get("database", "Unknown"),
            "original_email": target_job.get("email", "Unknown"),
            "original_name": TRUSTED_EMAILS_DICT.get(target_job.get("email", ""), target_job.get("email", "Unknown")),
            "created": target_job.get("created", ""),
            "shared_with": target_job.get("shared_with", [])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get share history for {job_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get share history: {str(e)}")

@app.get("/api/backup/jobs", response_class=HTMLResponse)
async def get_backup_jobs():
    """Get backup jobs status as HTML"""
    jobs = load_backup_jobs()
    
    if not jobs:
        return HTMLResponse("""
            <div class="text-center text-muted">
                <i class="bi bi-inbox"></i>
                <p class="mt-2">No backup jobs yet</p>
                <small>Trigger a backup to see job status here</small>
            </div>
        """)
    
    # Sort jobs by creation date (newest first)
    jobs.sort(key=lambda x: x.get("created", ""), reverse=True)
    
    html = '<div class="table-responsive">'
    html += '''
    <table class="table table-striped table-hover">
        <thead class="table-dark">
            <tr>
                <th>Database</th>
                <th>Email</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
    '''
    
    for job in jobs[:10]:  # Show last 10 jobs
        status = job.get("status", "unknown")
        status_class = {
            "running": "warning",
            "completed": "success", 
            "failed": "danger"
        }.get(status, "secondary")
        
        status_icon = {
            "running": "clock",
            "completed": "check-circle",
            "failed": "exclamation-triangle"
        }.get(status, "question-circle")
        
        created_date = job.get("created", "")
        if created_date:
            try:
                created_dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                created_str = created_dt.strftime("%d/%m/%y %H:%M")
            except:
                created_str = created_date
        else:
            created_str = "Unknown"
        
        progress = job.get("progress", "No details")
        email = job.get("email", "Unknown")
        
        html += f'''
        <tr>
            <td><strong>{job.get("database", "Unknown")}</strong></td>
            <td><small>{email}</small></td>
            <td><span class="badge bg-{status_class}"><i class="bi bi-{status_icon}"></i> {status.upper()}</span></td>
            <td><small>{progress}</small></td>
            <td><small>{created_str}</small></td>
            <td>
        '''
        
        if status == "completed" and job.get("download_token"):
            html += f'<a href="/downloads/{job["download_token"]}" class="btn btn-sm btn-outline-primary me-1" title="Download"><i class="bi bi-download"></i></a>'
            # Add share button
            shared_count = len(job.get("shared_with", []))
            share_text = f" ({shared_count})" if shared_count > 0 else ""
            html += f'<button class="btn btn-sm btn-outline-success me-1" title="Share backup" onclick="shareBackup(\'{job["id"]}\')"><i class="bi bi-share"></i>{share_text}</button>'
            # Add history button if there are shares
            if shared_count > 0:
                html += f'<button class="btn btn-sm btn-outline-info me-1" title="View share history" onclick="viewShareHistory(\'{job["id"]}\')"><i class="bi bi-clock-history"></i></button>'
        elif status == "running":
            html += '<span class="spinner-border spinner-border-sm me-1" role="status"></span>'
        elif status == "failed":
            html += f'<button class="btn btn-sm btn-outline-danger me-1" title="View Error" onclick="alert(\'{job.get("error", "Unknown error")}\')"><i class="bi bi-exclamation-triangle"></i></button>'
        
        # Add delete button for all jobs
        html += f'''<button class="btn btn-sm btn-outline-danger" 
                            title="Delete backup" 
                            hx-delete="/api/backup/jobs/{job['id']}" 
                            hx-trigger="click"
                            hx-target="closest #backup-jobs"
                            hx-swap="innerHTML"
                            hx-confirm="Are you sure you want to delete this backup job and its files?"
                            hx-indicator="#backup-jobs">
                        <i class="bi bi-trash"></i>
                    </button>'''
        
        html += '''
            </td>
        </tr>
        '''
    
    html += '</tbody></table></div>'
    
    return HTMLResponse(content=html)

@app.delete("/api/backup/jobs/{job_id}", response_class=HTMLResponse)
async def delete_backup_job(job_id: str):
    """Delete a backup job and its associated files"""
    try:
        jobs = load_backup_jobs()
        job_to_delete = None
        
        # Find the job to delete
        for job in jobs:
            if job["id"] == job_id:
                job_to_delete = job
                break
        
        if not job_to_delete:
            logger.warning(f"Backup job not found for deletion: {job_id}")
            # Return updated jobs list
            return await get_backup_jobs()
        
        # Delete associated files
        deleted_files = []
        
        # Delete token file if exists
        if job_to_delete.get("download_token"):
            token_file = f"{TOKENS_PATH}/{job_to_delete['download_token']}.json"
            if os.path.exists(token_file):
                try:
                    os.remove(token_file)
                    deleted_files.append("token file")
                    logger.info(f"Deleted token file: {token_file}")
                except Exception as e:
                    logger.error(f"Failed to delete token file {token_file}: {e}")
        
        # Delete dump file if exists (try multiple approaches)
        dump_file_deleted = False
        
        # Approach 1: Try to get file path from token data
        if job_to_delete.get("download_token"):
            token_data = load_token_data(job_to_delete["download_token"])
            if token_data and token_data.get("file_path"):
                dump_file = token_data["file_path"]
                if os.path.exists(dump_file):
                    try:
                        os.remove(dump_file)
                        deleted_files.append("dump file (from token)")
                        dump_file_deleted = True
                        logger.info(f"Deleted dump file from token data: {dump_file}")
                    except Exception as e:
                        logger.error(f"Failed to delete dump file {dump_file}: {e}")
        
        # Approach 2: If token approach failed, try to construct file path from job data
        if not dump_file_deleted and job_to_delete.get("database"):
            database = job_to_delete["database"]
            files_dir = f"{DOWNLOADS_BASE_PATH}/files"
            
            # Look for files matching the database name pattern
            if os.path.exists(files_dir):
                try:
                    import glob
                    # Pattern: database_YYYYMMDD_HHMMSS.dump
                    pattern = f"{files_dir}/{database}_*.dump"
                    matching_files = glob.glob(pattern)
                    
                    # Find the file that matches the job creation time approximately
                    job_created = job_to_delete.get("created", "")
                    for file_path in matching_files:
                        try:
                            file_stat = os.stat(file_path)
                            file_time = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            
                            # If job was created recently (within 1 hour of file modification)
                            if job_created:
                                job_dt = datetime.fromisoformat(job_created.replace('Z', '+00:00'))
                                file_dt = datetime.fromtimestamp(file_stat.st_mtime)
                                time_diff = abs((job_dt - file_dt).total_seconds())
                                
                                if time_diff < 3600:  # Within 1 hour
                                    os.remove(file_path)
                                    deleted_files.append(f"dump file (pattern match): {os.path.basename(file_path)}")
                                    dump_file_deleted = True
                                    logger.info(f"Deleted dump file by pattern: {file_path}")
                                    break
                        except Exception as e:
                            logger.warning(f"Error processing file {file_path}: {e}")
                            continue
                            
                    # If still no file deleted and there's only one matching file, delete it
                    if not dump_file_deleted and len(matching_files) == 1:
                        try:
                            os.remove(matching_files[0])
                            deleted_files.append(f"dump file (single match): {os.path.basename(matching_files[0])}")
                            dump_file_deleted = True
                            logger.info(f"Deleted single matching dump file: {matching_files[0]}")
                        except Exception as e:
                            logger.error(f"Failed to delete single matching file {matching_files[0]}: {e}")
                            
                except Exception as e:
                    logger.error(f"Failed to search for dump files: {e}")
        
        if not dump_file_deleted:
            logger.warning(f"Could not locate dump file for deletion: job_id={job_id}, database={job_to_delete.get('database', 'unknown')}")
        
        # Remove job from jobs list
        jobs = [job for job in jobs if job["id"] != job_id]
        save_backup_jobs(jobs)
        
        logger.info(f"Deleted backup job {job_id} (database: {job_to_delete.get('database', 'unknown')})")
        if deleted_files:
            logger.info(f"Also deleted: {', '.join(deleted_files)}")
        
        # Return updated jobs list with the same structure as get_backup_jobs
        return await get_backup_jobs()
        
    except Exception as e:
        logger.error(f"Failed to delete backup job {job_id}: {e}")
        # Return current jobs list even if deletion failed
        return await get_backup_jobs()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    redis_ok = redis_helper.redis_client is not None
    return {
        "status": "healthy" if redis_ok else "unhealthy",
        "redis": "connected" if redis_ok else "disconnected",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/test-permissions")
async def test_permissions():
    """Test endpoint to verify filesystem permissions"""
    results = {}
    
    # Test downloads directory structure
    base_dir = DOWNLOADS_BASE_PATH
    subdirs = ["files", "tokens", "jobs"]
    
    for subdir in subdirs:
        dir_path = f"{base_dir}/{subdir}"
        try:
            # Check if directory exists
            exists = os.path.exists(dir_path)
            results[f"{subdir}_exists"] = exists
            
            if exists:
                # Check if writable
                test_file = f"{dir_path}/test_write_{int(time.time())}.tmp"
                try:
                    with open(test_file, 'w') as f:
                        f.write("test")
                    os.remove(test_file)
                    results[f"{subdir}_writable"] = True
                except Exception as e:
                    results[f"{subdir}_writable"] = False
                    results[f"{subdir}_error"] = str(e)
            else:
                results[f"{subdir}_writable"] = False
        except Exception as e:
            results[f"{subdir}_error"] = str(e)
    
    return {"status": "test complete", "results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)