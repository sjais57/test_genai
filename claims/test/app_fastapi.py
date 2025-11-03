import os
import re
import yaml
import logging
from datetime import timedelta, datetime
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Depends, Request, status, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from pydantic import BaseModel, Field
import logging
import pathlib
import yaml
import uuid
import glob
from dotenv import load_dotenv
import jwt as pyjwt

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Import authentication methods
from auth.file_auth import authenticate_file
from auth.ldap_auth import authenticate_ldap, LDAP_AVAILABLE
from utils.api_key import get_additional_claims, BASE_API_KEY_FILE
from utils.jwe_handler import (
    encrypt_jwt_token, decrypt_jwe_token,
    encrypt_payload_to_jwe, decrypt_jwe_to_payload,
    JWEHandler
)

# --- Helper Functions ---------------------------------------------------------------

def _normalize(name: str) -> str:
    """
    Canonicalize group names for matching:
    - lower-case
    - collapse separators: treat '.' and '_' as equivalent
    - strip surrounding quotes/spaces
    """
    s = str(name).strip().strip("'\"").lower()
    # replace any run of [._\s-] with a single dot
    s = re.sub(r"[._\s-]+", ".", s)
    return s


def extract_group_cn(groups):
    result = []
    for g in (groups or []):
        if isinstance(g, dict):
            cn = g.get('cn') or g.get('name') or g.get('uid') or ''
            if cn:
                result.append(cn.lower())
        elif isinstance(g, str):
            m = re.search(r'cn=([^,]+)', g, flags=re.I)
            result.append((m.group(1) if m else g).lower())
    seen, ordered = set(), []
    for n in result:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


def parse_comma_separated_groups(group_config: str) -> list:
    if not group_config:
        return []
    groups = [group.strip() for group in group_config.split(',')]
    return [_normalize(group) for group in groups if group]


def user_pre_validation(api_key: str, normalized_groups: list, username: str) -> dict:
    """
    Perform pre-validation checks for API key access based on LDAP groups and GES namespaces.
    """
    try:
        # Load the API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")

        if not os.path.exists(api_key_file):
            return {"valid": False, "message": "Invalid API key"}

        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)

        # Check if pre_validation_check is configured
        pre_validation_config = api_key_config.get('pre_validation_check')
        if not pre_validation_config:
            return {"valid": True, "message": "No pre-validation required"}

        # Handle both old string format and new dict format for backward compatibility
        if isinstance(pre_validation_config, str):
            logger.info("Using legacy pre-validation format")
            required_ldap_groups = parse_comma_separated_groups(pre_validation_config)
            required_ges_namespaces = []
        elif isinstance(pre_validation_config, dict):
            logger.info("Using structured pre-validation format")

            # Parse LDAP groups if specified
            ldap_config = pre_validation_config.get('LDAP', '')
            if isinstance(ldap_config, str):
                required_ldap_groups = parse_comma_separated_groups(ldap_config)
            else:
                required_ldap_groups = []

            # Parse GES namespaces if specified
            ges_config = pre_validation_config.get('GES', '')
            if isinstance(ges_config, str):
                required_ges_namespaces = [ns.strip() for ns in ges_config.split(',') if ns.strip()]
            elif isinstance(ges_config, list):
                required_ges_namespaces = [ns for ns in ges_config if ns]
            else:
                required_ges_namespaces = []
        else:
            logger.warning(f"Invalid pre_validation_check format: {type(pre_validation_config)}")
            return {
                "valid": False,
                "message": "Invalid pre-validation configuration format"
            }

        logger.info(f"Required LDAP groups: {required_ldap_groups}")
        logger.info(f"Required GES namespaces: {required_ges_namespaces}")

        # If no requirements specified, validation passes
        if not required_ldap_groups and not required_ges_namespaces:
            return {"valid": True, "message": "No specific validation requirements"}

        # Check LDAP groups first - user needs to be in ANY of the required groups
        if required_ldap_groups:
            normalized_user_groups = [_normalize(group) for group in normalized_groups]
            ldap_matches = [group for group in required_ldap_groups if group in normalized_user_groups]
            if ldap_matches:
                return {
                    "valid": True,
                    "message": f"User has access via LDAP groups: {', '.join(ldap_matches)}",
                    "matched_groups": ldap_matches,
                    "source": "LDAP"
                }

        # Check GES namespace membership - user needs to have ANY groups in ANY namespace
        if required_ges_namespaces:
            try:
                # Try to import GES service if available
                from auth.ges_auth import ges_service

                logger.info("Checking GES namespace membership")

                # Use the existing GES service to check namespace membership
                user_namespace_groups = ges_service.get_user_groups_in_namespaces(
                    username, required_ges_namespaces
                )
                logger.info(f"User GES namespace groups: {user_namespace_groups}")

                accessible_namespaces = [
                    namespace
                    for namespace, groups in user_namespace_groups.items()
                    if groups
                ]
                if accessible_namespaces:
                    return {
                        "valid": True,
                        "message": f"User has access via GES namespaces: {', '.join(accessible_namespaces)}",
                        "matched_namespaces": accessible_namespaces,
                        "source": "GES"
                    }
            except ImportError:
                logger.warning("GES integration not available - skipping GES validation")
            except Exception as e:
                logger.error(f"Error checking GES namespace membership: {str(e)}")

        # No matches found
        error_details = []
        if required_ldap_groups:
            error_details.append(f"LDAP groups: {required_ldap_groups}")
        if required_ges_namespaces:
            error_details.append(f"GES namespaces: {required_ges_namespaces}")

        return {
            "valid": False,
            "message": "User does not meet pre-validation requirements",
            "details": error_details,
            "user_ad_groups": normalized_groups
        }

    except Exception as e:
        logger.error(f"Error during pre-validation check: {str(e)}")
        return {"valid": False, "message": f"Error during validation: {str(e)}"}


# Pydantic Models
class LoginRequest(BaseModel):
    username: str
    password: str
    api_key: Optional[str] = None
    api_key_config: Optional[Dict[str, Any]] = None
    secret: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Optional[str] = "Bearer"
    encryption: Optional[str] = None
    note: Optional[str] = None

class DecodeRequest(BaseModel):
    token: str
    skipVerification: Optional[bool] = False
    secret: Optional[str] = None

class ValidateRequest(BaseModel):
    token: str

class ValidateResponse(BaseModel):
    valid: bool
    signature_verified: bool
    expired: bool
    expiry_time: Optional[str] = None
    issued_at: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    error: Optional[str] = None

class JWEEncryptRequest(BaseModel):
    token: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    encryption_key: str
    encryption: Optional[str] = "A256GCM"
    compression: Optional[str] = None

class JWEDecryptRequest(BaseModel):
    jwe_token: str
    encryption_key: str
    encryption: Optional[str] = "A256GCM"
    extract_jwt: Optional[bool] = True

class JWEKeyGenRequest(BaseModel):
    algorithm: Optional[str] = "A256GCM"
    format: Optional[str] = "base64"

class CreateAPIKeyRequest(BaseModel):
    owner: str
    provider_permissions: Optional[List[str]] = ["openai"]
    endpoint_permissions: Optional[List[str]] = ["/v1/chat/completions", "/v1/embeddings"]
    static_claims: Optional[Dict[str, Any]] = Field(default_factory=lambda: {
        "models": ["gpt-3.5-turbo"],
        "rate_limit": 20,
        "tier": "standard",
        "exp_hours": 1
    })
    dynamic_claims: Optional[Dict[str, Any]] = Field(default_factory=dict)

class UpdateAPIKeyRequest(BaseModel):
    owner: Optional[str] = None
    provider_permissions: Optional[List[str]] = None
    endpoint_permissions: Optional[List[str]] = None
    static_claims: Optional[Dict[str, Any]] = None
    dynamic_claims: Optional[Dict[str, Any]] = None

# Initialize FastAPI app
app = FastAPI(
    title="JWT Auth API",
    description="A FastAPI implementation of JWT authentication with advanced features",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
AUTH_METHOD = os.getenv("AUTH_METHOD", "file")
ALWAYS_USE_BASE_CLAIMS = os.getenv("ALWAYS_USE_BASE_CLAIMS", "true").lower() == "true"

# Check if LDAP is requested but not available
if AUTH_METHOD == "ldap" and not LDAP_AVAILABLE:
    logger.warning("LDAP authentication method selected but python-ldap is not installed.")
    logger.warning("Falling back to file-based authentication.")
    logger.warning("To use LDAP authentication, install python-ldap: pip install python-ldap")
    AUTH_METHOD = "file"

# JWT Security
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        return username
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

async def get_current_user_fresh(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        
        # Check if token is fresh
        if not payload.get("fresh", False):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Fresh token required",
            )
        return username
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

async def get_current_user_refresh(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        
        # Check if token is a refresh token
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token required",
            )
        return username, payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        
        # Check if user is admin
        groups = payload.get("groups", [])
        if 'administrators' not in groups and 'admins' not in groups:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator access required",
            )
        return username, payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

# Utility functions
def get_team_id_from_user(username: str, user_data: Dict[str, Any]) -> str:
    """Determine the team ID from the user's data"""
    groups = user_data.get("groups", [])
    
    if "administrators" in groups or "admins" in groups:
        return "admin-team"
    elif "ai-team" in groups:
        return "ai-team"
    elif "ml-team" in groups:
        return "ml-team"
    
    return "general-users"

def get_jwe_config_from_api_key(api_key: Optional[str] = None, api_key_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Get JWE configuration from API key or inline configuration"""
    try:
        if api_key_config:
            logger.info(f"Checking for JWE config in api_key_config. Keys present: {list(api_key_config.keys())}")
            jwe_config = api_key_config.get('jwe_config', {})
            logger.info(f"JWE config found: {jwe_config}")
            if jwe_config.get('enabled', False):
                logger.info(f"JWE is enabled, returning config")
                return jwe_config
            else:
                logger.info(f"JWE not enabled or config empty")
            return {}
        
        if api_key:
            api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
            specific_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
            
            if os.path.exists(specific_key_file):
                with open(specific_key_file, 'r') as f:
                    key_data = yaml.safe_load(f)
                    jwe_config = key_data.get('jwe_config', {})
                    if jwe_config.get('enabled', False):
                        return jwe_config
        
        return {}
        
    except Exception as e:
        logger.error(f"Error getting JWE config: {str(e)}")
        return {}

def create_jwt_token(identity: str, claims: Dict[str, Any], expires_delta: timedelta, token_type: str = "access") -> str:
    """Create a JWT token"""
    now = datetime.utcnow()
    expire = now + expires_delta
    
    payload = {
        "sub": identity,
        "iat": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "type": token_type,
        **claims
    }
    
    if token_type == "access":
        payload["fresh"] = True
    
    return pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

# Routes
@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html>
        <head>
            <title>JWT Auth API</title>
        </head>
        <body>
            <h1>JWT Auth API</h1>
            <p>Welcome to the JWT Authentication API</p>
            <ul>
                <li><a href="/docs">API Documentation</a></li>
                <li><a href="/redoc">ReDoc Documentation</a></li>
            </ul>
        </body>
    </html>
    """

@app.post("/token", response_model=TokenResponse)
async def login(login_data: LoginRequest):
    username = login_data.username
    password = login_data.password
    api_key = login_data.api_key
    api_key_config = login_data.api_key_config
    custom_secret = login_data.secret

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing username or password"
        )

    # Authenticate based on the configured method
    if AUTH_METHOD == "ldap":
        authenticated, user_data = authenticate_ldap(username, password)
    else:  # file-based authentication
        authenticated, user_data = authenticate_file(username, password)

    if not authenticated:
        error_message = "Invalid username or password"
        if "error" in user_data:
            error_message = user_data["error"]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_message
        )

    # Prepare group info using helper functions
    raw_groups = user_data.get("groups", [])
    normalized_groups = extract_group_cn(raw_groups)

    # API-key pre-validation (if provided)
    ges_claims = {}
    if api_key:
        validation_result = user_pre_validation(api_key, normalized_groups, username)
        if not validation_result["valid"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=validation_result["message"],
                headers={
                    "X-Validation-Details": str(validation_result.get("details", "")),
                    "X-User-Groups": str(validation_result.get("user_ad_groups", ""))
                }
            )

        # Try to get GES claims if available
        try:
            from claims.ges_claims import get_ges_claims_from_api_key
            ges_claims = get_ges_claims_from_api_key(username, api_key)
        except ImportError:
            logger.warning("GES claims module not available")
        except Exception as e:
            logger.error(f"Error fetching GES claims: {str(e)}")
            ges_claims = {}

    # Create user context for dynamic claims processing
    user_context = {
        "user_id": username,
        "email": user_data.get("email", ""),
        "groups": user_data.get("groups", []),
        "roles": user_data.get("roles", []),
        "team_id": get_team_id_from_user(username, user_data)
    }

    # If an API key or API key config was provided, get additional claims to include in the token
    if api_key or api_key_config:
        user_context = {
            "user_id": username,
            "team_id": get_team_id_from_user(username, user_data),
            "groups": user_data.get("groups", []),
            "api_key_id": api_key if api_key else api_key_config.get('id', 'inline_config')
        }
        logger.info(f"Processing API key with user_context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context, api_key_config)
    else:
        api_key_claims = get_additional_claims(None, user_context, None)

    # Log which API key is being used
    if api_key_config:
        logger.info(f"Using inline API key configuration: {api_key_config.get('id', 'no-id')}")
    elif api_key:
        logger.info(f"Using provided API key: {api_key}")
    else:
        logger.info("No API key provided, using base API key")

    # Merge user data with additional claims and GES claims
    claims = {**user_data, **ges_claims, **api_key_claims}
    
    # Remove groups from claims as they're already processed
    claims.pop("groups", None)
    
    # Get expiration time from API key configuration if available
    expires_delta = JWT_ACCESS_TOKEN_EXPIRES
    if 'exp_hours' in claims:
        expires_delta = timedelta(hours=claims['exp_hours'])
        logger.info(f"Using custom expiration time from API key: {claims['exp_hours']} hours")
        claims.pop('exp_hours')
    
    # If custom secret is provided, use it with PyJWT directly
    if custom_secret:
        import datetime as dt
        
        logger.info(f"Using custom secret for token generation")
        
        now = dt.datetime.now(dt.timezone.utc)
        access_token_exp = now + expires_delta
        refresh_token_exp = now + JWT_REFRESH_TOKEN_EXPIRES
        
        access_payload = {
            "iat": now,
            "nbf": now,
            "jti": str(uuid.uuid4()),
            "exp": access_token_exp,
            "sub": username,
            "type": "access",
            "fresh": True,
            **claims
        }
        
        refresh_payload = {
            "iat": now,
            "nbf": now,
            "jti": str(uuid.uuid4()),
            "exp": refresh_token_exp,
            "sub": username,
            "type": "refresh",
            **claims
        }
        
        algorithm = JWT_ALGORITHM
        access_token = pyjwt.encode(access_payload, custom_secret, algorithm=algorithm)
        refresh_token = pyjwt.encode(refresh_payload, custom_secret, algorithm=algorithm)
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            note="Tokens generated with custom secret - will not be usable with standard application routes unless the same secret is provided for verification"
        )
    else:
        # Standard token creation with application secret
        logger.info(f"Generated claims for user before creating tokens: username={username} claims={claims}")
        access_token = create_jwt_token(username, claims, expires_delta, "access")
        refresh_token = create_jwt_token(username, claims, JWT_REFRESH_TOKEN_EXPIRES, "refresh")
        
        # Check if JWE encryption is enabled for this API key
        jwe_config = get_jwe_config_from_api_key(api_key, api_key_config)
        
        if jwe_config:
            logger.info("JWE encryption enabled, encrypting tokens")
            try:
                encryption_key = jwe_config.get('encryption_key')
                if encryption_key and encryption_key.startswith('${') and encryption_key.endswith('}'):
                    env_var = encryption_key[2:-1]
                    encryption_key = os.getenv(env_var)
                    if not encryption_key:
                        logger.error(f"JWE encryption key environment variable not set: {env_var}")
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="JWE encryption key not configured"
                        )
                
                content_encryption = jwe_config.get('encryption', 'A256GCM')
                compression = jwe_config.get('compression', None)
                
                kid = claims.get('key') if claims else None
                
                encrypted_access_token = encrypt_jwt_token(
                    access_token,
                    encryption_key,
                    content_encryption,
                    compression,
                    kid=kid
                )
                encrypted_refresh_token = encrypt_jwt_token(
                    refresh_token,
                    encryption_key,
                    content_encryption,
                    compression,
                    kid=kid
                )
                
                return TokenResponse(
                    access_token=encrypted_access_token,
                    refresh_token=encrypted_refresh_token,
                    token_type="JWE",
                    encryption=content_encryption,
                    note="Tokens are JWE-encrypted. Use /decrypt-jwe endpoint to extract JWT."
                )
                
            except Exception as e:
                logger.error(f"Error encrypting tokens with JWE: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"JWE encryption failed: {str(e)}"
                )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )

@app.post("/refresh")
async def refresh(current_user_data: tuple = Depends(get_current_user_refresh)):
    current_user, jwt_payload = current_user_data
    
    # Remove JWT reserved claims that shouldn't be transferred
    reserved_claims = ['exp', 'iat', 'nbf', 'jti', 'type', 'fresh']
    additional_claims = {key: value for key, value in jwt_payload.items() 
                         if key not in reserved_claims}
    
    # Create new access token with the same additional claims
    access_token = create_jwt_token(current_user, additional_claims, JWT_ACCESS_TOKEN_EXPIRES, "access")
    
    logger.info(f"Refreshing token for user {current_user} with claims: {additional_claims}")
    
    return {"access_token": access_token}

@app.post("/decode")
async def decode(decode_data: DecodeRequest):
    token = decode_data.token
    skip_verification = decode_data.skipVerification
    custom_secret = decode_data.secret
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing token"
        )
    
    # Determine which secret to use
    secret_key = custom_secret if custom_secret else JWT_SECRET_KEY
    algorithm = JWT_ALGORITHM
    
    try:
        # First attempt standard verification
        try:
            if custom_secret:
                decoded = pyjwt.decode(token, secret_key, algorithms=[algorithm])
                decoded["note"] = "Decoded using provided custom secret"
            else:
                decoded = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[algorithm])
            return decoded
        except Exception as e:
            # If verification fails and skipVerification is enabled, try decoding without verification
            if skip_verification:
                # Decode without verification for debugging purposes
                try:
                    decoded = pyjwt.decode(token, options={"verify_signature": False})
                    decoded["warning"] = "Token signature verification was skipped! This token may not be valid."
                    if custom_secret:
                        decoded["note"] = "Custom secret was provided but not used due to skip verification"
                    return decoded
                except Exception as inner_e:
                    # If even non-verified decoding fails, it's likely not a valid JWT format
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid token format: {str(inner_e)}"
                    )
            else:
                # If not skipping verification, return the original error
                error_msg = str(e)
                if custom_secret:
                    error_msg += " (using provided custom secret)"
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_msg
                )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )

@app.post("/validate", response_model=ValidateResponse)
async def validate_token(validate_data: ValidateRequest):
    token = validate_data.token
    
    try:
        # Attempt to decode the token with verify=True (default) to check signature
        decoded = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # If we get here, token is valid
        expiry = datetime.utcfromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S UTC')
        issue_time = datetime.utcfromtimestamp(decoded['iat']).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Check if token is expired
        is_expired = datetime.utcfromtimestamp(decoded['exp']) < datetime.utcnow()
        
        return ValidateResponse(
            valid=True,
            signature_verified=True,
            expired=is_expired,
            expiry_time=expiry,
            issued_at=issue_time,
            issuer=decoded.get('iss', 'Not specified'),
            subject=decoded.get('sub', 'Not specified')
        )
    except Exception as e:
        # Determine type of error
        error_msg = str(e)
        signature_failed = "signature" in error_msg.lower()
        expired = "expired" in error_msg.lower()
        
        # Return detailed validation result
        return ValidateResponse(
            valid=False,
            signature_verified=not signature_failed,
            expired=expired,
            error=error_msg
        )

@app.get("/protected")
async def protected(current_user: str = Depends(get_current_user)):
    return {"logged_in_as": current_user}

@app.post("/sensitive-action")
async def sensitive_action(current_user: str = Depends(get_current_user_fresh)):
    """This endpoint requires a fresh token (from direct login, not from refresh)"""
    return {
        "message": "Sensitive action performed successfully",
        "user": current_user,
        "token_status": "Fresh token confirmed",
        "action_time": str(datetime.now())
    }

# API Key Management Endpoints
@app.get("/api-keys")
async def get_api_keys(admin_data: tuple = Depends(get_admin_user)):
    """Get a list of all API keys"""
    current_user, claims = admin_data
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    if not os.path.exists(api_keys_dir):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API keys directory not found"
        )
    
    # Get all API key files (excluding base key)
    api_key_files = glob.glob(os.path.join(api_keys_dir, "*.yaml"))
    api_keys = []
    
    for key_file in api_key_files:
        filename = os.path.basename(key_file)
        if filename != BASE_API_KEY_FILE:
            try:
                with open(key_file, 'r') as f:
                    key_data = yaml.safe_load(f)
                    
                api_keys.append({
                    'filename': filename,
                    'id': key_data.get('id', ''),
                    'owner': key_data.get('owner', ''),
                    'provider_permissions': key_data.get('provider_permissions', []),
                    'endpoint_permissions': key_data.get('endpoint_permissions', []),
                    'static_claims': key_data.get('claims', {}).get('static', {})
                })
            except Exception as e:
                logger.error(f"Error reading API key file {filename}: {str(e)}")
    
    return api_keys

@app.get("/api-keys/{api_key_id}")
async def get_api_key(api_key_id: str, admin_data: tuple = Depends(get_admin_user)):
    """Get details for a specific API key"""
    current_user, claims = admin_data
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Look for the API key file
    api_key_files = glob.glob(os.path.join(api_keys_dir, "*.yaml"))
    
    for key_file in api_key_files:
        try:
            with open(key_file, 'r') as f:
                key_data = yaml.safe_load(f)
                
                if key_data.get('id') == api_key_id:
                    return key_data
        except Exception as e:
            logger.error(f"Error reading API key file {key_file}: {str(e)}")
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="API key not found"
    )

@app.post("/api-keys")
async def create_api_key(api_key_data: CreateAPIKeyRequest, admin_data: tuple = Depends(get_admin_user)):
    """Create a new API key"""
    current_user, claims = admin_data
    
    # Generate API key string and ID
    api_key_string = str(uuid.uuid4()).replace('-', '')
    api_key_id = f"api-key-{str(uuid.uuid4())[:8]}"
    
    # Create API key data
    api_key_config = {
        'id': api_key_id,
        'owner': api_key_data.owner,
        'provider_permissions': api_key_data.provider_permissions,
        'endpoint_permissions': api_key_data.endpoint_permissions,
        'claims': {
            'static': api_key_data.static_claims,
            'dynamic': api_key_data.dynamic_claims
        }
    }
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Ensure API keys directory exists
    if not os.path.exists(api_keys_dir):
        os.makedirs(api_keys_dir)
    
    # Save API key to file
    api_key_file = os.path.join(api_keys_dir, f"{api_key_string}.yaml")
    
    try:
        with open(api_key_file, 'w') as f:
            yaml.dump(api_key_config, f, default_flow_style=False)
    except Exception as e:
        logger.error(f"Error creating API key file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create API key: {str(e)}"
        )
    
    # Return API key data with the key string
    return {
        **api_key_config,
        'api_key': api_key_string
    }

@app.put("/api-keys/{api_key_string}")
async def update_api_key(api_key_string: str, update_data: UpdateAPIKeyRequest, admin_data: tuple = Depends(get_admin_user)):
    """Update an existing API key"""
    current_user, claims = admin_data
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Check if API key file exists
    api_key_file = os.path.join(api_keys_dir, f"{api_key_string}.yaml")
    
    if not os.path.exists(api_key_file):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    try:
        # Read existing API key data
        with open(api_key_file, 'r') as f:
            existing_data = yaml.safe_load(f)
        
        # Update API key data with new values while preserving the ID
        api_key_id = existing_data['id']
        
        # Update fields from request data
        updated_data = {
            'id': api_key_id,
            'owner': update_data.owner if update_data.owner is not None else existing_data.get('owner'),
            'provider_permissions': update_data.provider_permissions if update_data.provider_permissions is not None else existing_data.get('provider_permissions', []),
            'endpoint_permissions': update_data.endpoint_permissions if update_data.endpoint_permissions is not None else existing_data.get('endpoint_permissions', []),
            'claims': {
                'static': update_data.static_claims if update_data.static_claims is not None else existing_data.get('claims', {}).get('static', {}),
                'dynamic': update_data.dynamic_claims if update_data.dynamic_claims is not None else existing_data.get('claims', {}).get('dynamic', {})
            }
        }
        
        # Save updated API key to file
        with open(api_key_file, 'w') as f:
            yaml.dump(updated_data, f, default_flow_style=False)
        
        return updated_data
    except Exception as e:
        logger.error(f"Error updating API key: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update API key: {str(e)}"
        )

@app.delete("/api-keys/{api_key_string}")
async def delete_api_key(api_key_string: str, admin_data: tuple = Depends(get_admin_user)):
    """Delete an API key"""
    current_user, claims = admin_data
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Check if API key file exists
    api_key_file = os.path.join(api_keys_dir, f"{api_key_string}.yaml")
    
    if not os.path.exists(api_key_file):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    try:
        # Delete API key file
        os.remove(api_key_file)
        return {"message": "API key deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting API key: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete API key: {str(e)}"
        )

@app.post("/encrypt-jwe")
async def encrypt_jwe(encrypt_data: JWEEncryptRequest):
    """
    Encrypt a JWT token or payload using JWE (JSON Web Encryption)
    """
    token = encrypt_data.token
    payload = encrypt_data.payload
    encryption_key = encrypt_data.encryption_key
    content_encryption = encrypt_data.encryption
    compression = encrypt_data.compression
    
    if not encryption_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing encryption_key"
        )
    
    if not token and not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either token or payload must be provided"
        )
    
    try:
        if token:
            # Encrypt JWT token
            encrypted = encrypt_jwt_token(
                token,
                encryption_key,
                content_encryption,
                compression
            )
        else:
            # Encrypt payload directly
            encrypted = encrypt_payload_to_jwe(
                payload,
                encryption_key,
                content_encryption,
                compression
            )
        
        return {
            "jwe_token": encrypted,
            "encryption": content_encryption,
            "compression": compression
        }
        
    except Exception as e:
        logger.error(f"Error encrypting with JWE: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Encryption failed: {str(e)}"
        )

@app.post("/decrypt-jwe")
async def decrypt_jwe(decrypt_data: JWEDecryptRequest):
    """
    Decrypt a JWE token to retrieve the JWT token or payload
    """
    jwe_token = decrypt_data.jwe_token
    encryption_key = decrypt_data.encryption_key
    content_encryption = decrypt_data.encryption
    extract_jwt = decrypt_data.extract_jwt
    
    if not jwe_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing jwe_token"
        )
    
    if not encryption_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing encryption_key"
        )
    
    try:
        if extract_jwt:
            # Decrypt to get JWT token
            jwt_token = decrypt_jwe_token(
                jwe_token,
                encryption_key,
                content_encryption
            )
            return {
                "jwt_token": jwt_token,
                "note": "Use /decode endpoint to decode the JWT token"
            }
        else:
            # Decrypt to get full payload
            payload = decrypt_jwe_to_payload(
                jwe_token,
                encryption_key,
                content_encryption
            )
            return {
                "payload": payload
            }
        
    except Exception as e:
        logger.error(f"Error decrypting JWE: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {str(e)}"
        )

@app.post("/generate-jwe-key")
async def generate_jwe_key(key_gen_data: JWEKeyGenRequest = Body(default=None)):
    """
    Generate a new symmetric encryption key for JWE
    """
    algorithm = key_gen_data.algorithm if key_gen_data else "A256GCM"
    output_format = key_gen_data.format if key_gen_data else "base64"
    
    try:
        key = JWEHandler.generate_encryption_key(algorithm, output_format)
        
        return {
            "encryption_key": key,
            "algorithm": algorithm,
            "format": output_format,
            "key_size_bytes": JWEHandler.KEY_SIZES[algorithm],
            "note": "Store this key securely! Add it to your environment variables."
        }
        
    except Exception as e:
        logger.error(f"Error generating JWE key: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key generation failed: {str(e)}"
        )

@app.get("/debug/request-info")
@app.post("/debug/request-info")
async def request_debug_info(request: Request):
    """
    Endpoint that returns detailed information about the current request and response.
    Useful for debugging HTTP interactions and API testing.
    """
    # Collect request information
    request_info = {
        "headers": dict(request.headers),
        "method": request.method,
        "url": str(request.url),
        "path": request.url.path,
        "query_params": dict(request.query_params),
        "cookies": request.cookies,
        "client_host": request.client.host if request.client else None,
    }
    
    # Try to get JSON body for POST requests
    json_body = None
    if request.method == "POST":
        try:
            json_body = await request.json()
        except:
            json_body = "Could not parse JSON body"
    
    request_info["json_body"] = json_body
    
    # Check for JWT token in Authorization header
    jwt_info = {}
    auth_header = request.headers.get('authorization', '')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        jwt_info["token"] = token
        
        # Check for custom secret in query parameters
        custom_secret = request.query_params.get('secret', None)
        if custom_secret:
            jwt_info["using_custom_secret"] = True
            
        # Determine which secret to use
        secret_key = custom_secret if custom_secret else JWT_SECRET_KEY
        algorithm = JWT_ALGORITHM
        
        # Try to decode the token without verification
        try:
            # First attempt standard verification
            try:
                decoded = pyjwt.decode(token, secret_key, algorithms=[algorithm])
                jwt_info["decoded"] = decoded
                jwt_info["verified"] = True
            except Exception as e:
                # If verification fails, try decoding without verification
                jwt_info["verification_error"] = str(e)
                jwt_info["verified"] = False
                jwt_info["warning"] = "Token signature verification failed! Showing unverified token contents."
                
                # Decode without verification
                decoded = pyjwt.decode(token, options={"verify_signature": False})
                jwt_info["decoded"] = decoded
        except Exception as e:
            jwt_info["error"] = f"Failed to decode token: {str(e)}"
    
    # Create response with detailed information
    response_data = {
        "request_info": request_info,
        "jwt_info": jwt_info if jwt_info else None,
        "response_info": {
            "status_code": 200,
            "timestamp": str(datetime.now())
        }
    }
    
    return response_data

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        "main:app",
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        reload=True
    )
