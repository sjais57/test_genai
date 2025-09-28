def check_pre_validation(api_key: str, ad_groups: list, username: str) -> dict:
    """
    Check if the user meets the pre-validation requirements for the API key
    Uses existing GES integration service for GES group checks
    
    Args:
        api_key: The API key string
        ad_groups: List of AD/LDAP groups from user
        username: The username for GES lookup
        
    Returns:
        Dict with validation result and message
    """
    
    def parse_comma_separated_groups(group_config: str) -> list:
        """
        Parse comma-separated groups configuration
        
        Args:
            group_config: Comma-separated string of groups
            
        Returns:
            List of normalized group names
        """
        if not group_config:
            return []
        
        groups = [group.strip() for group in group_config.split(',')]
        return [_normalize(group) for group in groups if group]
    
    try:
        # Load the API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        if not os.path.exists(api_key_file):
            return {
                "valid": False,
                "message": "Invalid API key"
            }
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Check if pre_validation_check is configured
        pre_validation_config = api_key_config.get('pre_validation_check')
        if not pre_validation_config:
            # No pre-validation required
            return {
                "valid": True,
                "message": "No pre-validation required"
            }
        
        # Parse required groups (comma-separated)
        if isinstance(pre_validation_config, dict):
            # New format: check both LDAP and GES sections
            ldap_groups_config = pre_validation_config.get('LDAP', '')
            ges_namespaces_config = pre_validation_config.get('GES', '')
            
            required_ldap_groups = parse_comma_separated_groups(ldap_groups_config)
            required_ges_namespaces = [ns.strip() for ns in ges_namespaces_config.split(',')] if ges_namespaces_config else []
        else:
            # Old format: treat as LDAP groups only
            required_ldap_groups = parse_comma_separated_groups(str(pre_validation_config))
            required_ges_namespaces = []
        
        logger.info(f"Required LDAP groups: {required_ldap_groups}")
        logger.info(f"Required GES namespaces: {required_ges_namespaces}")
        
        # If no requirements specified, validation passes
        if not required_ldap_groups and not required_ges_namespaces:
            return {
                "valid": True,
                "message": "No specific validation requirements"
            }
        
        # Get user's AD groups (normalized)
        normalized_ad_groups = [_normalize(group) for group in ad_groups]
        logger.info(f"User AD groups: {normalized_ad_groups}")
        
        # Check LDAP groups first - user needs to be in ANY of the required groups
        if required_ldap_groups:
            ldap_matches = [group for group in required_ldap_groups if group in normalized_ad_groups]
            if ldap_matches:
                return {
                    "valid": True,
                    "message": f"User has access via LDAP groups: {', '.join(ldap_matches)}",
                    "matched_groups": ldap_matches,
                    "source": "LDAP"
                }
        
        # Check GES namespace membership using existing GES service
        if required_ges_namespaces and GES_AVAILABLE:
            logger.info("Checking GES namespace membership using GES service")
            
            # Use the existing GES service to check namespace membership
            user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, required_ges_namespaces)
            logger.info(f"User GES namespace groups: {user_namespace_groups}")
            
            # Check if user has ANY groups in ANY of the required namespaces
            accessible_namespaces = []
            for namespace, groups in user_namespace_groups.items():
                if groups:  # User has at least one group in this namespace
                    accessible_namespaces.append(namespace)
            
            if accessible_namespaces:
                return {
                    "valid": True,
                    "message": f"User has access via GES namespaces: {', '.join(accessible_namespaces)}",
                    "matched_namespaces": accessible_namespaces,
                    "user_ges_groups": user_namespace_groups,
                    "source": "GES"
                }
        
        # No matches found
        return {
            "valid": False,
            "message": f"User does not have access to any required groups or namespaces",
            "required_ldap_groups": required_ldap_groups,
            "required_ges_namespaces": required_ges_namespaces,
            "user_ad_groups": ad_groups,
            "user_ges_groups": user_namespace_groups if 'user_namespace_groups' in locals() else {}
        }
            
    except Exception as e:
        logger.error(f"Error during pre-validation check: {str(e)}")
        return {
            "valid": False,
            "message": f"Error during validation: {str(e)}"
        }


===============
import os
import re
from datetime import timedelta, datetime
from flask import Flask, jsonify, request, make_response, render_template, send_from_directory
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, decode_token, get_jwt
)
from dotenv import load_dotenv
import logging
import pathlib
import yaml
import uuid
import glob
from flask_swagger_ui import get_swaggerui_blueprint
from swagger_config import get_swagger_dict, get_swagger_json, get_swagger_yaml

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

# Import GES integration
try:
    from auth.ges_integration import ges_service
    GES_AVAILABLE = True
except ImportError:
    logger.warning("GES integration not available - ges_entitylements may not be installed")
    GES_AVAILABLE = False

# Ensure the templates directory exists
templates_dir = pathlib.Path(__file__).parent / 'templates'
templates_dir.mkdir(exist_ok=True)

# Initialize Flask app
app = Flask(__name__, 
            template_folder=str(templates_dir))

# Configure Swagger UI
SWAGGER_URL = '/dspai-docs'  # URL for exposing Swagger UI
API_URL = '/swagger.json'  # Where to get the swagger spec from

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "JWT Auth API Documentation",
        'deepLinking': True,
        'defaultModelsExpandDepth': 2,
        'defaultModelExpandDepth': 2,
    }
)

# Register the Swagger UI blueprint
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Endpoints to serve the Swagger specification
@app.route('/swagger.json')
def swagger_json():
    return get_swagger_json()

@app.route('/swagger.yaml')
def swagger_yaml():
    return get_swagger_yaml()

# Configure Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # Default if not specified in API key
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

# Authentication method
AUTH_METHOD = os.getenv("AUTH_METHOD", "file")  # "ldap" or "file"

# Whether to always include base API key claims
ALWAYS_USE_BASE_CLAIMS = os.getenv("ALWAYS_USE_BASE_CLAIMS", "true").lower() == "true"

# Check if LDAP is requested but not available
if AUTH_METHOD == "ldap" and not LDAP_AVAILABLE:
    logger.warning("LDAP authentication method selected but python-ldap is not installed.")
    logger.warning("Falling back to file-based authentication.")
    logger.warning("To use LDAP authentication, install python-ldap: pip install python-ldap")
    AUTH_METHOD = "file"

jwt = JWTManager(app)

@app.route('/')
def index():
    return render_template('index.html')

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
    """
    Extract group common names from LDAP group data
    
    Args:
        groups: List of groups from LDAP (can be strings or dicts)
        
    Returns:
        List of group common names in lowercase
    """
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
    """
    Parse comma-separated groups configuration
    
    Args:
        group_config: Comma-separated string of groups
        
    Returns:
        List of normalized group names
    """
    if not group_config:
        return []
    
    groups = [group.strip() for group in group_config.split(',')]
    return [_normalize(group) for group in groups if group]

def check_pre_validation(api_key: str, ad_groups: list, username: str) -> dict:
    """
    Check if the user meets the pre-validation requirements for the API key
    Uses existing GES integration service for GES group checks
    
    Args:
        api_key: The API key string
        ad_groups: List of AD/LDAP groups from user
        username: The username for GES lookup
        
    Returns:
        Dict with validation result and message
    """
    try:
        # Load the API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        if not os.path.exists(api_key_file):
            return {
                "valid": False,
                "message": "Invalid API key"
            }
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Check if pre_validation_check is configured
        pre_validation_config = api_key_config.get('pre_validation_check')
        if not pre_validation_config:
            # No pre-validation required
            return {
                "valid": True,
                "message": "No pre-validation required"
            }
        
        # Parse required groups (comma-separated)
        if isinstance(pre_validation_config, dict):
            # New format: check both LDAP and GES sections
            ldap_groups_config = pre_validation_config.get('LDAP', '')
            ges_namespaces_config = pre_validation_config.get('GES', '')
            
            required_ldap_groups = parse_comma_separated_groups(ldap_groups_config)
            required_ges_namespaces = [ns.strip() for ns in ges_namespaces_config.split(',')] if ges_namespaces_config else []
        else:
            # Old format: treat as LDAP groups only
            required_ldap_groups = parse_comma_separated_groups(str(pre_validation_config))
            required_ges_namespaces = []
        
        logger.info(f"Required LDAP groups: {required_ldap_groups}")
        logger.info(f"Required GES namespaces: {required_ges_namespaces}")
        
        # If no requirements specified, validation passes
        if not required_ldap_groups and not required_ges_namespaces:
            return {
                "valid": True,
                "message": "No specific validation requirements"
            }
        
        # Get user's AD groups (normalized)
        normalized_ad_groups = [_normalize(group) for group in ad_groups]
        logger.info(f"User AD groups: {normalized_ad_groups}")
        
        # Check LDAP groups first - user needs to be in ANY of the required groups
        if required_ldap_groups:
            ldap_matches = [group for group in required_ldap_groups if group in normalized_ad_groups]
            if ldap_matches:
                return {
                    "valid": True,
                    "message": f"User has access via LDAP groups: {', '.join(ldap_matches)}",
                    "matched_groups": ldap_matches,
                    "source": "LDAP"
                }
        
        # Check GES namespace membership using existing GES service
        if required_ges_namespaces and GES_AVAILABLE:
            logger.info("Checking GES namespace membership using GES service")
            
            # Use the existing GES service to check namespace membership
            user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, required_ges_namespaces)
            logger.info(f"User GES namespace groups: {user_namespace_groups}")
            
            # Check if user has ANY groups in ANY of the required namespaces
            accessible_namespaces = []
            for namespace, groups in user_namespace_groups.items():
                if groups:  # User has at least one group in this namespace
                    accessible_namespaces.append(namespace)
            
            if accessible_namespaces:
                return {
                    "valid": True,
                    "message": f"User has access via GES namespaces: {', '.join(accessible_namespaces)}",
                    "matched_namespaces": accessible_namespaces,
                    "user_ges_groups": user_namespace_groups,
                    "source": "GES"
                }
        
        # No matches found
        return {
            "valid": False,
            "message": f"User does not have access to any required groups or namespaces",
            "required_ldap_groups": required_ldap_groups,
            "required_ges_namespaces": required_ges_namespaces,
            "user_ad_groups": ad_groups,
            "user_ges_groups": user_namespace_groups if 'user_namespace_groups' in locals() else {}
        }
            
    except Exception as e:
        logger.error(f"Error during pre-validation check: {str(e)}")
        return {
            "valid": False,
            "message": f"Error during validation: {str(e)}"
        }

@app.route('/token', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    api_key = request.json.get('api_key', None)
    custom_secret = request.json.get('secret', None)

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Authenticate based on the configured method
    if AUTH_METHOD == "ldap":
        authenticated, user_data = authenticate_ldap(username, password)
    else:  # file-based authentication
        authenticated, user_data = authenticate_file(username, password)

    if not authenticated:
        error_message = "Invalid username or password"
        if "error" in user_data:
            error_message = user_data["error"]
        return jsonify({"error": error_message}), 401
    
    raw_groups = user_data.get("groups", [])
    normalized_ad_groups = extract_group_cn(raw_groups)

    # Create user context for dynamic claims processing
    user_context = {
        "user_id": username,
        "email": user_data.get("email", ""),
        "groups": normalized_ad_groups,
        "roles": user_data.get("roles", []),
        "team_id": get_team_id_from_user(username, user_data)
    }

    # If an API key was provided, check pre-validation and get additional claims
    if api_key:
        # Check pre-validation before processing API key
        validation_result = check_pre_validation(api_key, normalized_ad_groups, username)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "required_ldap_groups": validation_result.get("required_ldap_groups"),
                "required_ges_namespaces": validation_result.get("required_ges_namespaces"),
                "user_ad_groups": validation_result.get("user_ad_groups"),
                "user_ges_groups": validation_result.get("user_ges_groups")
            }), 403
        
        logger.info(f"Pre-validation passed: {validation_result.get('message')}")
        
        # Create a proper user context for dynamic claims
        user_context = {
            "user_id": username,
            "team_id": get_team_id_from_user(username, user_data),
            "groups": normalized_ad_groups,
            "api_key_id": api_key
        }
        logger.info(f"Processing API key with user_context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        api_key_claims = get_additional_claims(None, user_context)

    # Log which API key is being used
    if api_key:
        logger.info(f"Using provided API key: {api_key}")
    else:
        logger.info("No API key provided, using base API key")

    # Merge user data with additional claims
    claims = {**user_data, **api_key_claims}
    
    # Get expiration time from API key configuration if available
    expires_delta = app.config["JWT_ACCESS_TOKEN_EXPIRES"]  # Default
    if 'exp_hours' in claims:
        expires_delta = timedelta(hours=claims['exp_hours'])
        logger.info(f"Using custom expiration time from API key: {claims['exp_hours']} hours")
        # Remove exp_hours from claims to avoid conflicts
        claims.pop('exp_hours')
    
    # If custom secret is provided, use it with PyJWT directly instead of flask_jwt_extended
    if custom_secret:
        import jwt
        import datetime as dt
        
        # Log that we're using a custom secret
        logger.info(f"Using custom secret for token generation")
        
        # Prepare the payload with the standard JWT claims
        now = dt.datetime.now(dt.timezone.utc)
        access_token_exp = now + expires_delta
        refresh_token_exp = now + app.config["JWT_REFRESH_TOKEN_EXPIRES"]
        
        # Add standard JWT claims to the payload
        access_payload = {
            "iat": now,
            "nbf": now,
            "jti": str(uuid.uuid4()),
            "exp": access_token_exp,
            "sub": username,
            "type": "access",
            "fresh": True,
            **claims  # Include all the additional claims
        }
        
        refresh_payload = {
            "iat": now,
            "nbf": now,
            "jti": str(uuid.uuid4()),
            "exp": refresh_token_exp,
            "sub": username,
            "type": "refresh",
            **claims  # Include all the additional claims
        }
        
        # Generate the tokens using PyJWT directly with the custom secret
        algorithm = app.config.get('JWT_ALGORITHM', 'HS256')
        access_token = jwt.encode(access_payload, custom_secret, algorithm=algorithm)
        refresh_token = jwt.encode(refresh_payload, custom_secret, algorithm=algorithm)
        
        # Add note to response indicating custom secret was used
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "note": "Tokens generated with custom secret - will not be usable with standard application routes unless the same secret is provided for verification"
        }), 200
    else:
        # Standard token creation with application secret
        access_token = create_access_token(
            identity=username, 
            additional_claims=claims,
            expires_delta=expires_delta,
            fresh=True  # Mark the token as fresh since it's from direct login
        )
        refresh_token = create_refresh_token(identity=username, additional_claims=claims)
        
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

def get_team_id_from_user(username, user_data):
    """
    Determine the team ID from the user's data
    This is a simple implementation - in a real app, you would look this up from a database
    
    Args:
        username: The username of the user
        user_data: The user data retrieved during authentication
        
    Returns:
        A team ID string
    """
    # Simple mapping based on groups
    groups = user_data.get("groups", [])
    
    if "administrators" in groups or "admins" in groups:
        return "admin-team"
    elif "ai-team" in groups:
        return "ai-team"
    elif "ml-team" in groups:
        return "ml-team"
    
    # Default team
    return "general-users"

# ... (rest of the endpoints remain the same)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
