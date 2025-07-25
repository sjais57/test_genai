import os
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
from claims.group_category import get_user_category
from utils.api_key import get_api_key_metadata


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

    # Create user context for dynamic claims processing
    user_context = {
        "user_id": username,
        "email": user_data.get("email", ""),
        "groups": user_data.get("groups", []),
        "roles": user_data.get("roles", []),
        "team_id": get_team_id_from_user(username, user_data)
    }

    # If an API key was provided, get additional claims to include in the token
    if api_key:
        # Create a proper user context for dynamic claims
        user_context = {
            "user_id": username,
            "team_id": get_team_id_from_user(username, user_data),
            "groups": user_data.get("groups", []),  # Ensure groups is included for dynamic claims
            # Additional context that might be needed by dynamic claims
            "api_key_id": api_key  # Use the API key itself as an ID if needed
        }
        logger.info(f"Processing API key with user_context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context)
		api_key_metadata = get_api_key_metadata(api_key)
		if "user_category" not in api_key_claims:
			user_category = get_user_category(
				user_groups=user_context.get("groups", []),
				lookup_mode="TIERED_MATCH",
				metadata=api_key_metadata
			)
			api_key_claims["user_category"] = user_category
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

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    # Get all claims from the current refresh token
    jwt_claims = get_jwt()
    
    # Remove JWT reserved claims that shouldn't be transferred
    reserved_claims = ['exp', 'iat', 'nbf', 'jti', 'type', 'fresh']
    additional_claims = {key: value for key, value in jwt_claims.items() 
                         if key not in reserved_claims}
    
    # Create new access token with the same additional claims
    access_token = create_access_token(
        identity=current_user,
        additional_claims=additional_claims
    )
    
    # Log the claims being carried over
    logger.info(f"Refreshing token for user {current_user} with claims: {additional_claims}")
    
    return jsonify(access_token=access_token), 200

@app.route('/decode', methods=['POST'])
def decode():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    token = request.json.get('token', None)
    if not token:
        return jsonify({"error": "Missing token"}), 400
        
    skip_verification = request.json.get('skipVerification', False)
    custom_secret = request.json.get('secret')
    
    # Determine which secret to use
    secret_key = custom_secret if custom_secret else app.config['JWT_SECRET_KEY']
    algorithm = app.config['JWT_ALGORITHM']
    
    try:
        # First attempt standard verification
        try:
            import jwt
            if custom_secret:
                # Use custom secret if provided
                decoded = jwt.decode(token, secret_key, algorithms=[algorithm])
                decoded["note"] = "Decoded using provided custom secret"
            else:
                # Use system default decode_token method
                decoded = decode_token(token)
            return jsonify(decoded), 200
        except Exception as e:
            # If verification fails and skipVerification is enabled, try decoding without verification
            if skip_verification:
                # Decode without verification for debugging purposes
                try:
                    import jwt
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    decoded["warning"] = "Token signature verification was skipped! This token may not be valid."
                    if custom_secret:
                        decoded["note"] = "Custom secret was provided but not used due to skip verification"
                    return jsonify(decoded), 200
                except Exception as inner_e:
                    # If even non-verified decoding fails, it's likely not a valid JWT format
                    return jsonify({"error": f"Invalid token format: {str(inner_e)}"}), 400
            else:
                # If not skipping verification, return the original error
                error_msg = str(e)
                if custom_secret:
                    error_msg += " (using provided custom secret)"
                return jsonify({"error": error_msg}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route('/validate', methods=['POST'])
def validate_token():
    """Validate a JWT token's signature and expiration"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    token = request.json.get('token', None)
    if not token:
        return jsonify({"error": "Missing token"}), 400
    
    try:
        # Attempt to decode the token with verify=True (default) to check signature
        # This will raise an exception if signature is invalid or token is expired
        decoded = decode_token(token)
        
        # If we get here, token is valid
        expiry = datetime.utcfromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S UTC')
        issue_time = datetime.utcfromtimestamp(decoded['iat']).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Check if token is expired
        is_expired = datetime.utcfromtimestamp(decoded['exp']) < datetime.utcnow()
        
        return jsonify({
            "valid": True,
            "signature_verified": True,
            "expired": is_expired,
            "expiry_time": expiry,
            "issued_at": issue_time,
            "issuer": decoded.get('iss', 'Not specified'),
            "subject": decoded.get('sub', 'Not specified')
        }), 200
    except Exception as e:
        # Determine type of error
        error_msg = str(e)
        signature_failed = "signature" in error_msg.lower()
        expired = "expired" in error_msg.lower()
        
        # Return detailed validation result
        return jsonify({
            "valid": False,
            "signature_verified": not signature_failed,
            "expired": expired,
            "error": error_msg
        }), 200  # Return 200 even for invalid tokens, as this is expected behavior

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/sensitive-action', methods=['POST'])
@jwt_required(fresh=True)
def sensitive_action():
    """This endpoint requires a fresh token (from direct login, not from refresh)"""
    current_user = get_jwt_identity()
    jwt_claims = get_jwt()
    
    # Demo of a sensitive action like password change, payment, etc.
    return jsonify({
        "message": "Sensitive action performed successfully",
        "user": current_user,
        "token_status": "Fresh token confirmed",
        "token_freshness": jwt_claims.get('fresh', False),
        "action_time": str(datetime.now())
    }), 200

# API Key Management Endpoints
@app.route('/api-keys', methods=['GET'])
@jwt_required(fresh=True)
def get_api_keys():
    """Get a list of all API keys"""
    # Only allow administrators to access this endpoint
    claims = get_jwt()
    groups = claims.get('groups', [])
    
    if 'administrators' not in groups and 'admins' not in groups:
        return jsonify({"error": "Administrator access required"}), 403
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    if not os.path.exists(api_keys_dir):
        return jsonify({"error": "API keys directory not found"}), 500
    
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
    
    return jsonify(api_keys), 200

@app.route('/api-keys/<api_key_id>', methods=['GET'])
@jwt_required(fresh=True)
def get_api_key(api_key_id):
    """Get details for a specific API key"""
    # Only allow administrators to access this endpoint
    claims = get_jwt()
    groups = claims.get('groups', [])
    
    if 'administrators' not in groups and 'admins' not in groups:
        return jsonify({"error": "Administrator access required"}), 403
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Look for the API key file
    api_key_files = glob.glob(os.path.join(api_keys_dir, "*.yaml"))
    
    for key_file in api_key_files:
        try:
            with open(key_file, 'r') as f:
                key_data = yaml.safe_load(f)
                
                if key_data.get('id') == api_key_id:
                    return jsonify(key_data), 200
        except Exception as e:
            logger.error(f"Error reading API key file {key_file}: {str(e)}")
    
    return jsonify({"error": "API key not found"}), 404

@app.route('/api-keys', methods=['POST'])
@jwt_required(fresh=True)
def create_api_key():
    """Create a new API key"""
    # Only allow administrators to access this endpoint
    claims = get_jwt()
    groups = claims.get('groups', [])
    
    if 'administrators' not in groups and 'admins' not in groups:
        return jsonify({"error": "Administrator access required"}), 403
    
    # Check request data
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.json
    
    # Validate required fields
    required_fields = ['owner']
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
    
    # Generate API key string and ID
    api_key_string = str(uuid.uuid4()).replace('-', '')
    api_key_id = f"api-key-{str(uuid.uuid4())[:8]}"
    
    # Create API key data
    api_key_data = {
        'id': api_key_id,
        'owner': data['owner'],
        'provider_permissions': data.get('provider_permissions', ['openai']),
        'endpoint_permissions': data.get('endpoint_permissions', 
                                        ['/v1/chat/completions', '/v1/embeddings']),
        'claims': {
            'static': data.get('static_claims', {
                'models': ['gpt-3.5-turbo'],
                'rate_limit': 20,
                'tier': 'standard',
                'exp_hours': 1
            }),
            'dynamic': data.get('dynamic_claims', {})
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
            yaml.dump(api_key_data, f, default_flow_style=False)
    except Exception as e:
        logger.error(f"Error creating API key file: {str(e)}")
        return jsonify({"error": f"Failed to create API key: {str(e)}"}), 500
    
    # Return API key data with the key string
    return jsonify({
        **api_key_data,
        'api_key': api_key_string
    }), 201

@app.route('/api-keys/<api_key_string>', methods=['PUT'])
@jwt_required(fresh=True)
def update_api_key(api_key_string):
    """Update an existing API key"""
    # Only allow administrators to access this endpoint
    claims = get_jwt()
    groups = claims.get('groups', [])
    
    if 'administrators' not in groups and 'admins' not in groups:
        return jsonify({"error": "Administrator access required"}), 403
    
    # Check request data
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.json
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Check if API key file exists
    api_key_file = os.path.join(api_keys_dir, f"{api_key_string}.yaml")
    
    if not os.path.exists(api_key_file):
        return jsonify({"error": "API key not found"}), 404
    
    try:
        # Read existing API key data
        with open(api_key_file, 'r') as f:
            existing_data = yaml.safe_load(f)
        
        # Update API key data with new values while preserving the ID
        api_key_id = existing_data['id']
        
        # Update fields from request data
        updated_data = {
            'id': api_key_id,  # Preserve original ID
            'owner': data.get('owner', existing_data.get('owner')),
            'provider_permissions': data.get('provider_permissions', 
                                          existing_data.get('provider_permissions', [])),
            'endpoint_permissions': data.get('endpoint_permissions', 
                                          existing_data.get('endpoint_permissions', [])),
            'claims': {
                'static': data.get('static_claims', existing_data.get('claims', {}).get('static', {})),
                'dynamic': data.get('dynamic_claims', existing_data.get('claims', {}).get('dynamic', {}))
            }
        }
        
        # Save updated API key to file
        with open(api_key_file, 'w') as f:
            yaml.dump(updated_data, f, default_flow_style=False)
        
        return jsonify(updated_data), 200
    except Exception as e:
        logger.error(f"Error updating API key: {str(e)}")
        return jsonify({"error": f"Failed to update API key: {str(e)}"}), 500

@app.route('/api-keys/<api_key_string>', methods=['DELETE'])
@jwt_required(fresh=True)
def delete_api_key(api_key_string):
    """Delete an API key"""
    # Only allow administrators to access this endpoint
    claims = get_jwt()
    groups = claims.get('groups', [])
    
    if 'administrators' not in groups and 'admins' not in groups:
        return jsonify({"error": "Administrator access required"}), 403
    
    # Get API keys directory path
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    
    # Check if API key file exists
    api_key_file = os.path.join(api_keys_dir, f"{api_key_string}.yaml")
    
    if not os.path.exists(api_key_file):
        return jsonify({"error": "API key not found"}), 404
    
    try:
        # Delete API key file
        os.remove(api_key_file)
        return jsonify({"message": "API key deleted successfully"}), 200
    except Exception as e:
        logger.error(f"Error deleting API key: {str(e)}")
        return jsonify({"error": f"Failed to delete API key: {str(e)}"}), 500


@app.route('/debug/request-info', methods=['GET', 'POST'])
def request_debug_info():
    """
    Endpoint that returns detailed information about the current request and response.
    Useful for debugging HTTP interactions and API testing.
    Will attempt to decode JWT tokens even if verification fails.
    """
    # Collect request information
    request_info = {
        "headers": dict(request.headers),
        "method": request.method,
        "url": request.url,
        "path": request.path,
        "args": dict(request.args),
        "form": dict(request.form) if request.form else None,
        "json": request.get_json(silent=True),
        "cookies": dict(request.cookies),
        "remote_addr": request.remote_addr,
    }
    
    # Check for JWT token in Authorization header
    jwt_info = {}
    auth_header = request.headers.get('Authorization', '')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        jwt_info["token"] = token
        
        # Check for custom secret in query parameters
        custom_secret = request.args.get('secret', None)
        if custom_secret:
            jwt_info["using_custom_secret"] = True
            
        # Determine which secret to use
        secret_key = custom_secret if custom_secret else app.config['JWT_SECRET_KEY']
        algorithm = app.config['JWT_ALGORITHM']
        
        # Try to decode the token without verification
        try:
            # First attempt standard verification
            try:
                import jwt
                decoded = jwt.decode(token, secret_key, algorithms=[algorithm])
                jwt_info["decoded"] = decoded
                jwt_info["verified"] = True
            except Exception as e:
                # If verification fails, try decoding without verification
                jwt_info["verification_error"] = str(e)
                jwt_info["verified"] = False
                jwt_info["warning"] = "Token signature verification failed! Showing unverified token contents."
                
                # Decode without verification
                decoded = jwt.decode(token, options={"verify_signature": False})
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
    
    return jsonify(response_data), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
