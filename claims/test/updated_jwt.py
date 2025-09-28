# --- helpers ---------------------------------------------------------------

import os
import re
import yaml
import logging
from datetime import timedelta
from flask import request, jsonify

logger = logging.getLogger(__name__)


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


# --- /token route ----------------------------------------------------------

@app.route('/token', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get("username")
    password = request.json.get("password")
    api_key = request.json.get("api_key")
    custom_secret = request.json.get("secret")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Authenticate based on the configured method
    if AUTH_METHOD == "ldap":
        authenticated, user_data = authenticate_ldap(username, password)
    else:
        authenticated, user_data = authenticate_file(username, password)

    if not authenticated:
        error_message = user_data.get("error", "Invalid username or password")
        return jsonify({"error": error_message}), 401

    # Prepare group info
    raw_groups = user_data.get("groups", [])
    normalized_groups = extract_group_cn(raw_groups)

    # API-key pre-validation (if provided)
    ges_claims = {}
    if api_key:
        validation_result = user_pre_validation(api_key, normalized_groups, username)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "details": validation_result.get("details"),
                "user_ad_groups": validation_result.get("user_ad_groups")
            }), 403

        try:
            from claims.ges_claims import get_ges_claims_from_api_key
            ges_claims = get_ges_claims_from_api_key(username, api_key)
        except Exception as e:
            logger.error(f"Error fetching GES claims: {str(e)}")
            ges_claims = {}

    # Create a proper user context for dynamic claims
    user_context = {
        "user_id": username,
        "team_id": get_team_id_from_user(username, user_data),
        "groups": normalized_groups,
        "api_key_id": api_key,
    }

    # Process API key (dynamic claims)
    if api_key:
        logger.info(f"Processing API key with user context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        api_key_claims = get_additional_claims(None, user_context)

    # Merge user data with additional claims
    claims = {**user_data, **ges_claims, **api_key_claims}
    claims.pop("groups", None)

    # Determine expiration time
    expires_delta = app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    if "exp_hours" in claims:
        expires_delta = timedelta(hours=claims.pop("exp_hours"))

    # If custom secret is provided, use PyJWT directly
    if custom_secret:
        import jwt
        import datetime as dt
        import uuid

        logger.info("Using custom secret for token generation")
        now = dt.datetime.now(dt.timezone.utc)
        access_token_exp = now + expires_delta
        refresh_token_exp = now + app.config["JWT_REFRESH_TOKEN_EXPIRES"]

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

        algorithm = app.config.get("JWT_ALGORITHM", "HS256")
        access_token = jwt.encode(access_payload, custom_secret, algorithm=algorithm)
        refresh_token = jwt.encode(refresh_payload, custom_secret, algorithm=algorithm)

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "note": "Tokens generated with custom secret"
        }), 200

    # Standard token creation
    logger.info(f"Generated claims for user before creating tokens: username={username} claims={claims}")
    access_token = create_access_token(
        identity=username,
        additional_claims=claims,
        expires_delta=expires_delta,
        fresh=True
    )
    refresh_token = create_refresh_token(
        identity=username,
        additional_claims=claims
    )
    return jsonify(access_token=access_token, refresh_token=refresh_token), 200
