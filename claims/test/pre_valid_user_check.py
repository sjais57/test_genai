# --- helpers ---------------------------------------------------------------

import os
import re
import yaml
import logging
from datetime import datetime, timezone, timedelta
from flask import request, jsonify
import pytz

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


def _check_time_constraints(start_time_str: str, end_time_str: str, timezone_str: str = "CST") -> dict:
    """
    Check if current time is within the specified time range.
    
    Args:
        start_time_str: Start time string (format: DD-MM-YYYY or DD-MM-YYYY HH:MM)
        end_time_str: End time string (format: DD-MM-YYYY or DD-MM-YYYY HH:MM)
        timezone_str: Timezone identifier (default: "CST")
    
    Returns:
        dict with 'valid' key and appropriate message
    """
    # If no time constraints specified, always valid
    if not start_time_str and not end_time_str:
        return {"valid": True, "message": "No time constraints specified"}
    
    try:
        # Get timezone
        if timezone_str.upper() == "CST":
            # CST could be US Central Standard Time
            # Try common CST timezones
            for tz_name in ["America/Chicago", "US/Central", "CST6CDT"]:
                try:
                    tz = pytz.timezone(tz_name)
                    break
                except pytz.exceptions.UnknownTimeZoneError:
                    continue
            else:
                tz = pytz.timezone("UTC")  # fallback
        else:
            tz = pytz.timezone(timezone_str)
        
        # Get current time in specified timezone
        current_time = datetime.now(timezone.utc).astimezone(tz)
        
        # Parse start time if provided
        start_time = None
        if start_time_str:
            try:
                # Try with time format first
                start_time = datetime.strptime(start_time_str, "%d-%m-%Y %H:%M")
            except ValueError:
                # Try date-only format
                start_time = datetime.strptime(start_time_str, "%d-%m-%Y")
            # Localize to the specified timezone
            start_time = tz.localize(start_time)
        
        # Parse end time if provided
        end_time = None
        if end_time_str:
            try:
                # Try with time format first
                end_time = datetime.strptime(end_time_str, "%d-%m-%Y %H:%M")
            except ValueError:
                # Try date-only format
                end_time = datetime.strptime(end_time_str, "%d-%m-%Y")
            # Localize to the specified timezone
            end_time = tz.localize(end_time)
        
        # Check if current time is before start time
        if start_time and current_time < start_time:
            return {
                "valid": False,
                "message": f"Project is not started yet. Access will be available from {start_time.strftime('%d-%m-%Y %H:%M %Z')}",
                "current_time": current_time.strftime('%d-%m-%Y %H:%M %Z'),
                "start_time": start_time.strftime('%d-%m-%Y %H:%M %Z')
            }
        
        # Check if current time is after end time
        if end_time and current_time > end_time:
            return {
                "valid": False,
                "message": f"Project access has ended. Access was available until {end_time.strftime('%d-%m-%Y %H:%M %Z')}",
                "current_time": current_time.strftime('%d-%m-%Y %H:%M %Z'),
                "end_time": end_time.strftime('%d-%m-%Y %H:%M %Z')
            }
        
        # All time checks passed
        return {
            "valid": True,
            "message": "Time constraints satisfied",
            "current_time": current_time.strftime('%d-%m-%Y %H:%M %Z')
        }
        
    except ValueError as e:
        logger.error(f"Error parsing time constraints: {str(e)}")
        return {
            "valid": False,
            "message": f"Invalid time format. Expected DD-MM-YYYY or DD-MM-YYYY HH:MM. Error: {str(e)}"
        }
    except pytz.exceptions.UnknownTimeZoneError as e:
        logger.error(f"Unknown timezone: {timezone_str}")
        return {
            "valid": False,
            "message": f"Invalid timezone: {timezone_str}"
        }
    except Exception as e:
        logger.error(f"Error checking time constraints: {str(e)}")
        return {
            "valid": False,
            "message": f"Error checking time constraints: {str(e)}"
        }


def user_pre_validation(
    api_key: str,
    normalized_groups: list,
    username: str,
    user_data: dict,
    api_key_config: dict = None
) -> dict:
    try:
        # Load API key config
        if api_key_config:
            config = api_key_config
        else:
            api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
            api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")

            if not os.path.exists(api_key_file):
                return {
                    "valid": False,
                    "message": "Invalid API key"
                }

            with open(api_key_file, "r") as f:
                config = yaml.safe_load(f)

        pre_validation_config = config.get("pre_validation_check")
        if not pre_validation_config:
            return {
                "valid": True,
                "message": "No pre-validation required"
            }

        # --- Defaults ---
        required_ldap_groups = []
        required_ldap_users = []
        required_ges_namespaces = []
        start_time_str = None
        end_time_str = None
        timezone_str = "CST"

        # --- Legacy string format ---
        if isinstance(pre_validation_config, str):
            logger.info("Using legacy pre-validation format")
            required_ldap_groups = parse_comma_separated_groups(pre_validation_config)

        # --- Structured format ---
        elif isinstance(pre_validation_config, dict):
            logger.info("Using structured pre-validation format")

            # LDAP groups
            ldap_config = pre_validation_config.get("LDAP", "")
            if isinstance(ldap_config, str):
                required_ldap_groups = parse_comma_separated_groups(ldap_config)

            # LDAP users
            ldap_users_config = pre_validation_config.get("LDAP_USER", "")
            if isinstance(ldap_users_config, str):
                required_ldap_users = [
                    u.strip().lower()
                    for u in ldap_users_config.split(",")
                    if u.strip()
                ]
            elif isinstance(ldap_users_config, list):
                required_ldap_users = [u.lower() for u in ldap_users_config if u]

            # GES namespaces
            ges_config = pre_validation_config.get("GES", "")
            if isinstance(ges_config, str):
                required_ges_namespaces = [
                    ns.strip()
                    for ns in ges_config.split(",")
                    if ns.strip()
                ]
            elif isinstance(ges_config, list):
                required_ges_namespaces = [ns for ns in ges_config if ns]

            # Time constraints
            start_time_str = pre_validation_config.get("START_TIME")
            end_time_str = pre_validation_config.get("END_TIME")
            timezone_str = pre_validation_config.get("TIMEZONE", "CST")

        else:
            logger.warning(
                f"Invalid pre_validation_check format: {type(pre_validation_config)}"
            )
            return {
                "valid": False,
                "message": "Invalid pre-validation configuration format"
            }

        logger.info(f"Required LDAP groups: {required_ldap_groups}")
        logger.info(f"Required LDAP users: {required_ldap_users}")
        logger.info(f"Required GES namespaces: {required_ges_namespaces}")
        logger.info(f"Time constraints: START_TIME={start_time_str}, END_TIME={end_time_str}, TIMEZONE={timezone_str}")

        # Check time constraints first (if specified)
        time_check_result = _check_time_constraints(start_time_str, end_time_str, timezone_str)
        if not time_check_result["valid"]:
            # Add time check failure details
            time_check_result["time_constraint_failure"] = True
            time_check_result["start_time"] = start_time_str
            time_check_result["end_time"] = end_time_str
            time_check_result["timezone"] = timezone_str
            return time_check_result

        # If no requirements specified, validation passes
        if (
            not required_ldap_groups
            and not required_ldap_users
            and not required_ges_namespaces
        ):
            return {
                "valid": True,
                "message": "No specific validation requirements"
            }

        # -------------------------------------------------------
        # LDAP USER CHECK (ANY)
        # -------------------------------------------------------
        if required_ldap_users:
            user_name = user_data.get("name", "").strip().lower()
            logger.info(
                f"Checking LDAP user match: '{username}' / '{user_name}' "
                f"against {required_ldap_users}"
            )

            if username.lower() in required_ldap_users or user_name in required_ldap_users:
                matched_user = (
                    username.lower()
                    if username.lower() in required_ldap_users
                    else user_name
                )
                return {
                    "valid": True,
                    "message": f"User has access via LDAP user match: {matched_user}",
                    "matched_user": matched_user,
                    "source": "LDAP_USER"
                }

        # -------------------------------------------------------
        # LDAP GROUP CHECK (ANY)
        # -------------------------------------------------------
        if required_ldap_groups:
            normalized_user_groups = [_normalize(g) for g in normalized_groups]
            ldap_matches = [
                g for g in required_ldap_groups
                if g in normalized_user_groups
            ]

            if ldap_matches:
                return {
                    "valid": True,
                    "message": f"User has access via LDAP groups: {', '.join(ldap_matches)}",
                    "matched_groups": ldap_matches,
                    "source": "LDAP"
                }

        # -------------------------------------------------------
        # GES NAMESPACE CHECK (ANY)
        # -------------------------------------------------------
        if required_ges_namespaces:
            try:
                from auth.ges_auth import ges_service

                logger.info("Checking GES namespace membership")

                user_namespace_groups = (
                    ges_service.get_user_roles_in_namespaces(
                        username,
                        required_ges_namespaces
                    )
                )

                logger.info(
                    f"User GES namespace groups: {user_namespace_groups}"
                )

                accessible_namespaces = []
                for namespace, groups in user_namespace_groups.items():
                    if groups:
                        accessible_namespaces.append(namespace)

                if accessible_namespaces:
                    return {
                        "valid": True,
                        "message": (
                            "User has access via GES namespaces: "
                            f"{', '.join(accessible_namespaces)}"
                        ),
                        "matched_namespaces": accessible_namespaces,
                        "source": "GES"
                    }

            except ImportError:
                logger.warning(
                    "GES integration not available - skipping GES validation"
                )
            except Exception as e:
                logger.error(
                    f"Error checking GES namespace membership: {str(e)}"
                )

        # -------------------------------------------------------
        # NO MATCHES
        # -------------------------------------------------------
        error_details = []

        if required_ldap_users:
            error_details.append(f"LDAP users: {required_ldap_users}")
        if required_ldap_groups:
            error_details.append(f"LDAP groups: {required_ldap_groups}")
        if required_ges_namespaces:
            error_details.append(f"GES namespaces: {required_ges_namespaces}")

        return {
            "valid": False,
            "message": "Access denied",
            "details": error_details,
            "user_ad_groups": normalized_groups,
            "user_name": user_data.get("name", "")
        }

    except Exception as e:
        logger.error(f"Error during pre-validation check: {str(e)}")
        return {
            "valid": False,
            "message": f"Error during validation: {str(e)}"
        }


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
        validation_result = user_pre_validation(api_key, normalized_groups, username, user_data)
        if not validation_result["valid"]:
            # Check if it's a time constraint failure
            if validation_result.get("time_constraint_failure"):
                response_data = {
                    "error": validation_result["message"],
                    "time_constraint_failure": True,
                    "current_time": validation_result.get("current_time"),
                    "start_time": validation_result.get("start_time"),
                    "end_time": validation_result.get("end_time"),
                    "timezone": validation_result.get("timezone")
                }
            else:
                response_data = {
                    "error": validation_result["message"],
                    "details": validation_result.get("details"),
                    "user_ad_groups": validation_result.get("user_ad_groups"),
                    "user_name": validation_result.get("user_name")
                }
            return jsonify(response_data), 403

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
