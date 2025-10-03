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
    if api_key:
        validation_result = check_pre_validation(api_key, normalized_groups)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "details": validation_result.get("details"),
                "user_ad_groups": validation_result.get("user_ad_groups")
            }), 403

    # Create a proper user context for dynamic claims
    user_context = {
        "user_id": username,  # This will be used by the GES function
        "team_id": get_team_id_from_user(username, user_data),
        "groups": normalized_groups,
        "api_key_id": api_key,
    }

    # Process API key (dynamic claims) - GES roles will be fetched here
    if api_key:
        logger.info(f"Processing API key with user_context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        api_key_claims = get_additional_claims(None, user_context)

    # Merge user data with additional claims
    claims = {**user_data, **api_key_claims}
    claims.pop("groups", None)

    # Log the final claims to verify GES roles are included
    logger.info(f"Final claims for JWT token - username={username}")
    if 'ges_namespace_roles' in claims:
        logger.info(f"GES roles included in token: {claims['ges_namespace_roles']}")
    else:
        logger.info("No GES roles in claims (might be expected if no API key or no GES config)")

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


# In your /token endpoint, add these debug logs:

# After user_context creation
logger.info("=" * 80)
logger.info("🔑 DYNAMIC CLAIMS DEBUG INFO")
logger.info("=" * 80)
logger.info(f"📋 User context for dynamic claims: {user_context}")

# Process API key claims
if api_key:
    logger.info(f"🔑 Processing API key: {api_key}")
    logger.info(f"👤 User ID in context: {user_context.get('user_id')}")
    
    api_key_claims = get_additional_claims(api_key, user_context)
    logger.info(f"📦 API key claims result: {api_key_claims}")
    
    # Debug: Check what's in the API key claims
    if api_key_claims:
        logger.info(f"🔍 API key claims keys: {list(api_key_claims.keys())}")
        for key, value in api_key_claims.items():
            logger.info(f"   - {key}: {type(value)} = {value}")
    else:
        logger.warning("🔍 No API key claims were returned")

# Merge claims
claims = {**user_data, **api_key_claims}
claims.pop("groups", None)

# Final check for GES roles
logger.info("-" * 80)
if 'ges_namespace_roles' in claims:
    logger.info(f"SUCCESS: GES roles added to token!")
    logger.info(f"GES roles data: {claims['ges_namespace_roles']}")
else:
    logger.error("FAILED: GES roles NOT found in final claims")
    logger.info(f"All claims keys: {list(claims.keys())}")
    
    # Check if it's in api_key_claims but got overwritten
    if 'ges_namespace_roles' in api_key_claims:
        logger.error("GES roles WERE in api_key_claims but got overwritten by user_data!")
    else:
        logger.error("GES roles were never added to api_key_claims")
logger.info("=" * 80)
