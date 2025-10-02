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
    ges_roles_data = {}
    if api_key:
        validation_result = user_pre_validation(api_key, normalized_groups, username)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "details": validation_result.get("details"),
                "user_ad_groups": validation_result.get("user_ad_groups")
            }), 403

        # Get GES roles - we'll get ALL namespaces since rules are processed in dynamic claims
        try:
            from auth.ges_integration import ges_service
            
            # Get ALL available namespaces for the user from GES
            # The dynamic claims will filter based on the rules in API key
            ges_roles_data = ges_service.get_all_user_namespaces(username)
            logger.info(f"All GES namespaces and roles for user: {ges_roles_data}")
                
        except Exception as e:
            logger.error(f"Error fetching GES roles: {str(e)}")
            ges_roles_data = {}

    # Create a proper user context for dynamic claims
    user_context = {
        "user_id": username,
        "team_id": get_team_id_from_user(username, user_data),
        "groups": normalized_groups,
        "api_key_id": api_key,
        "ges_roles": ges_roles_data  # Add ALL GES roles for dynamic claims to filter
    }

    # Process API key (dynamic claims) - this already loads the API key config
    if api_key:
        logger.info(f"Processing API key with user context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        api_key_claims = get_additional_claims(None, user_context)

    # Merge user data with additional claims
    claims = {**user_data, **api_key_claims}
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
