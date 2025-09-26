@app.route("/token", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get("username", None)
    password = request.json.get("password", None)
    api_key = request.json.get("api_key", None)
    custom_secret = request.json.get("secret", None)

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Authenticate user
    if AUTH_METHOD == "ldap":
        authenticated, user_data = authenticate_ldap(username, password)
    else:
        authenticated, user_data = authenticate_file(username, password)

    if not authenticated:
        error_message = "Invalid username or password"
        if "error" in user_data:
            error_message = user_data["error"]
        return jsonify({"error": error_message}), 401

    # Initialize GES claims (will be empty if user has no namespace groups)
    ges_claims = {}

    # Process API key if provided
    if api_key:
        # Your existing pre-validation
        validation_result = user_pre_validation(api_key, normalized_groups)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "required_group": validation_result.get("required_group")
            }), 403

        # Get GES claims (will be empty if user has no namespace groups)
        try:
            from claims.ges_claims import get_ges_claims_from_api_key
            ges_claims = get_ges_claims_from_api_key(username, api_key)
        except Exception as e:
            logger.error(f"Error fetching GES claims: {str(e)}")
            ges_claims = {}  # Ensure it's empty on error

    # Prepare user data
    raw_groups = user_data.get("groups", [])
    normalized_groups = extract_group_cn(raw_groups)

    # Create user context
    user_context = {
        "user_id": username,
        "team_id": get_team_id_from_user(username, user_data),
        "groups": normalized_groups,
        "api_key_id": api_key,
    }

    # Get additional claims
    if api_key:
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        api_key_claims = get_additional_claims(None, user_context)

    # Merge all claims - GES claims will only be included if user has namespace groups
    claims = {**user_data, **ges_claims, **api_key_claims}

    # Remove raw groups to prevent leakage
    claims.pop("groups", None)

    # Handle expiration
    expires_delta = app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    if "exp_hours" in claims:
        expires_delta = timedelta(hours=claims["exp_hours"])
        claims.pop("exp_hours", None)

    # Token generation (your existing code)
    if custom_secret:
        import jwt
        import datetime as dt
        import uuid

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
            **claims,
        }

        refresh_payload = {
            "iat": now,
            "nbf": now,
            "jti": str(uuid.uuid4()),
            "exp": refresh_token_exp,
            "sub": username,
            "type": "refresh",
            **claims,
        }

        algorithm = app.config.get("JWT_ALGORITHM", "HS256")
        access_token = jwt.encode(access_payload, custom_secret, algorithm=algorithm)
        refresh_token = jwt.encode(refresh_payload, custom_secret, algorithm=algorithm)

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "note": "Tokens generated with custom secret"
        }), 200

    else:
        access_token = create_access_token(
            identity=username,
            additional_claims=claims,
            expires_delta=expires_delta,
            fresh=True,
        )

        refresh_token = create_refresh_token(
            identity=username,
            additional_claims=claims
        )

        return jsonify(
            access_token=access_token,
            refresh_token=refresh_token
        ), 200
