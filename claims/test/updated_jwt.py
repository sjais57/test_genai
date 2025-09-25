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
    normalized_groups = extract_group_cn(raw_groups)

    # Initialize GES claims
    ges_claims = {}

    # If an API key was provided, check pre-validation and get additional claims
    if api_key:
        # Check pre-validation before processing API key (skip GES validation here)
        validation_result = check_pre_validation(api_key, normalized_groups)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "required_group": validation_result.get("required_group")
            }), 403
        
        # Get GES claims from API key namespaces
        try:
            from claims.ges_claims import get_ges_claims_from_api_key
            ges_claims = get_ges_claims_from_api_key(username, api_key)
            logger.info(f"GES claims for user {username}: {ges_claims}")
        except Exception as e:
            logger.error(f"Error fetching GES claims: {str(e)}")
            # Continue without GES claims if there's an error
        
        # Create a proper user context for dynamic claims including GES data
        user_context = {
            "user_id": username,
            "team_id": get_team_id_from_user(username, user_data),
            "groups": normalized_groups,  # Use normalized groups for dynamic claims
            "api_key_id": api_key,
            # Include GES claims in context for potential use in dynamic claims
            **ges_claims
        }
        logger.info(f"Processing API key with user_context: {user_context}")
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        user_context = {
            "user_id": username,
            "team_id": get_team_id_from_user(username, user_data),
            "groups": normalized_groups,
        }
        api_key_claims = get_additional_claims(None, user_context)

    # Log which API key is being used
    if api_key:
        logger.info(f"Using provided API key: {api_key}")
    else:
        logger.info("No API key provided, using base API key")

    # Merge all claims: user data + GES claims + API key claims
    claims = {**user_data, **ges_claims, **api_key_claims}
    
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
