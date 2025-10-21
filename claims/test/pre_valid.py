@app.route('/token', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    api_key = request.json.get('api_key', None)
    api_key_config = request.json.get('api_key_config', None)
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

    # Prepare group info
    raw_groups = user_data.get("groups", [])
    normalized_groups = extract_group_cn(raw_groups)

    # API-key pre-validation (if provided via api_key OR api_key_config)
    ges_claims = {}
    
    # Check if we have either api_key or api_key_config for pre-validation
    validation_api_key = None
    validation_config = None
    
    if api_key:
        validation_api_key = api_key
    elif api_key_config:
        # For inline config, we need to extract the pre_validation_check from the config
        validation_config = api_key_config.get('pre_validation_check')
        # Create a mock API key for validation purposes
        validation_api_key = "inline_config"
    
    if validation_api_key:
        validation_result = user_pre_validation(validation_api_key, normalized_groups, username, user_data, validation_config)
        if not validation_result["valid"]:
            return jsonify({
                "error": validation_result["message"],
                "details": validation_result.get("details"),
                "user_ad_groups": validation_result.get("user_ad_groups"),
                "user_name": validation_result.get("user_name")
            }), 403

        try:
            from claims.ges_claims import get_ges_claims_from_api_key
            ges_claims = get_ges_claims_from_api_key(username, validation_api_key)
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
        # Create a proper user context for dynamic claims
        user_context = {
            "user_id": username,
            "team_id": get_team_id_from_user(username, user_data),
            "groups": user_data.get("groups", []),  # Ensure groups is included for dynamic claims
            # Additional context that might be needed by dynamic claims
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

    # Merge user data with additional claims
    claims = {**user_data, **ges_claims, **api_key_claims}
    
    # Get expiration time from API key configuration if available
    expires_delta = app.config["JWT_ACCESS_TOKEN_EXPIRES"]  # Default
    if 'exp_hours' in claims:
        expires_delta = timedelta(hours=claims['exp_hours'])
        logger.info(f"Using custom expiration time from API key: {claims['exp_hours']} hours")
        # Remove exp_hours from claims to avoid conflicts
        claims.pop('exp_hours')
    
    # Rest of your token generation code remains the same...
    # [Keep the rest of your existing token generation code]
