# In your app_jwt_updated.py - Update the login function

@app.route("/token", methods=["POST"])
def login():
    # ... your existing authentication code ...
    
    # After authentication, add this:
    
    # Get GES roles for dynamic claims
    from auth.ges_integration import ges_service
    
    # Load API key to get namespaces
    api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
    api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
    
    with open(api_key_file, 'r') as f:
        api_key_config = yaml.safe_load(f)
    
    # Get namespaces from API key metadata
    namespace_configs = api_key_config.get('metadata', {}).get('ges_namespaces', {})
    namespaces_to_check = list(namespace_configs.keys())
    
    # Get user's roles from GES
    ges_roles_data = {}
    if namespaces_to_check:
        ges_roles_data = ges_service.get_user_groups_in_namespaces(username, namespaces_to_check)
        logger.info(f"GES roles data: {ges_roles_data}")

    # Create user context including GES roles
    user_context = {
        "user_id": username,
        "team_id": get_team_id_from_user(username, user_data),
        "groups": normalized_groups,
        "api_key_id": api_key,
        # Add GES roles for dynamic claims
        "ges_roles": ges_roles_data
    }

    # Get additional claims (this will now include the GES roles dynamic claim)
    if api_key:
        api_key_claims = get_additional_claims(api_key, user_context)
    else:
        api_key_claims = get_additional_claims(None, user_context)

    # Merge all claims
    claims = {**user_data, **api_key_claims}
    
    # Remove raw groups if needed
    claims.pop("groups", None)
    
    # ... rest of your token generation code ...
