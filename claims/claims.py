# claims/ges_claims.py
import logging
import yaml
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces
    Only returns claims if user is member of namespace groups
    Returns empty dict if user has no groups in any namespace
    """
    try:
        from auth.ges_integration import ges_service
        
        # Load API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        if not os.path.exists(api_key_file):
            logger.warning(f"API key file not found: {api_key_file}")
            return {}
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Get namespace configurations from API key metadata
        metadata = api_key_config.get('metadata', {})
        namespace_configs = metadata.get('ges_namespaces', {})
        
        if not namespace_configs:
            logger.info("No GES namespace configurations found")
            return {}
        
        # Get namespaces to check
        namespaces_to_check = list(namespace_configs.keys())
        logger.info(f"Checking namespaces: {namespaces_to_check}")
        
        # Get user's groups in namespaces (only returns namespaces where user has groups)
        user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, namespaces_to_check)
        
        # If user has no groups in any namespace, return empty claims
        if not user_namespace_groups:
            logger.info(f"User '{username}' has no groups in any configured namespace")
            return {}
        
        claims = {}
        
        # Process each namespace where user has groups
        for namespace, user_groups in user_namespace_groups.items():
            logger.info(f"User has groups in namespace '{namespace}': {user_groups}")
            
            group_claims_mapping = namespace_configs[namespace].get('group_claims', {})
            
            # Apply claims for each group the user belongs to
            for group_name, group_claims in group_claims_mapping.items():
                if group_name in user_groups:
                    logger.info(f"Applying claims for group '{group_name}'")
                    claims.update(group_claims)
        
        logger.info(f"Generated GES claims for user '{username}': {claims}")
        return claims
        
    except Exception as e:
        logger.error(f"Error processing GES claims: {str(e)}")
        return {}  # Return empty dict on error
