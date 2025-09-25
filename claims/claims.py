# claims/ges_claims.py
import logging
import yaml
import os
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces defined in the API key
    
    Args:
        username: The username
        api_key: The API key containing namespace configurations
        
    Returns:
        Dictionary of claims based on GES group membership
    """
    try:
        from ges_integration import ges_service
        
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
            logger.info(f"No GES namespace configurations found in API key {api_key}")
            return {}
        
        logger.info(f"Processing GES claims for user {username} using API key {api_key}")
        logger.info(f"Namespaces configured in API key: {list(namespace_configs.keys())}")
        
        # Get namespaces to check from the API key configuration
        namespaces_to_check = list(namespace_configs.keys())
        
        # Get user's groups in all specified namespaces
        user_namespace_groups = ges_service.get_user_groups_in_multiple_namespaces(
            username, namespaces_to_check
        )
        
        claims = {}
        matched_groups = []
        
        # Process each namespace defined in the API key
        for namespace, namespace_config in namespace_configs.items():
            user_groups = user_namespace_groups.get(namespace, [])
            group_mappings = namespace_config.get('group_claims', {})
            
            logger.info(f"Checking namespace {namespace}: user has groups {user_groups}")
            
            # Check each group mapping in this namespace
            for group_name, group_claims in group_mappings.items():
                if group_name.lower() in [g.lower() for g in user_groups]:
                    logger.info(f"User {username} is member of group {group_name} in namespace {namespace}, applying claims")
                    
                    # Merge the claims (later definitions override earlier ones)
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{group_name}")
        
        # Apply default claims if defined and no specific groups matched
        if not claims and 'default_claims' in metadata:
            claims.update(metadata.get('default_claims', {}))
            logger.info(f"Applying default claims for user {username}")
        
        # Add GES information for debugging/auditing
        if claims:
            claims['_ges_metadata'] = {
                'api_key': api_key,
                'matched_groups': matched_groups,
                'checked_namespaces': namespaces_to_check,
                'user_has_groups_in': [ns for ns, groups in user_namespace_groups.items() if groups]
            }
        
        logger.info(f"Final GES claims for user {username}: {claims}")
        return claims
        
    except Exception as e:
        logger.error(f"Error processing GES claims from API key: {str(e)}")
        return {}

def check_ges_access(username: str, api_key: str) -> Dict[str, Any]:
    """
    Check if user has required GES group access for the API key
    
    Args:
        username: The username
        api_key: The API key to check access for
        
    Returns:
        Access validation result
    """
    try:
        from ges_integration import ges_service
        
        # Load API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        if not os.path.exists(api_key_file):
            return {
                "valid": False,
                "message": "Invalid API key"
            }
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Check if GES access validation is required
        ges_validation = api_key_config.get('ges_validation', {})
        if not ges_validation:
            return {
                "valid": True,
                "message": "No GES validation required"
            }
        
        required_namespaces = ges_validation.get('required_namespaces', [])
        minimum_groups_required = ges_validation.get('minimum_groups_required', 1)
        
        if not required_namespaces:
            return {
                "valid": True,
                "message": "No specific namespaces required"
            }
        
        # Get user's groups in required namespaces
        user_namespace_groups = ges_service.get_user_groups_in_multiple_namespaces(
            username, required_namespaces
        )
        
        # Check if user has groups in the required namespaces
        has_access = False
        accessible_namespaces = []
        
        for namespace in required_namespaces:
            user_groups = user_namespace_groups.get(namespace, [])
            if len(user_groups) >= minimum_groups_required:
                has_access = True
                accessible_namespaces.append(namespace)
        
        if has_access:
            return {
                "valid": True,
                "message": f"User has access to namespaces: {accessible_namespaces}",
                "accessible_namespaces": accessible_namespaces
            }
        else:
            return {
                "valid": False,
                "message": f"User does not have required access to namespaces: {required_namespaces}",
                "required_namespaces": required_namespaces,
                "user_namespace_groups": user_namespace_groups
            }
            
    except Exception as e:
        logger.error(f"Error during GES access check: {str(e)}")
        return {
            "valid": False,
            "message": f"Error during GES validation: {str(e)}"
        }
