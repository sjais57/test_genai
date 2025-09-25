# claims/ges_claims.py
import logging
import yaml
import os
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces defined in the API key YAML
    
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
        
        # Extract the namespace names from the API key YAML
        namespaces_to_check = list(namespace_configs.keys())
        logger.info(f"Checking namespaces from API key {api_key}: {namespaces_to_check}")
        
        # Get user's groups in all specified namespaces from API key
        user_namespace_groups = ges_service.get_user_groups_in_namespaces(
            username, namespaces_to_check
        )
        
        claims = {}
        matched_groups = []
        
        # Process each namespace defined in the API key YAML
        for namespace, namespace_config in namespace_configs.items():
            user_groups = user_namespace_groups.get(namespace, [])
            group_claims_mapping = namespace_config.get('group_claims', {})
            
            logger.info(f"Checking namespace {namespace} from API key: user has groups {user_groups}")
            
            # Check each group mapping in this namespace from API key YAML
            for group_name, group_claims in group_claims_mapping.items():
                if group_name.lower() in [g.lower() for g in user_groups]:
                    logger.info(f"User {username} is member of group {group_name} in namespace {namespace}, applying claims from API key")
                    
                    # Merge the claims from API key YAML
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{group_name}")
        
        # Apply default claims from API key if defined and no specific groups matched
        if not claims and 'default_claims' in metadata:
            claims.update(metadata.get('default_claims', {}))
            logger.info(f"Applying default claims from API key for user {username}")
        
        # Add GES information for debugging/auditing
        if claims:
            claims['_ges_metadata'] = {
                'api_key': api_key,
                'matched_groups': matched_groups,
                'namespaces_checked': namespaces_to_check,
                'namespaces_with_groups': [ns for ns, groups in user_namespace_groups.items() if groups]
            }
        
        logger.info(f"Final GES claims for user {username} from API key {api_key}: {claims}")
        return claims
        
    except Exception as e:
        logger.error(f"Error processing GES claims from API key: {str(e)}")
        return {}

def check_ges_access(username: str, api_key: str) -> Dict[str, Any]:
    """
    Check if user has required GES group access based on API key YAML configuration
    
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
        
        # Check if GES access validation is required in API key YAML
        ges_validation = api_key_config.get('ges_validation', {})
        if not ges_validation:
            return {
                "valid": True,
                "message": "No GES validation required in API key"
            }
        
        # Get required namespaces from API key YAML
        required_namespaces = ges_validation.get('required_namespaces', [])
        minimum_groups_required = ges_validation.get('minimum_groups_required', 1)
        
        if not required_namespaces:
            return {
                "valid": True,
                "message": "No specific namespaces required in API key"
            }
        
        # Get user's groups in required namespaces from API key YAML
        user_namespace_groups = ges_service.get_user_groups_in_namespaces(
            username, required_namespaces
        )
        
        # Check if user has groups in the required namespaces from API key
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
                "message": f"User has access to namespaces from API key: {accessible_namespaces}",
                "accessible_namespaces": accessible_namespaces
            }
        else:
            return {
                "valid": False,
                "message": f"User does not have required access to namespaces specified in API key: {required_namespaces}",
                "required_namespaces": required_namespaces,
                "user_namespace_groups": user_namespace_groups
            }
            
    except Exception as e:
        logger.error(f"Error during GES access check: {str(e)}")
        return {
            "valid": False,
            "message": f"Error during GES validation: {str(e)}"
        }
