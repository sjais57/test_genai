# claims/ges_claims.py - Add detailed debugging
import logging
import yaml
import os
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces defined in the API key YAML
    """
    try:
        from auth.ges_integration import ges_service
        
        # Load API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        logger.info(f"Looking for API key file: {api_key_file}")
        
        if not os.path.exists(api_key_file):
            logger.warning(f"API key file not found: {api_key_file}")
            return {}
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Get namespace configurations from API key metadata
        metadata = api_key_config.get('metadata', {})
        namespace_configs = metadata.get('ges_namespaces', {})
        
        logger.info(f"Found namespace configs in API key: {list(namespace_configs.keys())}")
        
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
        
        logger.info(f"User {username} groups in namespaces: {user_namespace_groups}")
        
        claims = {}
        matched_groups = []
        
        # Process each namespace defined in the API key YAML
        for namespace, namespace_config in namespace_configs.items():
            user_groups = user_namespace_groups.get(namespace, [])
            group_claims_mapping = namespace_config.get('group_claims', {})
            
            logger.info(f"Checking namespace '{namespace}': user has groups {user_groups}")
            logger.info(f"Group claims mapping for this namespace: {list(group_claims_mapping.keys())}")
            
            # Check each group mapping in this namespace from API key YAML
            for group_name, group_claims in group_claims_mapping.items():
                # Normalize both sides for comparison
                normalized_config_group = group_name.lower().strip()
                user_groups_normalized = [g.lower().strip() for g in user_groups]
                
                logger.info(f"Checking group '{group_name}' (normalized: '{normalized_config_group}') against user groups: {user_groups_normalized}")
                
                if normalized_config_group in user_groups_normalized:
                    logger.info(f"✅ MATCH: User {username} is member of group {group_name} in namespace {namespace}")
                    logger.info(f"Applying claims: {group_claims}")
                    
                    # Merge the claims from API key YAML
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{group_name}")
                else:
                    logger.info(f"❌ NO MATCH: Group '{group_name}' not found in user's groups")
        
        # Apply default claims from API key if defined and no specific groups matched
        if not claims and 'default_claims' in metadata:
            logger.info("No group matches found, applying default claims")
            claims.update(metadata.get('default_claims', {}))
        
        # Add GES information for debugging/auditing
        if claims:
            claims['_ges_metadata'] = {
                'api_key': api_key,
                'matched_groups': matched_groups,
                'namespaces_checked': namespaces_to_check,
                'namespaces_with_groups': [ns for ns, groups in user_namespace_groups.items() if groups],
                'all_user_groups': user_namespace_groups
            }
            logger.info(f"✅ Final GES claims for user {username}: {claims}")
        else:
            logger.warning(f"❌ No GES claims generated for user {username}")
        
        return claims
        
    except Exception as e:
        logger.error(f"Error processing GES claims from API key: {str(e)}", exc_info=True)
        return {}
