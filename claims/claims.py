# claims/ges_claims.py
import logging
import yaml
import os
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces with detailed debugging
    """
    try:
        from auth.ges_integration import ges_service
        
        logger.info(f" STARTING GES CLAIMS PROCESSING")
        logger.info(f"   User: {username}")
        logger.info(f"   API Key: {api_key}")
        
        # Load API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        logger.info(f"📁 API key file: {api_key_file}")
        
        if not os.path.exists(api_key_file):
            logger.warning(f"API key file not found")
            return {}
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Get namespace configurations from API key metadata
        metadata = api_key_config.get('metadata', {})
        namespace_configs = metadata.get('ges_namespaces', {})
        
        logger.info(f"Namespaces in API key: {list(namespace_configs.keys())}")
        
        if not namespace_configs:
            logger.info("No GES namespace configurations found")
            return {}
        
        # Get namespaces to check
        namespaces_to_check = list(namespace_configs.keys())
        logger.info(f"Checking namespaces: {namespaces_to_check}")
        
        # Get user's groups in namespaces
        user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, namespaces_to_check)
        logger.info(f"User groups from GES: {user_namespace_groups}")
        
        # If user has no groups in any namespace, return empty claims
        if not user_namespace_groups:
            logger.info(f" User has no groups in any namespace")
            return {}
        
        claims = {}
        matched_groups = []
        
        # Process each namespace where user has groups
        for namespace, user_groups in user_namespace_groups.items():
            logger.info(f"Processing namespace: {namespace}")
            logger.info(f"   User groups in this namespace: {user_groups}")
            
            # Get group claims mapping for this namespace
            if namespace not in namespace_configs:
                logger.warning(f" Namespace '{namespace}' not found in API key config")
                continue
                
            namespace_config = namespace_configs[namespace]
            group_claims_mapping = namespace_config.get('group_claims', {})
            
            logger.info(f"   Group claims defined in API key: {list(group_claims_mapping.keys())}")
            
            # Check each group the user belongs to
            for user_group in user_groups:
                logger.info(f"   🔍 Checking user group: '{user_group}'")
                
                # Try exact match first
                if user_group in group_claims_mapping:
                    group_claims = group_claims_mapping[user_group]
                    logger.info(f" EXACT MATCH FOUND for group '{user_group}'")
                    logger.info(f"Claims to apply: {group_claims}")
                    
                    # Merge the claims
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{user_group}")
                    logger.info(f"Claims applied successfully")
                
                else:
                    # Try case-insensitive match
                    user_group_lower = user_group.lower()
                    matching_key = None
                    
                    for config_group in group_claims_mapping.keys():
                        if config_group.lower() == user_group_lower:
                            matching_key = config_group
                            break
                    
                    if matching_key:
                        group_claims = group_claims_mapping[matching_key]
                        logger.info(f"CASE-INSENSITIVE MATCH: '{user_group}' -> '{matching_key}'")
                        logger.info(f"Claims to apply: {group_claims}")
                        
                        claims.update(group_claims)
                        matched_groups.append(f"{namespace}:{user_group}->{matching_key}")
                        logger.info(f"Claims applied successfully")
                    else:
                        logger.info(f"No matching group found in API key for '{user_group}'")
        
        # Final results
        if claims:
            logger.info(f"SUCCESS: Generated GES claims")
            logger.info(f"Matched groups: {matched_groups}")
            logger.info(f"Final claims: {claims}")
            
            # Add debug metadata (optional)
            claims['_ges_debug'] = {
                'matched_groups': matched_groups,
                'timestamp': str(datetime.now())
            }
        else:
            logger.warning(f"No claims generated despite user having groups")
            logger.info(f"User groups: {user_namespace_groups}")
            logger.info(f"API key group definitions: { {ns: list(config.get('group_claims', {}).keys()) for ns, config in namespace_configs.items()} }")
        
        return claims
        
    except Exception as e:
        logger.error(f"Error in GES claims processing: {str(e)}", exc_info=True)
        return {}
