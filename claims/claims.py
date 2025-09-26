# claims/ges_claims.py - Enhanced debugging version
import logging
import yaml
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces with detailed debugging
    """
    try:
        from auth.ges_integration import ges_service
        
        logger.info(f"Starting GES claims processing for user '{username}' with API key '{api_key}'")
        
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
        
        logger.info(f"Found namespace configs: {list(namespace_configs.keys())}")
        
        if not namespace_configs:
            logger.info("No GES namespace configurations found")
            return {}
        
        # Get namespaces to check
        namespaces_to_check = list(namespace_configs.keys())
        logger.info(f"Checking namespaces: {namespaces_to_check}")
        
        # Get user's groups in namespaces
        user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, namespaces_to_check)
        logger.info(f"User namespace groups result: {user_namespace_groups}")
        
        # If user has no groups in any namespace, return empty claims
        if not user_namespace_groups:
            logger.info(f"User '{username}' has no groups in any configured namespace")
            return {}
        
        claims = {}
        matched_groups = []
        unmatched_groups = []
        
        # Process each namespace where user has groups
        for namespace, user_groups in user_namespace_groups.items():
            logger.info(f"Processing namespace: {namespace}")
            logger.info(f"User groups: {user_groups}")
            
            group_claims_mapping = namespace_configs[namespace].get('group_claims', {})
            api_key_groups = list(group_claims_mapping.keys())
            logger.info(f"   API key groups: {api_key_groups}")
            
            # Try different matching strategies
            matches_found = False
            
            for group_name, group_claims in group_claims_mapping.items():
                # Strategy 1: Exact match
                if group_name in user_groups:
                    logger.info(f" EXACT MATCH: '{group_name}'")
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{group_name}")
                    matches_found = True
                    continue
                
                # Strategy 2: Case-insensitive match
                user_groups_lower = [g.lower() for g in user_groups]
                if group_name.lower() in user_groups_lower:
                    # Find the actual case version that matched
                    actual_group = next((g for g in user_groups if g.lower() == group_name.lower()), None)
                    logger.info(f" CASE-INSENSITIVE MATCH: '{group_name}' -> '{actual_group}'")
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{actual_group}->{group_name}")
                    matches_found = True
                    continue
                
                # Strategy 3: Partial match
                for user_group in user_groups:
                    if (group_name.lower() in user_group.lower() or 
                        user_group.lower() in group_name.lower()):
                        logger.info(f" PARTIAL MATCH: '{user_group}' contains '{group_name}'")
                        claims.update(group_claims)
                        matched_groups.append(f"{namespace}:{user_group}->{group_name}")
                        matches_found = True
                        break
                
                if not matches_found:
                    unmatched_groups.append(f"{namespace}:{group_name}")
                    logger.info(f" NO MATCH: '{group_name}'")
            
            if not matches_found:
                logger.warning(f"  No group matches found in namespace '{namespace}'")
        
        # Final results
        if claims:
            logger.info(f"SUCCESS: Generated {len(claims)} GES claims")
            logger.info(f"Matched groups: {matched_groups}")
            logger.info(f"Final claims keys: {list(claims.keys())}")
            
            # Add debug info (remove in production if desired)
            claims['_ges_metadata'] = {
                'matched_groups': matched_groups,
                'unmatched_groups': unmatched_groups,
                'user_namespace_groups': user_namespace_groups,
                'timestamp': str(datetime.now())
            }
        else:
            logger.warning(f"FAILED: User has groups but no claims were generated")
            logger.info(f"User groups: {user_namespace_groups}")
            logger.info(f"API key groups: {[list(ns.get('group_claims', {}).keys()) for ns in namespace_configs.values()]}")
        
        return claims
        
    except Exception as e:
        logger.error(f"Error processing GES claims: {str(e)}", exc_info=True)
        return {}
