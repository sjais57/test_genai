# claims/ges_claims.py
import logging
import yaml
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces
    """
    try:
        from auth.ges_integration import ges_service
        
        logger.info(f"🚀 STARTING GES CLAIMS PROCESSING")
        logger.info(f"   User: {username}")
        logger.info(f"   API Key: {api_key}")
        
        # Load API key configuration
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        if not os.path.exists(api_key_file):
            logger.warning(f"❌ API key file not found")
            return {}
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Get namespace configurations
        namespace_configs = api_key_config.get('metadata', {}).get('ges_namespaces', {})
        
        if not namespace_configs:
            logger.info("❌ No GES namespace configurations found")
            return {}
        
        # Get namespaces to check
        namespaces_to_check = list(namespace_configs.keys())
        logger.info(f"🔍 Checking namespaces: {namespaces_to_check}")
        
        # Get user's groups in namespaces
        user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, namespaces_to_check)
        logger.info(f"👥 User groups from GES: {user_namespace_groups}")
        
        # If user has no groups in any namespace, return empty claims
        if not user_namespace_groups:
            logger.info(f"❌ User has no groups in any namespace")
            return {}
        
        claims = {}
        matched_groups = []
        
        # Process each namespace where user has groups
        for namespace, user_groups in user_namespace_groups.items():
            logger.info(f"🎯 Processing namespace: {namespace}")
            logger.info(f"   User groups: {user_groups}")
            logger.info(f"   Type of user_groups: {type(user_groups)}")
            
            # Get group claims mapping for this namespace
            if namespace not in namespace_configs:
                logger.warning(f"   ⚠️ Namespace '{namespace}' not found in API key config")
                continue
                
            group_claims_mapping = namespace_configs[namespace].get('group_claims', {})
            api_key_groups = list(group_claims_mapping.keys())
            logger.info(f"   API key groups: {api_key_groups}")
            
            # Check each group the user belongs to
            for user_group in user_groups:
                logger.info(f"   🔍 Checking user group: '{user_group}' (type: {type(user_group)})")
                
                # Clean the group name (remove extra quotes/spaces)
                user_group_clean = str(user_group).strip().strip("'\"")
                logger.info(f"   🔧 Cleaned group name: '{user_group_clean}'")
                
                # Try exact match
                if user_group_clean in group_claims_mapping:
                    group_claims = group_claims_mapping[user_group_clean]
                    logger.info(f"   ✅ EXACT MATCH FOUND for group '{user_group_clean}'")
                    logger.info(f"   📦 Claims to apply: {group_claims}")
                    
                    # Merge the claims
                    claims.update(group_claims)
                    matched_groups.append(f"{namespace}:{user_group_clean}")
                    logger.info(f"   ✅ Claims applied successfully")
                
                else:
                    logger.info(f"   ❌ No exact match for '{user_group_clean}'")
                    
                    # Try case-insensitive match
                    user_group_lower = user_group_clean.lower()
                    for api_group in api_key_groups:
                        if api_group.lower() == user_group_lower:
                            group_claims = group_claims_mapping[api_group]
                            logger.info(f"   ✅ CASE-INSENSITIVE MATCH: '{user_group_clean}' -> '{api_group}'")
                            logger.info(f"   📦 Claims to apply: {group_claims}")
                            
                            claims.update(group_claims)
                            matched_groups.append(f"{namespace}:{user_group_clean}->{api_group}")
                            logger.info(f"   ✅ Claims applied successfully")
                            break
                    else:
                        logger.info(f"   ❌ No case-insensitive match either")
        
        # Final results
        if claims:
            logger.info(f"🎉 SUCCESS: Generated GES claims")
            logger.info(f"📋 Matched groups: {matched_groups}")
            logger.info(f"🔧 Final claims keys: {list(claims.keys())}")
        else:
            logger.warning(f"💔 No claims generated")
            logger.info(f"User had groups: {user_namespace_groups}")
            logger.info(f"But no matches with API key groups: {api_key_groups}")
        
        return claims
        
    except Exception as e:
        logger.error(f"💥 Error in GES claims processing: {str(e)}", exc_info=True)
        return {}
