# claims/ges_claims.py - SIMPLIFIED
import logging
import yaml
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    SIMPLIFIED version - just make it work
    """
    try:
        from auth.ges_integration import ges_service
        
        print(f"=== GES CLAIMS DEBUG ===")
        print(f"User: {username}, API Key: {api_key}")
        
        # Load API key
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        
        if not os.path.exists(api_key_file):
            print("❌ API key file not found")
            return {}
        
        with open(api_key_file, 'r') as f:
            api_key_config = yaml.safe_load(f)
        
        # Get namespaces
        namespace_configs = api_key_config.get('metadata', {}).get('ges_namespaces', {})
        namespaces = list(namespace_configs.keys())
        
        print(f"Namespaces to check: {namespaces}")
        
        # Get user groups
        user_groups_by_namespace = ges_service.get_user_groups_in_namespaces(username, namespaces)
        print(f"User groups from GES: {user_groups_by_namespace}")
        
        claims = {}
        
        # SIMPLE LOGIC: For each namespace and each user group, apply claims
        for namespace, user_groups in user_groups_by_namespace.items():
            print(f"Processing namespace: {namespace}")
            print(f"User groups: {user_groups}")
            
            group_claims = namespace_configs[namespace].get('group_claims', {})
            print(f"Available group claims: {list(group_claims.keys())}")
            
            for user_group in user_groups:
                print(f"Checking group: '{user_group}'")
                
                if user_group in group_claims:
                    print(f"✅ MATCH FOUND! Applying claims for group: {user_group}")
                    print(f"Claims: {group_claims[user_group]}")
                    
                    # THIS IS THE KEY LINE - merge the claims
                    claims.update(group_claims[user_group])
                    print(f"Claims after update: {claims}")
                else:
                    print(f"❌ No claims defined for group: {user_group}")
        
        print(f"=== FINAL CLAIMS: {claims} ===")
        return claims
        
    except Exception as e:
        print(f"💥 ERROR: {e}")
        return {}
