# claims/ges_roles.py
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def get_ges_roles(user_groups: Dict[str, List[str]], rules: List[Dict]) -> Dict[str, Any]:
    """
    Extract roles from GES namespaces based on configuration rules
    """
    try:
        logger.info("EXTRACTING ROLES FROM GES NAMESPACES")
        logger.info(f"User groups from GES: {user_groups}")
        logger.info(f"Configuration rules: {rules}")
        
        claims = {}
        
        for rule in rules:
            match_type = rule.get('match_type')
            group_prefix = rule.get('group_prefix')
            group_name = rule.get('group_name')
            value_template = rule.get('value', {})
            
            logger.info(f"Processing rule: match_type={match_type}, namespace={group_prefix or group_name}")
            
            # Find matching namespaces
            matching_namespaces = []
            
            if match_type == "startswith" and group_prefix:
                # Match namespaces starting with prefix
                for namespace in user_groups.keys():
                    if namespace.startswith(group_prefix):
                        matching_namespaces.append(namespace)
                logger.info(f"Prefix '{group_prefix}' matched {len(matching_namespaces)} namespaces")
                
            elif match_type == "exact" and group_name:
                # Exact namespace match
                if group_name in user_groups:
                    matching_namespaces.append(group_name)
                logger.info(f"Exact namespace '{group_name}' found: {group_name in user_groups}")
            
            # Extract all groups (roles) from matching namespaces
            all_roles = []
            for namespace in matching_namespaces:
                roles = user_groups.get(namespace, [])
                all_roles.extend(roles)
                logger.info(f"Namespace '{namespace}' has roles: {roles}")
            
            # Create claim if we found roles
            if all_roles:
                # Determine claim key
                if match_type == "startswith" and group_prefix:
                    claim_key = group_prefix.replace('.', '_').rstrip('_')
                elif match_type == "exact" and group_name:
                    claim_key = group_name.replace('.', '_')
                else:
                    claim_key = 'ges_roles'
                
                # Build claim value with roles
                claim_value = {}
                if 'roles' in value_template:
                    claim_value['roles'] = all_roles
                
                claims[claim_key] = claim_value
                logger.info(f"Added claim '{claim_key}' with {len(all_roles)} roles")
        
        logger.info(f"Final claims: {claims}")
        return claims
        
    except Exception as e:
        logger.error(f"Error in GES roles extraction: {str(e)}", exc_info=True)
        return {}
