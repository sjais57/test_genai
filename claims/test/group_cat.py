# claims/group_category.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Simple function to get both roles and groups for JWT token
    """
    logger.info(f"Getting GES data for user: {user_id}")
    
    if not user_id:
        logger.error("No user_id provided")
        return {}
    
    # Import GES service
    try:
        from auth.ges_integration import ges_service
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    try:
        # Get namespaces from rules
        namespaces = []
        for rule in rules:
            namespace_value = rule.get('ges_namespace', '')
            if namespace_value:
                namespaces.extend([ns.strip() for ns in namespace_value.split(',') if ns.strip()])
        
        # Get ROLES from namespaces
        roles_list = []
        if namespaces:
            ges_roles_data = ges_service.get_user_groups_in_namespaces(user_id, namespaces)
            for namespace_roles in ges_roles_data.values():
                roles_list.extend(namespace_roles)
            
            # Remove duplicate roles
            roles_list = list(dict.fromkeys(roles_list))
        
        # Get GROUPS (not namespace-specific)
        groups_list = ges_service.get_user_groups(user_id)
        
        # Return both in JWT token
        result = {
            "ges_namespace_roles": {"roles": roles_list},
            "ges_namespace_groups": {"groups": groups_list}
        }
        
        logger.info(f"GES data result: {result}")
        return result
            
    except Exception as e:
        logger.error(f"Error getting GES data: {str(e)}")
        return {
            "ges_namespace_roles": {"roles": []},
            "ges_namespace_groups": {"groups": []}
        }
