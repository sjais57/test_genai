# claims/group_category.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Simple function to get both roles and groups for JWT token
    """
    logger.info(f"STARTING GES DATA FETCH for user: {user_id}")
    logger.info(f"Rules received: {rules}")
    
    if not user_id:
        logger.error("No user_id provided")
        return {}
    
    # Import GES service
    try:
        from auth.ges_integration import ges_service
        logger.info("Successfully imported GES service")
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    try:
        # Get namespaces from rules
        namespaces = []
        for rule in rules:
            namespace_value = rule.get('ges_namespace', '')
            logger.info(f"Processing rule with namespace_value: '{namespace_value}'")
            if namespace_value:
                parsed_namespaces = [ns.strip() for ns in namespace_value.split(',') if ns.strip()]
                namespaces.extend(parsed_namespaces)
                logger.info(f"Added namespaces: {parsed_namespaces}")
        
        logger.info(f"Final namespaces to query: {namespaces}")
        
        if not namespaces:
            logger.warning("No GES namespaces specified in rules")
            return {
                "ges_namespace_roles": {"roles": []},
                "ges_namespace_groups": {"groups": []}
            }
        
        # Get ROLES from namespaces
        logger.info(f"Calling ges_service.get_user_groups_in_namespaces for roles...")
        ges_roles_data = ges_service.get_user_groups_in_namespaces(user_id, namespaces)
        logger.info(f"Raw roles data from GES: {ges_roles_data}")
        
        roles_list = []
        for namespace, namespace_roles in ges_roles_data.items():
            logger.info(f"Processing namespace '{namespace}' with roles: {namespace_roles}")
            roles_list.extend(namespace_roles)
        
        # Remove duplicate roles
        roles_list = list(dict.fromkeys(roles_list))
        logger.info(f"Final roles list: {roles_list}")
        
        # Get GROUPS from the same namespaces
        logger.info(f"Calling ges_service.get_user_groups for each namespace...")
        groups_list = []
        for namespace in namespaces:
            logger.info(f"Getting groups for namespace: {namespace}")
            namespace_groups = ges_service.get_user_groups(user_id, namespace)
            logger.info(f"Groups from namespace '{namespace}': {namespace_groups}")
            groups_list.extend(namespace_groups)
        
        # Remove duplicate groups
        groups_list = list(dict.fromkeys(groups_list))
        logger.info(f"Final groups list: {groups_list}")
        
        # Return both in JWT token
        result = {
            "ges_namespace_roles": {"roles": roles_list},
            "ges_namespace_groups": {"groups": groups_list}
        }
        
        logger.info(f"FINAL GES RESULT: {result}")
        return result
            
    except Exception as e:
        logger.error(f"ERROR getting GES data: {str(e)}", exc_info=True)
        return {
            "ges_namespace_roles": {"roles": []},
            "ges_namespace_groups": {"groups": []}
        }
