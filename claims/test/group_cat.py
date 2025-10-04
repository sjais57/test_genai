# claims/group_category.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Dynamic claims function to fetch and process GES roles and groups
    """
    logger.info("ENTERING get_ges_namespace_roles function")
    logger.info(f"Parameters - user_id: {user_id}, rules: {rules}")
    
    if not user_id:
        logger.error("No user_id provided for GES lookup")
        return {}
    
    logger.info(f"Starting GES lookup for user: {user_id}")
    
    # Import here to avoid circular imports
    try:
        from auth.ges_integration import ges_service
        logger.info("Successfully imported GES service")
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    try:
        # Extract namespaces from rules if provided
        namespaces = []
        for rule in rules:
            namespace_value = rule.get('ges_namespace', '')
            if namespace_value:
                # Split comma-separated namespaces
                namespaces.extend([ns.strip() for ns in namespace_value.split(',') if ns.strip()])
        
        # If no namespaces in rules, use None to let GES service handle defaults
        if not namespaces:
            namespaces = None
            logger.info("No namespaces specified in rules, using defaults")
        else:
            logger.info(f"Using namespaces from rules: {namespaces}")
        
        # Get both roles and groups in a single call
        logger.info(f"Calling ges_service.get_user_entitlements for user: {user_id}")
        entitlements_data = ges_service.get_user_entitlements(user_id, namespaces)
        logger.info(f"Fetched GES entitlements data: {entitlements_data}")
        
        # Directly use the parsed data from GES service
        roles_list = entitlements_data.get("roles", [])
        groups_list = entitlements_data.get("groups", [])
        
        final_result = {
            "ges_namespace_roles": {"roles": roles_list},
            "ges_namespace_groups": {"groups": groups_list}
        }
        
        logger.info(f"Final result: {final_result}")
        logger.info("EXITING get_ges_namespace_roles function")
        return final_result
            
    except Exception as e:
        logger.error(f"Error fetching GES entitlements: {str(e)}", exc_info=True)
        # Return empty structure instead of complete failure
        return {
            "ges_namespace_roles": {"roles": []},
            "ges_namespace_groups": {"groups": []}
        }
