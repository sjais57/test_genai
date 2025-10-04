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
        from auth.ges_integration import ges_service, _safe_parse_groups
        logger.info("Successfully imported GES service and parser")
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    try:
        # Get both roles and groups in a single call
        logger.info(f"Calling ges_service.get_user_entitlements for user: {user_id}")
        entitlements_data = ges_service.get_user_entitlements(user_id)
        logger.info(f"Fetched GES entitlements data: {entitlements_data}")
        
        # Parse the raw data using GES-specific parsing
        raw_roles = entitlements_data.get("roles")
        raw_groups = entitlements_data.get("groups")
        
        # Parse roles data
        if raw_roles is not None:
            roles_list = _safe_parse_groups(raw_roles)
            logger.info(f"Processed roles: {roles_list}")
        else:
            roles_list = []
            logger.info("No roles data found")
        
        # Parse groups data
        if raw_groups is not None:
            groups_list = _safe_parse_groups(raw_groups)
            logger.info(f"Processed groups: {groups_list}")
        else:
            groups_list = []
            logger.info("No groups data found")
        
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
