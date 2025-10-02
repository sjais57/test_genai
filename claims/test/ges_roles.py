# claims/ges_roles.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_roles(user_id: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Dynamic claims function to fetch and process GES namespace roles
    
    Args:
        user_id: The username to look up
        rules: List of rules from API key configuration
        
    Returns:
        Dictionary with namespace roles to be included in JWT claims
    """
    result = {}
    
    if not user_id:
        logger.error("No user_id provided for GES roles lookup")
        return {}
    
    logger.info(f"Starting GES roles lookup for user: {user_id}")
    logger.info(f"Rules configuration: {rules}")
    
    # Import here to avoid circular imports
    try:
        from auth.ges_auth import ges_service
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    # Extract required namespaces from rules
    required_namespaces = []
    for rule in rules:
        namespace = rule.get('ges_namespace')
        if namespace and namespace not in required_namespaces:
            required_namespaces.append(namespace)
    
    if not required_namespaces:
        logger.info("No GES namespaces specified in API key rules")
        return {}
    
    logger.info(f"Required namespaces for GES lookup: {required_namespaces}")
    
    # Fetch GES roles for all required namespaces
    try:
        ges_roles_data = ges_service.get_user_groups_in_namespaces(user_id, required_namespaces)
        logger.info(f"Fetched GES roles data: {ges_roles_data}")
        
        # Process each rule and apply matching logic
        for rule in rules:
            match_type = rule.get('match_type', 'exact')
            ges_namespace = rule.get('ges_namespace')
            value = rule.get('value', {})
            
            if not ges_namespace:
                continue
                
            # Check if we have data for this namespace
            if ges_namespace not in ges_roles_data:
                logger.warning(f"No GES roles found for namespace: {ges_namespace}")
                continue
                
            namespace_roles = ges_roles_data[ges_namespace]
            logger.info(f"Processing namespace '{ges_namespace}' with roles: {namespace_roles}")
            
            # Apply matching logic
            if match_type == "exact":
                # For exact match, include all roles from that namespace
                result[ges_namespace] = {
                    "roles": namespace_roles
                }
            elif match_type == "filtered":
                # Filter specific roles if specified
                filter_roles = value.get("roles", [])
                if filter_roles:
                    filtered = [role for role in namespace_roles if role in filter_roles]
                    result[ges_namespace] = {
                        "roles": filtered
                    }
                    logger.info(f"Filtered roles for '{ges_namespace}': {filtered}")
                else:
                    # If no filter specified, include all roles
                    result[ges_namespace] = {
                        "roles": namespace_roles
                    }
            else:
                # Default: include all roles
                result[ges_namespace] = {
                    "roles": namespace_roles
                }
                
            logger.info(f"Final roles for namespace '{ges_namespace}': {result[ges_namespace]['roles']}")
            
    except Exception as e:
        logger.error(f"Error fetching GES roles: {str(e)}", exc_info=True)
        return {}
    
    final_result = {"ges_namespace_roles": result}
    logger.info(f"Final GES roles result: {final_result}")
    return final_result
