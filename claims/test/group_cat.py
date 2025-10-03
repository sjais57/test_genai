# claims/group_category.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Dynamic claims function to fetch and process GES namespace roles
    """
    logger.info("ENTERING get_ges_namespace_roles function")
    logger.info(f"Parameters - user_id: {user_id}, rules: {rules}")
    
    # If metadata is passed in kwargs, log it (for debugging)
    if 'metadata' in kwargs:
        logger.info(f"Metadata received: {kwargs['metadata']}")
    
    result = {}
    
    if not user_id:
        logger.error("No user_id provided for GES roles lookup")
        return {}
    
    logger.info(f"Starting GES roles lookup for user: {user_id}")
    logger.info(f"Rules configuration: {rules}")
    
    # Import here to avoid circular imports
    try:
        from auth.ges_integration import ges_service
        logger.info("Successfully imported GES service")
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
    tr



# claims/group_category.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Dynamic claims function to fetch and process GES namespace roles
    """
    logger.info("ENTERING get_ges_namespace_roles function")
    logger.info(f"Parameters - user_id: {user_id}, rules: {rules}")
    
    # If metadata is passed in kwargs, log it (for debugging)
    if 'metadata' in kwargs:
        logger.info(f"Metadata received: {kwargs['metadata']}")
    
    if not user_id:
        logger.error("No user_id provided for GES roles lookup")
        return {}
    
    logger.info(f"Starting GES roles lookup for user: {user_id}")
    logger.info(f"Rules configuration: {rules}")
    
    # Import here to avoid circular imports
    try:
        from auth.ges_integration import ges_service
        logger.info("Successfully imported GES service")
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    # Extract required namespaces from rules - support comma-separated namespaces
    required_namespaces = []
    for rule in rules:
        namespace_value = rule.get('ges_namespace', '')
        if namespace_value:
            # Split by comma and strip whitespace
            namespaces = [ns.strip() for ns in namespace_value.split(',') if ns.strip()]
            for namespace in namespaces:
                if namespace and namespace not in required_namespaces:
                    required_namespaces.append(namespace)
    
    if not required_namespaces:
        logger.info("No GES namespaces specified in API key rules")
        return {}
    
    logger.info(f"Required namespaces for GES lookup: {required_namespaces}")
    
    # Fetch GES roles for all required namespaces
    try:
        logger.info(f"Calling ges_service.get_user_groups_in_namespaces with: user={user_id}, namespaces={required_namespaces}")
        ges_roles_data = ges_service.get_user_groups_in_namespaces(user_id, required_namespaces)
        logger.info(f"Fetched GES roles data: {ges_roles_data}")
        
        # Collect all roles from all namespaces into a single list
        all_roles = []
        
        for rule in rules:
            namespace_value = rule.get('ges_namespace', '')
            if not namespace_value:
                continue
                
            # Split comma-separated namespaces
            namespaces = [ns.strip() for ns in namespace_value.split(',') if ns.strip()]
            
            for ges_namespace in namespaces:
                # Check if we have data for this namespace
                if ges_namespace not in ges_roles_data:
                    logger.warning(f"No GES roles found for namespace: {ges_namespace}")
                    continue
                    
                namespace_roles = ges_roles_data[ges_namespace]
                logger.info(f"Processing namespace '{ges_namespace}' with roles: {namespace_roles}")
                
                # Add all roles from this namespace to the combined list
                all_roles.extend(namespace_roles)
                
                logger.info(f"Roles from namespace '{ges_namespace}': {namespace_roles}")
        
        # Remove duplicates while preserving order
        unique_roles = []
        seen_roles = set()
        for role in all_roles:
            if role not in seen_roles:
                seen_roles.add(role)
                unique_roles.append(role)
        
        logger.info(f"All unique roles from all namespaces: {unique_roles}")
        
        # Return only the roles list, not the namespace structure
        final_result = {"roles": unique_roles}
        logger.info(f"Final roles result: {final_result}")
        logger.info("EXITING get_ges_namespace_roles function")
        return final_result
            
    except Exception as e:
        logger.error(f"Error fetching GES roles: {str(e)}", exc_info=True)
        return {}
