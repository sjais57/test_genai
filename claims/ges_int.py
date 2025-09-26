# auth/ges_integration.py
import logging
from typing import List, Dict
from ges_entitylements.security import EntitlementsService

logger = logging.getLogger(__name__)

class GESService:
    def __init__(self):
        pass
        
    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace
        Returns empty list if user has no groups in namespace
        """
        try:
            # Replace with your actual GES connection details
            hostname = "your-ges-server.com"
            port = 8080
            client_id = "your-client-id"
            client_key = "your-client-key"
            
            logger.info(f"Checking GES groups for user '{username}' in namespace '{namespace}'")
            
            # Create GES service instance
            ges_service = EntitlementsService(
                hostname=hostname,
                port=port,
                namespace=namespace,
                client_id=client_id,
                client_key=client_key
            )
            
            # Get user's groups from GES
            groups = ges_service.get_roles(username)
            
            # Convert to list of strings
            if isinstance(groups, list):
                group_list = [str(group) for group in groups]
            elif groups:
                group_list = [str(groups)]
            else:
                group_list = []  # User has no groups in this namespace
            
            logger.info(f"User '{username}' has {len(group_list)} groups in namespace '{namespace}'")
            return group_list
            
        except Exception as e:
            logger.error(f"Error getting GES groups: {str(e)}")
            return []  # Return empty list on error

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's groups across multiple namespaces
        Only includes namespaces where user actually has groups
        """
        results = {}
        
        for namespace in namespaces:
            groups = self.get_user_groups_in_namespace(username, namespace)
            # Only include namespace if user has groups in it
            if groups:  # This is the key - only include if groups exist
                results[namespace] = groups
        
        return results

# Global GES service instance
ges_service = GESService()
