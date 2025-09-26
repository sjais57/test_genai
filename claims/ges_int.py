# auth/ges_integration.py
import os
import logging
from typing import List, Dict, Any
from ges_entitylements.security import EntitlementsService

logger = logging.getLogger(__name__)

class GESService:
    def __init__(self):
        self.service = None
        
    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Simple function to get user's groups in a specific namespace
        """
        try:
            # Hardcoded connection details - replace with your actual values
            hostname = "your-ges-server.com"  # Replace with your GES hostname
            port = 8080                       # Replace with your GES port
            client_id = "your-client-id"      # Replace with your client ID
            client_key = "your-client-key"    # Replace with your client key
            
            logger.info(f"Checking groups for user '{username}' in namespace '{namespace}'")
            
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
                group_list = []
            
            logger.info(f"User '{username}' has groups in namespace '{namespace}': {group_list}")
            return group_list
            
        except Exception as e:
            logger.error(f"Error getting groups for user '{username}' in namespace '{namespace}': {str(e)}")
            return []

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's groups across multiple namespaces
        """
        results = {}
        
        for namespace in namespaces:
            groups = self.get_user_groups_in_namespace(username, namespace)
            results[namespace] = groups
        
        return results

# Global GES service instance
ges_service = GESService()
