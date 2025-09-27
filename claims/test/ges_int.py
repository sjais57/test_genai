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
        Properly handles set responses from GES
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
            
            logger.info(f"Raw GES response type: {type(groups)}")
            logger.info(f"Raw GES response: {groups}")
            
            # Handle different response formats
            if isinstance(groups, (set, list)):
                # Already a set or list - convert to list of strings
                group_list = [str(group) for group in groups]
                logger.info(f"Converted to list: {group_list}")
                
            elif isinstance(groups, str):
                # String representation - try to parse it
                groups_cleaned = groups.strip()
                if (groups_cleaned.startswith('{') and groups_cleaned.endswith('}')) or \
                   (groups_cleaned.startswith('[') and groups_cleaned.endswith(']')):
                    # Remove braces/brackets and split
                    inner_content = groups_cleaned[1:-1]
                    group_list = [group.strip().strip("'\"") for group in inner_content.split(',')]
                    logger.info(f"Parsed from string: {group_list}")
                else:
                    # Single group as string
                    group_list = [groups_cleaned]
            else:
                # Other type or None
                group_list = []
            
            logger.info(f"Final processed groups: {group_list}")
            return group_list
            
        except Exception as e:
            logger.error(f"Error getting GES groups: {str(e)}")
            return []

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's groups across multiple namespaces
        """
        results = {}
        
        for namespace in namespaces:
            groups = self.get_user_groups_in_namespace(username, namespace)
            if groups:  # Only include if user has groups
                results[namespace] = groups
        
        return results

# Global GES service instance
ges_service = GESService()
