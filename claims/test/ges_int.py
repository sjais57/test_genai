# auth/ges_integration.py
import logging
import ast
import json
from typing import List, Dict
from ges_entitylements.security import EntitlementsService

logger = logging.getLogger(__name__)

class GESService:
    def __init__(self):
        pass
        
    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace
        Handles string representation of lists returned by GES
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
            if isinstance(groups, list):
                # Already a list - perfect!
                group_list = [str(group) for group in groups]
                
            elif isinstance(groups, str):
                # String representation of list - need to parse it
                groups_cleaned = groups.strip()
                
                # Try different parsing methods
                if groups_cleaned.startswith('[') and groups_cleaned.endswith(']'):
                    try:
                        # Method 1: Use ast.literal_eval for safe parsing
                        group_list = ast.literal_eval(groups_cleaned)
                        group_list = [str(group) for group in group_list]
                        logger.info("✅ Successfully parsed using ast.literal_eval")
                        
                    except:
                        try:
                            # Method 2: Use json.loads
                            group_list = json.loads(groups_cleaned)
                            group_list = [str(group) for group in group_list]
                            logger.info("✅ Successfully parsed using json.loads")
                            
                        except:
                            # Method 3: Manual parsing
                            groups_cleaned = groups_cleaned[1:-1]  # Remove brackets
                            group_list = [group.strip().strip("'\"") for group in groups_cleaned.split(',')]
                            logger.info("✅ Successfully parsed using manual parsing")
                
                else:
                    # Single group as string
                    group_list = [groups_cleaned]
                    
            elif groups:
                # Other type (probably single value)
                group_list = [str(groups)]
                
            else:
                # Empty response
                group_list = []
            
            logger.info(f"✅ Processed groups: {group_list}")
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
            # Only include namespace if user has groups in it
            if groups:
                results[namespace] = groups
        
        return results

# Global GES service instance
ges_service = GESService()
