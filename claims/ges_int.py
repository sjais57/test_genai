# ges_integration.py
import os
import logging
from typing import List, Dict, Any, Optional
from ges_entitylements.security import EntitlementsService

logger = logging.getLogger(__name__)

class GESService:
    def __init__(self):
        self.service = None
        self.initialized = False
    
    def initialize(self):
        """Initialize GES service with connection details from .env"""
        try:
            hostname = os.getenv('GES_HOSTNAME')
            port = int(os.getenv('GES_PORT', '8080'))
            client_id = os.getenv('GES_CLIENT_ID')
            client_key = os.getenv('GES_CLIENT_KEY')
            
            if not all([hostname, client_id, client_key]):
                logger.error("Missing GES connection details in environment variables")
                return False
            
            self.service = EntitlementsService(
                hostname=hostname,
                port=port,
                namespace="default",  # Temporary namespace, will be overridden per call
                client_id=client_id,
                client_key=client_key
            )
            
            self.initialized = True
            logger.info("GES service initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GES service: {str(e)}")
            return False
    
    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace
        
        Args:
            username: The username
            namespace: The namespace to check
            
        Returns:
            List of group names in that namespace
        """
        if not self.initialized:
            if not self.initialize():
                return []
        
        try:
            # Create a new service instance for this specific namespace
            namespace_service = EntitlementsService(
                hostname=self.service.hostname,
                port=self.service.port,
                namespace=namespace,  # Use the specific namespace
                client_id=self.service.client_id,
                client_key=self.service.client_key
            )
            
            groups = namespace_service.get_roles(username)
            
            # Normalize groups to list of strings
            if isinstance(groups, list):
                normalized_groups = [str(group).lower() for group in groups]
            elif groups:
                normalized_groups = [str(groups).lower()]
            else:
                normalized_groups = []
            
            logger.info(f"User {username} has {len(normalized_groups)} groups in namespace {namespace}: {normalized_groups}")
            return normalized_groups
            
        except Exception as e:
            logger.error(f"Error fetching groups for user {username} in namespace {namespace}: {str(e)}")
            return []
    
    def get_user_groups_in_multiple_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's groups across multiple namespaces
        
        Args:
            username: The username
            namespaces: List of namespaces to check
            
        Returns:
            Dict mapping namespace to list of groups
        """
        results = {}
        
        for namespace in namespaces:
            groups = self.get_user_groups_in_namespace(username, namespace)
            results[namespace] = groups
        
        return results

# Global GES service instance
ges_service = GESService()
