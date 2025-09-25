# ges_integration.py
import os
import logging
from typing import List, Dict, Any, Optional
from ges_entitylements.security import EntitlementsService

logger = logging.getLogger(__name__)

class GESManager:
    def __init__(self):
        self.services = {}  # namespace -> EntitlementsService mapping
        self.initialized = False
        
    def initialize_services(self):
        """Initialize GES services for different namespaces"""
        try:
            # Get GES configuration from environment variables
            ges_configs = self._get_ges_configs()
            
            for namespace, config in ges_configs.items():
                try:
                    service = EntitlementsService(
                        hostname=config['hostname'],
                        port=config['port'],
                        namespace=namespace,
                        client_id=config['client_id'],
                        client_key=config['client_key']
                    )
                    self.services[namespace] = service
                    logger.info(f"GES service initialized for namespace: {namespace}")
                except Exception as e:
                    logger.error(f"Failed to initialize GES for namespace {namespace}: {str(e)}")
            
            self.initialized = True
            logger.info("GES services initialization completed")
            
        except Exception as e:
            logger.error(f"Failed to initialize GES services: {str(e)}")
            self.initialized = False
    
    def _get_ges_configs(self) -> Dict[str, Dict]:
        """Get GES configurations from environment variables"""
        configs = {}
        
        # Example: GES_NAMESPACES=namespace1,namespace2,namespace3
        namespaces = os.getenv('GES_NAMESPACES', '').split(',')
        
        for namespace in namespaces:
            namespace = namespace.strip()
            if not namespace:
                continue
                
            hostname = os.getenv(f'GES_{namespace.upper()}_HOSTNAME')
            port = os.getenv(f'GES_{namespace.upper()}_PORT')
            client_id = os.getenv(f'GES_{namespace.upper()}_CLIENT_ID')
            client_key = os.getenv(f'GES_{namespace.upper()}_CLIENT_KEY')
            
            if all([hostname, port, client_id, client_key]):
                configs[namespace] = {
                    'hostname': hostname,
                    'port': int(port),
                    'client_id': client_id,
                    'client_key': client_key
                }
        
        return configs
    
    def get_user_groups(self, username: str, namespaces: List[str] = None) -> Dict[str, List[str]]:
        """
        Get user's groups from specified namespaces
        
        Args:
            username: The username to look up
            namespaces: List of namespaces to check (if None, check all initialized namespaces)
            
        Returns:
            Dict mapping namespace to list of groups
        """
        if not self.initialized:
            self.initialize_services()
        
        results = {}
        
        target_namespaces = namespaces if namespaces else list(self.services.keys())
        
        for namespace in target_namespaces:
            if namespace not in self.services:
                logger.warning(f"GES service not initialized for namespace: {namespace}")
                continue
                
            try:
                groups = self.services[namespace].get_roles(username)
                # Normalize groups to list of strings
                if isinstance(groups, list):
                    normalized_groups = [str(group).lower() for group in groups]
                elif groups:
                    normalized_groups = [str(groups).lower()]
                else:
                    normalized_groups = []
                
                results[namespace] = normalized_groups
                logger.info(f"Retrieved {len(normalized_groups)} groups for user {username} in namespace {namespace}")
                
            except Exception as e:
                logger.error(f"Error fetching groups for user {username} in namespace {namespace}: {str(e)}")
                results[namespace] = []
        
        return results
    
    def get_all_user_groups(self, username: str) -> List[str]:
        """
        Get all unique groups across all namespaces for a user
        
        Args:
            username: The username to look up
            
        Returns:
            List of unique group names
        """
        namespace_groups = self.get_user_groups(username)
        all_groups = []
        
        for groups in namespace_groups.values():
            all_groups.extend(groups)
        
        return list(set(all_groups))

# Global GES manager instance
ges_manager = GESManager()
