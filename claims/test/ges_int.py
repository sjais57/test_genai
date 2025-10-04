# auth/ges_integration.py
import logging, ast, json, os
from typing import List, Dict, Any
from ges_entitylements.security import EntitlementsService

logger = logging.getLogger(__name__)

def _safe_parse_groups(obj: Any) -> List[str]:
    """
    Accepts: list | set | str(repr(list|set)) | {"namespace": <list|set|str>} | None
    Returns: list[str]
    """
    def _to_list(x):
        if x is None:
            return []
        if isinstance(x, (list, tuple, set)):
            return [str(i) for i in x]
        if isinstance(x, dict):
            # Common GES wrap: {"namespace": "['A','B']"} or {"namespace": ['A','B']}
            if "namespace" in x:
                return _to_list(x["namespace"])
            # Fall back to all values
            out = []
            for v in x.values():
                out.extend(_to_list(v))
            return out
        if isinstance(x, str):
            s = x.strip()
            # If string looks like a Python/JSON container, try parsing
            if (s.startswith('[') and s.endswith(']')) or (s.startswith('{') and s.endswith('}')):
                # Try ast first (handles single quotes + sets)
                try:
                    parsed = ast.literal_eval(s)
                    return _to_list(parsed)
                except Exception:
                    # Try JSON as a secondary path (requires double quotes / lists)
                    try:
                        parsed = json.loads(s)
                        return _to_list(parsed)
                    except Exception:
                        # Fall-through to manual split for degenerate cases
                        pass
            # Manual split on commas if user sent "A, B, C"
            if ',' in s and not s.startswith('{'):
                return [p.strip().strip("'\"") for p in s.split(',') if p.strip()]
            # Otherwise treat as single group token
            return [s.strip().strip("'\"")]
        # Anything else → string it
        return [str(x)]

    items = _to_list(obj)
    # de-dup while preserving order
    seen, out = set(), []
    for g in items:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


class GESService:
    def __init__(self): 
        # Load GES connection parameters from environment variables
        self.hostname = os.getenv("GES_HOSTNAME", "your-ges-server.com")
        self.port = int(os.getenv("GES_PORT", "8080"))
        self.client_id = os.getenv("GES_CLIENT_ID", "your-client-id")
        self.client_key = os.getenv("GES_CLIENT_KEY", "your-client-key")
        
        # Log the configuration (mask sensitive data)
        logger.info(f"GES Service initialized - Hostname: {self.hostname}, Port: {self.port}")
        logger.info(f"GES Client ID: {self.client_id}")
        logger.info(f"GES Client Key: {'*' * len(self.client_key) if self.client_key else 'Not set'}")

    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace. Handles list/set/str/dict variants.
        """
        try:
            logger.info(f"Checking GES groups for user '{username}' in namespace '{namespace}'")

            ges_service = EntitlementsService(
                hostname=self.hostname,
                port=self.port,
                namespace=namespace,
                client_id=self.client_id,
                client_key=self.client_key,
            )

            raw = ges_service.get_roles(username)
            logger.info(f"Raw GES response type: {type(raw)}")
            logger.info(f"Raw GES response: {raw}")

            group_list = _safe_parse_groups(raw)
            logger.info(f"Processed groups: {group_list}")
            return group_list
        except Exception as e:
            logger.error(f"Error getting GES groups for user {username} in namespace {namespace}: {e}", exc_info=True)
            return []

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's groups in multiple namespaces.
        
        Args:
            username: The username to look up
            namespaces: List of namespace strings to check
            
        Returns:
            Dict with namespace as key and list of roles as value
        """
        results = {}
        for ns in namespaces:
            logger.info(f"Fetching GES roles for namespace: {ns}")
            groups = self.get_user_groups_in_namespace(username, ns)
            if groups:
                results[ns] = groups
                logger.info(f"Found {len(groups)} roles in namespace '{ns}': {groups}")
            else:
                logger.info(f"No roles found in namespace '{ns}' for user '{username}'")
        return results

    # NEW: Combined function for roles and groups
    def get_user_entitlements(self, username: str, namespaces: List[str] = None) -> Dict[str, Any]:
        """
        Get user's roles (from namespaces) and groups in a single call
        
        Args:
            username: The username to look up
            namespaces: List of namespaces to get roles from. If None, uses default namespaces.
            
        Returns:
            Dict with 'roles' and 'groups' keys
        """
        try:
            logger.info(f"Getting GES entitlements for user: {username}, namespaces: {namespaces}")
            
            # If no namespaces provided, use some default or get from configuration
            if namespaces is None:
                # You can set default namespaces here or get from config
                namespaces = ["namespace1", "namespace2"]  # Adjust as needed
                logger.info(f"Using default namespaces: {namespaces}")
            
            # Get roles from namespaces using existing method
            roles_data = self.get_user_groups_in_namespaces(username, namespaces)
            
            # Flatten all roles from all namespaces into a single list
            all_roles = []
            for namespace_roles in roles_data.values():
                all_roles.extend(namespace_roles)
            
            # Remove duplicate roles while preserving order
            unique_roles = []
            seen_roles = set()
            for role in all_roles:
                if role not in seen_roles:
                    seen_roles.add(role)
                    unique_roles.append(role)
            
            # Get groups
            groups_data = self._get_user_groups(username)
            
            logger.info(f"Processed roles: {unique_roles}")
            logger.info(f"Processed groups: {groups_data}")
            
            return {
                "roles": unique_roles,
                "groups": groups_data
            }
            
        except Exception as e:
            logger.error(f"Error getting GES entitlements for user {username}: {e}")
            return {"roles": [], "groups": []}

    def _get_user_groups(self, username: str) -> List[str]:
        """
        Get user's groups using service.get_groups(username)
        """
        try:
            logger.info(f"Getting GES groups for user: {username}")
            
            ges_service = EntitlementsService(
                hostname=self.hostname,
                port=self.port,
                client_id=self.client_id,
                client_key=self.client_key,
            )
            
            # Call get_groups method
            raw_groups = ges_service.get_groups(username)
            logger.info(f"Raw GES groups response: {raw_groups}")

            groups_list = _safe_parse_groups(raw_groups)
            logger.info(f"Processed groups: {groups_list}")
            return groups_list
            
        except Exception as e:
            logger.error(f"Error getting GES groups for user {username}: {e}")
            return []

    # Keep individual functions for backward compatibility
    def get_roles(self, username: str, namespaces: List[str] = None) -> List[str]:
        """
        Get user's roles only
        """
        entitlements = self.get_user_entitlements(username, namespaces)
        return entitlements.get("roles", [])

    def get_groups(self, username: str) -> List[str]:
        """
        Get user's groups only  
        """
        entitlements = self.get_user_entitlements(username)
        return entitlements.get("groups", [])

ges_service = GESService()
