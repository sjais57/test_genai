# auth/ges_integration.py
import logging
import ast
import json
from typing import Dict, List, Any
from ges_entitlements.security import EntitlementsService

logger = logging.getLogger(__name__)

def _safe_parse_groups(obj: Any) -> List[str]:
    """
    Parse GES groups/roles data from various formats
    This is GES-specific parsing logic
    """
    def _to_list(x):
        if x is None:
            return []
        if isinstance(x, (list, tuple, set)):
            return [str(i) for i in x]
        if isinstance(x, dict):
            if "namespace" in x:
                return _to_list(x["namespace"])
            out = []
            for v in x.values():
                out.extend(_to_list(v))
            return out
        if isinstance(x, str):
            s = x.strip()
            if (s.startswith('[') and s.endswith(']')) or (s.startswith('{') and s.endswith('}')):
                try:
                    parsed = ast.literal_eval(s)
                    return _to_list(parsed)
                except Exception:
                    try:
                        parsed = json.loads(s)
                        return _to_list(parsed)
                    except Exception:
                        pass
            if ',' in s and not s.startswith('{'):
                return [p.strip().strip("'\"") for p in s.split(',') if p.strip()]
            return [s.strip().strip("'\"")]
        return [str(x)]

    items = _to_list(obj)
    seen, out = set(), []
    for g in items:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


class GESService:
    def __init__(self): 
        self.hostname = "your-ges-server.com"
        self.port = 8080
        self.client_id = "your-client-id"
        self.client_key = "your-client-key"

    def get_user_entitlements(self, username: str) -> Dict[str, Any]:
        """
        Get user's roles and groups in a single call
        """
        try:
            logger.info(f"Getting GES entitlements for user: {username}")
            
            ges_service = EntitlementsService(
                hostname=self.hostname,
                port=self.port,
                client_id=self.client_id,
                client_key=self.client_key,
            )
            
            # Get both roles and groups
            raw_roles = ges_service.get_roles(username)
            raw_groups = ges_service.get_groups(username)
            
            logger.info(f"Raw GES roles response: {raw_roles}")
            logger.info(f"Raw GES groups response: {raw_groups}")
            
            return {
                "roles": raw_roles,
                "groups": raw_groups
            }
            
        except Exception as e:
            logger.error(f"Error getting GES entitlements for user {username}: {e}")
            return {"roles": None, "groups": None}

    # Keep individual functions for backward compatibility
    def get_roles(self, username: str) -> Any:
        """
        Get user's roles only
        """
        entitlements = self.get_user_entitlements(username)
        return entitlements.get("roles")

    def get_groups(self, username: str) -> Any:
        """
        Get user's groups only  
        """
        entitlements = self.get_user_entitlements(username)
        return entitlements.get("groups")


# Global instance
ges_service = GESService()
