# auth/ges_integration.py
import logging, ast, json
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
        # Initialize your GES connection parameters here
        self.hostname = "your-ges-server.com"  # Replace with actual hostname
        self.port = 8080                       # Replace with actual port
        self.client_id = "your-client-id"      # Replace with actual client ID
        self.client_key = "your-client-key"    # Replace with actual client key

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

ges_service = GESService()
