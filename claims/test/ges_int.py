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
        # Load configuration once in __init__ for all methods
        self.hostname = os.getenv("GES_HOSTNAME", "")
        self.port = int(os.getenv("GES_PORT", "8080"))
        self.client_id = os.getenv("GES_CLIENT_ID", "")
        self.client_key = os.getenv("GES_CLIENT_KEY", "")
        
        # Log configuration (mask sensitive data)
        logger.info(f"GES Service initialized - Hostname: {self.hostname}, Port: {self.port}")
        logger.info(f"GES Client ID: {self.client_id}")
        logger.info(f"GES Client Key: {'*' * len(self.client_key) if self.client_key else 'Not set'}")

    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace.
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
            logger.error(f"Error getting GES groups: {e}", exc_info=True)
            return []

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's groups in multiple namespaces.
        """
        results = {}
        for ns in namespaces:
            groups = self.get_user_groups_in_namespace(username, ns)
            if groups:
                results[ns] = groups
        return results

    def get_user_groups(self, username: str) -> List[str]:
        """
        Simple method to get user's groups (not namespace-specific)
        """
        try:
            logger.info(f"Getting GES groups for user '{username}'")

            ges_service = EntitlementsService(
                hostname=self.hostname,
                port=self.port,
                client_id=self.client_id,
                client_key=self.client_key,
            )

            raw = ges_service.get_groups(username)
            logger.info(f"Raw GES groups response: {raw}")

            groups_list = _safe_parse_groups(raw)
            logger.info(f"Processed groups: {groups_list}")
            return groups_list
        except Exception as e:
            logger.error(f"Error getting GES groups: {e}", exc_info=True)
            return []

ges_service = GESService()
