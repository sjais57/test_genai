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

    def get_ges_namespace_groups(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        Dynamic claims function to fetch and combine GES groups across namespaces.
        Returns: {"groups": [ ...unique groups... ]}
        """
        logger.info("ENTERING get_ges_namespace_groups function")
        logger.info(f"Parameters - user_id: {user_id}, rules: {rules}")
        if 'metadata' in kwargs:
            logger.info(f"Metadata received: {kwargs['metadata']}")
        if not user_id:
            logger.error("No user_id provided for GES groups lookup")
            return {}
    
        # Import late to avoid circulars
        try:
            from auth.ges_integration import ges_service
            logger.info("Successfully imported GES service")
        except ImportError as e:
            logger.error(f"Failed to import GES service: {e}")
            return {}
    
        # Parse namespaces (support comma-separated)
        required_namespaces: List[str] = []
        for rule in rules or []:
            ns_val = (rule or {}).get("ges_namespace", "")
            if ns_val:
                for ns in [p.strip() for p in ns_val.split(",") if p.strip()]:
                    if ns not in required_namespaces:
                        required_namespaces.append(ns)
        if not required_namespaces:
            logger.info("No GES namespaces specified in API key rules for groups")
            return {}
    
        logger.info(f"Required namespaces for GES groups: {required_namespaces}")
        try:
            # Fetch groups per-namespace
            logger.info(f"Calling ges_service.get_user_groups_in_namespaces: user={user_id}, namespaces={required_namespaces}")
            ns_to_groups = ges_service.get_user_groups_in_namespaces(user_id, required_namespaces)
            logger.info(f"Fetched GES groups data: {ns_to_groups}")
    
            # Flatten + de-dup preserving order
            all_groups: List[str] = []
            seen = set()
            for ns in required_namespaces:
                groups = ns_to_groups.get(ns, [])
                logger.info(f"Processing namespace '{ns}' groups: {groups}")
                for g in groups:
                    if g not in seen:
                        seen.add(g)
                        all_groups.append(g)
    
            final_result = {"groups": all_groups}
            logger.info(f"Final groups result: {final_result}")
            logger.info("EXITING get_ges_namespace_groups function")
            return final_result
        except Exception as e:
            logger.error(f"Error fetching GES groups: {str(e)}", exc_info=True)
            return {}

ges_service = GESService()
