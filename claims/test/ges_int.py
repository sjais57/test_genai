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
def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's GROUPS in a specific namespace using EntitlementsService.get_groups.
        Uses safe_parse_groups to normalize list/set/str/dict payloads.
        """
        try:
            hostname  = os.getenv("GES_HOSTNAME", "")
            port      = os.getenv("GES_PORT", "")
            clientId  = os.getenv("GES_CLIENT_ID", "")
            clientKey = os.getenv("GES_CLIENT_KEY", "")

            logger.info("Checking GES groups for user '%s' in namespace '%s'", username, namespace)
            ges_service = EntitlementsService(
                hostname=hostname,
                port=port,
                namespace=namespace,
                clientId=clientId,
                clientKey=clientKey,
            )
            raw = ges_service.get_groups(username)   # <-- groups path
            logger.info("Raw groups payload type: %s", type(raw).__name__)
            logger.debug("Raw groups payload: %r", raw)
            groups = safe_parse_groups(raw)
            logger.info("Parsed groups: %s", groups)
            return groups
        except Exception as e:
            logger.error("Failed to get user groups for %s in ns=%s: %s", username, namespace, e, exc_info=True)
            return []

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {}
        for ns in namespaces:
            groups = self.get_user_groups_in_namespace(username, ns)
            if groups:
                results[ns] = groups
        return results
    def get_user_roles_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace. Handles list/set/str/dict variants.
        """
            raw = ges_service.get_roles(username)
            raw = ges_service.get_roles(username)   # roles path

ges_service = GESService()



===============================

# auth/ges_integration.py
import logging, ast, json, os
from typing import List, Dict, Any, Tuple
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

    def get_user_entitlements_in_namespace(self, username: str, namespace: str) -> Dict[str, List[str]]:
        """
        Get both roles and groups for a user in a specific namespace.
        Returns: {"roles": [], "groups": []}
        """
        try:
            logger.info(f"GES: Getting roles and groups for user '{username}' in namespace '{namespace}'")

            ges_service = EntitlementsService(
                hostname=self.hostname,
                port=self.port,
                namespace=namespace,
                client_id=self.client_id,
                client_key=self.client_key,
            )

            # Get ROLES
            raw_roles = ges_service.get_roles(username)
            logger.info(f"GES: Raw roles response type: {type(raw_roles)}")
            logger.info(f"GES: Raw roles response: {raw_roles}")

            # Get GROUPS
            raw_groups = ges_service.get_groups(username)
            logger.info(f"GES: Raw groups response type: {type(raw_groups)}")
            logger.info(f"GES: Raw groups response: {raw_groups}")

            # Process both
            roles_list = _safe_parse_groups(raw_roles)
            groups_list = _safe_parse_groups(raw_groups)

            logger.info(f"GES: Processed roles: {roles_list}")
            logger.info(f"GES: Processed groups: {groups_list}")

            return {
                "roles": roles_list,
                "groups": groups_list
            }
            
        except Exception as e:
            logger.error(f"GES: Error getting entitlements: {e}", exc_info=True)
            return {"roles": [], "groups": []}

    def get_user_entitlements_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, Dict[str, List[str]]]:
        """
        Get both roles and groups for a user in multiple namespaces.
        Returns: {
            "namespace1": {"roles": [], "groups": []},
            "namespace2": {"roles": [], "groups": []}
        }
        """
        results = {}
        for ns in namespaces:
            logger.info(f"GES: Fetching entitlements for namespace: {ns}")
            entitlements = self.get_user_entitlements_in_namespace(username, ns)
            if entitlements["roles"] or entitlements["groups"]:
                results[ns] = entitlements
                logger.info(f"GES: Found roles: {entitlements['roles']}, groups: {entitlements['groups']} in namespace '{ns}'")
            else:
                logger.info(f"GES: No entitlements found in namespace '{ns}' for user '{username}'")
        return results

    # Keep individual methods for backward compatibility
    def get_user_groups_in_namespace(self, username: str, namespace: str) -> List[str]:
        """
        Get user's roles in a specific namespace (backward compatibility).
        """
        entitlements = self.get_user_entitlements_in_namespace(username, namespace)
        return entitlements["roles"]

    def get_user_groups_in_namespaces(self, username: str, namespaces: List[str]) -> Dict[str, List[str]]:
        """
        Get user's roles in multiple namespaces (backward compatibility).
        """
        results = {}
        entitlements_data = self.get_user_entitlements_in_namespaces(username, namespaces)
        for namespace, data in entitlements_data.items():
            results[namespace] = data["roles"]
        return results

    def get_user_groups(self, username: str, namespace: str) -> List[str]:
        """
        Get user's groups in a specific namespace (backward compatibility).
        """
        entitlements = self.get_user_entitlements_in_namespace(username, namespace)
        return entitlements["groups"]

ges_service = GESService()
