# claims/group_category.py
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Simple function to get both roles and groups for JWT token
    """
    logger.info(f"Getting GES data for user: {user_id}")
    
    if not user_id:
        logger.error("No user_id provided")
        return {}
    
    # Import GES service
    try:
        from auth.ges_integration import ges_service
    except ImportError as e:
        logger.error(f"Failed to import GES service: {e}")
        return {}
    
    try:
        # Get namespaces from rules
        namespaces = []
        for rule in rules:
            namespace_value = rule.get('ges_namespace', '')
            if namespace_value:
                namespaces.extend([ns.strip() for ns in namespace_value.split(',') if ns.strip()])
        
        # Get ROLES from namespaces
        roles_list = []
        if namespaces:
            ges_roles_data = ges_service.get_user_groups_in_namespaces(user_id, namespaces)
            for namespace_roles in ges_roles_data.values():
                roles_list.extend(namespace_roles)
            
            # Remove duplicate roles
            roles_list = list(dict.fromkeys(roles_list))
        
        # Get GROUPS (not namespace-specific)
        groups_list = ges_service.get_user_groups(user_id)
        
        # Return both in JWT token
        result = {
            "ges_namespace_roles": {"roles": roles_list},
            "ges_namespace_groups": {"groups": groups_list}
        }
        
        logger.info(f"GES data result: {result}")
        return result
            
    except Exception as e:
        logger.error(f"Error getting GES data: {str(e)}")
        return {
            "ges_namespace_roles": {"roles": []},
            "ges_namespace_groups": {"groups": []}
        }


# claims/group_category.py
from typing import Any, Dict, List
import logging
logger = logging.getLogger(__name__)

def _to_list(x: Any, prefer_key: str | None = None) -> List[str]:
    """
    Normalize various SDK return shapes into a flat list[str].
    Handles list, set, tuple, str (comma/space separated), and dicts like
    {"roles": [...]}, {"groups": [...]}. If prefer_key is provided, try that key first.
    """
    if x is None:
        return []
    if isinstance(x, list):
        return [str(i).strip() for i in x if str(i).strip()]
    if isinstance(x, (set, tuple)):
        return [str(i).strip() for i in list(x) if str(i).strip()]
    if isinstance(x, str):
        # split on comma or whitespace
        parts = [p.strip() for p in x.replace(",", " ").split() if p.strip()]
        return parts
    if isinstance(x, dict):
        if prefer_key and prefer_key in x and isinstance(x[prefer_key], (list, set, tuple, str)):
            return _to_list(x[prefer_key])
        # try common keys
        for k in ("roles", "groups", "items", "values"):
            if k in x:
                return _to_list(x[k])
        # last resort: flatten values
        vals = []
        for v in x.values():
            vals.extend(_to_list(v))
        return vals
    # unknown type
    return [str(x).strip()] if str(x).strip() else []

def _dedup_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out

def _parse_namespaces(rules: List[Dict[str, Any]]) -> List[str]:
    wanted: List[str] = []
    for rule in rules or []:
        ns_val = (rule or {}).get("ges_namespace", "")
        if not ns_val:
            continue
        for ns in [p.strip() for p in ns_val.split(",") if p.strip()]:
            if ns not in wanted:
                wanted.append(ns)
    return wanted

def get_ges_namespace_roles(user_id: str, rules: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Unified dynamic: returns BOTH roles and groups collected across the given namespaces.

    Output shape:
      {
        "roles":  [ ...unique roles... ],
        "groups": [ ...unique groups... ]
      }
    """
    logger.info("ENTER get_ges_namespace_roles (merged)")
    logger.info("Args: user_id=%r rules=%r", user_id, rules)

    if not user_id:
        logger.error("No user_id provided")
        return {"roles": [], "groups": []}

    namespaces = _parse_namespaces(rules)
    if not namespaces:
        logger.info("No namespaces specified in API-key rules")
        return {"roles": [], "groups": []}

    # Late import to avoid circulars
    try:
        from auth.ges_auth_cleaned import GESService  # or your actual service module/class
    except Exception as e:
        logger.error("Failed to import GES service: %s", e, exc_info=True)
        return {"roles": [], "groups": []}

    svc = GESService()

    all_roles: List[str] = []
    all_groups: List[str] = []

    for ns in namespaces:
        try:
            # IMPORTANT: your EntitlementsService **must** be constructed with namespace.
            # GESService should handle that internally.
            raw_roles = svc.get_user_roles_in_namespace(user_id, ns)   # may return list/dict/etc.
            raw_groups = svc.get_user_groups_in_namespace(user_id, ns)

            roles = _to_list(raw_roles, prefer_key="roles")
            groups = _to_list(raw_groups, prefer_key="groups")

            logger.info("NS=%s -> roles=%r groups=%r", ns, roles, groups)

            all_roles.extend(roles)
            all_groups.extend(groups)

        except Exception as e:
            logger.error("Namespace %s fetch failed: %s", ns, e, exc_info=True)

    result = {
        "roles":  _dedup_preserve_order(all_roles),
        "groups": _dedup_preserve_order(all_groups),
    }

    logger.info("EXIT get_ges_namespace_roles -> %r", result)
    return result
