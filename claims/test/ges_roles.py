# claims/ges_roles.py
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def get_ges_roles(user_groups: Dict[str, List[str]], rules: List[Dict]) -> Dict[str, Any]:
    """
    From the already-fetched GES groups (user_groups = {namespace: [roles,...]}),
    select namespaces according to rules and emit their roles into JWT claims.

    Args:
      user_groups: dict like {"namespace2": ["TEST1", "TEST1.Access1", ...], ...}
      rules: list of rules from API-key YAML, e.g.:
        - { match_type: "exact", ges_namespace: "namespace2", value: { roles: [] } }

    Returns:
      dict of { <namespace>: { "roles": [...] }, ... }
    """
    claims: Dict[str, Any] = {}

    try:
        logger.info("PROCESSING GES NAMESPACE ROLES (dynamic claims)")
        logger.info(f"All user GES data: {user_groups}")
        logger.info(f"Filter rules: {rules}")

        if not isinstance(user_groups, dict):
            logger.warning("user_groups is not a dict; nothing to emit")
            return {}

        for rule in (rules or []):
            mt = (rule or {}).get("match_type", "exact")
            ns = (rule or {}).get("ges_namespace")
            template = (rule or {}).get("value", {}) or {}

            logger.info(f"Applying GES rule: match_type={mt} ges_namespace={ns}")

            if mt == "exact" and ns:
                roles = user_groups.get(ns, [])
                if roles:
                    out: Dict[str, Any] = {}
                    # Only write keys present in template (today just 'roles')
                    if "roles" in template:
                        # keep order + de-dup
                        seen, out_roles = set(), []
                        for r in roles:
                            if r not in seen:
                                seen.add(r)
                                out_roles.append(r)
                        out["roles"] = out_roles
                    claims[ns] = out
                    logger.info(f"Emitting claims for '{ns}': {out}")
                else:
                    logger.info(f"No roles found for namespace '{ns}' in user data")

            # (Optional) support prefix matches later:
            # elif mt == "startswith" and ns:
            #     for k, roles in user_groups.items():
            #         if k.startswith(ns) and roles:
            #             claims[k] = {"roles": list(dict.fromkeys(roles))}

        logger.info(f"Final GES namespace roles claims: {claims}")
        return claims

    except Exception as e:
        logger.error(f"Error in GES namespace roles extraction: {e}", exc_info=True)
        return {}
