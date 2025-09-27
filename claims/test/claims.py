# claims/ges_claims.py
import logging, yaml, os, re
from typing import Dict, Any

logger = logging.getLogger(__name__)

def _normalize(name: str) -> str:
    """
    Canonicalize group names for matching:
    - lower-case
    - collapse separators: treat '.' and '_' as equivalent
    - strip surrounding quotes/spaces
    """
    s = str(name).strip().strip("'\"").lower()
    # replace any run of [._\s-] with a single dot
    s = re.sub(r"[._\s-]+", ".", s)
    return s

def _equal_group(a: str, b: str) -> bool:
    """
    Equality allowing '.' vs '_' vs '-' vs spaces.
    """
    return _normalize(a) == _normalize(b)

def get_ges_claims_from_api_key(username: str, api_key: str) -> Dict[str, Any]:
    """
    Get claims based on user's GES groups in namespaces
    """
    try:
        from auth.ges_integration import ges_service

        logger.info("STARTING GES CLAIMS PROCESSING")
        logger.info(f"   User: {username}")
        logger.info(f"   API Key: {api_key}")

        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        if not os.path.exists(api_key_file):
            logger.warning("API key file not found")
            return {}

        with open(api_key_file, "r") as f:
            api_key_config = yaml.safe_load(f) or {}

        namespace_configs = (api_key_config.get("metadata") or {}).get("ges_namespaces", {})
        if not namespace_configs:
            logger.info("No GES namespace configurations found")
            return {}

        namespaces_to_check = list(namespace_configs.keys())
        logger.info(f"Checking namespaces: {namespaces_to_check}")

        user_namespace_groups = ges_service.get_user_groups_in_namespaces(username, namespaces_to_check)
        logger.info(f"User groups from GES: {user_namespace_groups}")

        if not user_namespace_groups:
            logger.info("User has no groups in any namespace")
            return {}

        claims: Dict[str, Any] = {}
        matched_groups = []
        all_api_groups = []  # keep for final log

        for namespace, user_groups in user_namespace_groups.items():
            logger.info(f"Processing namespace: {namespace}")
            logger.info(f"User groups: {user_groups} (type: {type(user_groups)})")

            ns_cfg = namespace_configs.get(namespace) or {}
            group_claims_mapping = ns_cfg.get("group_claims", {}) or {}
            api_key_groups = list(group_claims_mapping.keys())
            all_api_groups.extend(api_key_groups)
            logger.info(f"   API key groups: {api_key_groups}")

            # Precompute normalized map for API groups
            api_norm_map = { _normalize(k): k for k in api_key_groups }

            for user_group in user_groups:
                logger.info(f"Checking user group: '{user_group}' (type: {type(user_group)})")
                ug = str(user_group).strip().strip("'\"")
                ug_norm = _normalize(ug)
                logger.info(f"Cleaned group name: '{ug}'  | normalized: '{ug_norm}'")

                # Exact (plain) then normalized match
                if ug in group_claims_mapping:
                    base_key = ug
                elif ug_norm in api_norm_map:
                    base_key = api_norm_map[ug_norm]
                    logger.info(f"CASE/SEPARATOR-INSENSITIVE MATCH -> '{base_key}'")
                else:
                    logger.info(f"No match for '{ug}'")
                    continue

                group_claims = group_claims_mapping.get(base_key, {})
                if not isinstance(group_claims, dict):
                    logger.warning(f"Claims for group '{base_key}' are not a dict, skipping")
                    continue

                # Merge dict claims (later groups can override earlier keys)
                claims.update(group_claims)
                matched_groups.append(f"{namespace}:{ug} -> {base_key}")
                logger.info(f"Claims applied: keys={list(group_claims.keys())}")

        if claims:
            logger.info("SUCCESS: Generated GES claims")
            logger.info(f"Matched groups: {matched_groups}")
            logger.info(f"Final claims keys: {list(claims.keys())}")
        else:
            logger.warning("No claims generated")
            logger.info(f"User had groups: {user_namespace_groups}")
            logger.info(f"But no matches with API key groups: {all_api_groups}")

        return claims

    except Exception as e:
        logger.error(f"Error in GES claims processing: {e}", exc_info=True)
        return {}
