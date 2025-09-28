def check_pre_validation(api_key: str, normalized_ad_groups: list[str], username: str) -> dict:
    """
    Validate user according to API key's pre_validation_check:

    pre_validation_check:
      mode: any         # optional, 'any' (default) or 'all'
      LDAP: "AML.Viewer, DFS"   # comma-separated or list
      GES:  "namespace1, namespace2"  # comma-separated or list

    - LDAP passes if the user is in ANY of the listed AD groups.
    - GES passes if the user belongs to ANY group within ANY of the listed namespaces.
    - Final decision uses 'mode' across the present checks (any|all).
    """
    try:
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        api_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
        if not os.path.exists(api_key_file):
            return {"valid": False, "message": "Invalid API key"}

        with open(api_key_file, "r") as f:
            api_key_config = yaml.safe_load(f) or {}

        pvc = api_key_config.get("pre_validation_check") or {}
        # Backward compatibility: if pvc is a string/list, treat as LDAP-only
        if isinstance(pvc, (str, list, tuple, set)):
            pvc = {"LDAP": pvc}

        mode = str(pvc.get("mode", "any")).lower()
        ldap_required   = _parse_csv_or_list(pvc.get("LDAP"))
        ges_namespaces  = _parse_csv_or_list(pvc.get("GES"))

        # Nothing configured -> allow
        if not ldap_required and not ges_namespaces:
            return {"valid": True, "message": "No pre-validation required"}

        # Prepare user groups (normalized AD)
        ad_norm = [_norm_group(g) for g in (normalized_ad_groups or [])]

        # LDAP check (ANY match)
        ldap_ok = False
        matched_ldap = []
        if ldap_required:
            required_norm = [_norm_group(g) for g in ldap_required]
            user_set = set(ad_norm)
            matched_ldap = [g for g in required_norm if g in user_set]
            ldap_ok = len(matched_ldap) > 0

        # GES check (ANY namespace where user has ANY group)
        ges_ok = False
        matched_ns = []
        if ges_namespaces:
            try:
                from auth.ges_integration import ges_service
                for ns in ges_namespaces:
                    ns = ns.strip()
                    if not ns:
                        continue
                    groups = ges_service.get_user_groups_in_namespace(username, ns) or []
                    # If the user has at least one group in this namespace, we consider GES passed
                    if groups:
                        ges_ok = True
                        matched_ns.append(ns)
                        break  # ANY namespace is enough
            except Exception as e:
                logger.error(f"Failed to query GES namespaces for pre-validation: {e}", exc_info=True)
                ges_ok = False

        # Combine according to mode, but only across checks that are actually present
        checks = []
        labels = []
        if ldap_required:
            checks.append(ldap_ok); labels.append(f"LDAP({','.join(ldap_required)})")
        if ges_namespaces:
            checks.append(ges_ok);  labels.append(f"GES({','.join(ges_namespaces)})")

        if not checks:
            return {"valid": True, "message": "No pre-validation required"}

        if mode == "all":
            ok = all(checks)
        else:
            ok = any(checks)

        if ok:
            details = []
            if ldap_required:
                details.append(f"LDAP matched: {matched_ldap}" if matched_ldap else "LDAP not matched")
            if ges_namespaces:
                details.append(f"GES matched namespaces: {matched_ns}" if matched_ns else "GES not matched")
            return {"valid": True, "message": f"Pre-validation passed ({mode} of {labels}). " + "; ".join(details)}

        return {
            "valid": False,
            "message": f"Pre-validation failed ({mode} of {labels}).",
            "required": {"LDAP": ldap_required, "GES": ges_namespaces},
            "user_ad_groups": ad_norm,
            "matched_ldap": matched_ldap,
            "matched_ges_namespaces": matched_ns,
        }

    except Exception as e:
        logger.error(f"Error during pre-validation check: {e}", exc_info=True)
        return {"valid": False, "message": f"Error during validation: {e}"}
