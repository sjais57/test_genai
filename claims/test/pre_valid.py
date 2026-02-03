from datetime import datetime, time
import pytz

CST_TZ = pytz.timezone("US/Central")

CST_TZ = pytz.timezone("US/Central")

def _parse_dd_mm_yyyy(date_str: str) -> datetime:
    return datetime.strptime(date_str, "%d-%m-%Y")

def _is_within_time_window(start_date: str, end_date: str) -> bool:
    now_cst = datetime.now(CST_TZ)

    start_dt = CST_TZ.localize(
        datetime.combine(_parse_dd_mm_yyyy(start_date), time.min)
    )
    end_dt = CST_TZ.localize(
        datetime.combine(_parse_dd_mm_yyyy(end_date), time.max)
    )

    return start_dt <= now_cst <= end_dt



# --- Defaults ---
required_ldap_groups = []
required_ldap_users = []
required_ges_namespaces = []
start_time = None
end_time = None

elif isinstance(pre_validation_config, dict):
    logger.info("Using structured pre-validation format")
# Time window (optional)
start_time = pre_validation_config.get("START_TIME")
end_time = pre_validation_config.get("END_TIME")

# -------------------------------------------------------
# TIME WINDOW CHECK (DETAILED)
# -------------------------------------------------------
if start_time and end_time:
    try:
        now_cst = datetime.now(CST_TZ)

        start_dt = CST_TZ.localize(
            datetime.combine(_parse_dd_mm_yyyy(start_time), time.min)
        )
        end_dt = CST_TZ.localize(
            datetime.combine(_parse_dd_mm_yyyy(end_time), time.max)
        )

        if now_cst < start_dt:
            return {
                "valid": False,
                "message": "Project has not been started",
                "start_time": start_time,
                "current_time_cst": now_cst.strftime("%d-%m-%Y %H:%M:%S")
            }

        if now_cst > end_dt:
            return {
                "valid": False,
                "message": "Project expired",
                "end_time": end_time,
                "current_time_cst": now_cst.strftime("%d-%m-%Y %H:%M:%S")
            }

        # else → within window, continue validation

    except Exception as e:
        logger.error(f"Invalid START_TIME / END_TIME: {str(e)}")
        return {
            "valid": False,
            "message": "Invalid START_TIME / END_TIME configuration"
        }

