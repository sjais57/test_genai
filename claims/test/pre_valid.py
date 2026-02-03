from datetime import datetime, time
import pytz

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
# TIME WINDOW CHECK (GLOBAL)
# -------------------------------------------------------
if start_time and end_time:
    try:
        if not _is_within_time_window(start_time, end_time):
            return {
                "valid": False,
                "message": "Project is not started yet or access window expired",
                "start_time": start_time,
                "end_time": end_time,
                "current_time_cst": datetime.now(CST_TZ).strftime("%d-%m-%Y %H:%M:%S")
            }
    except Exception as e:
        logger.error(f"Invalid START_TIME / END_TIME: {str(e)}")
        return {
            "valid": False,
            "message": "Invalid START_TIME / END_TIME configuration"
        }


