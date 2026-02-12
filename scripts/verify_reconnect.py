import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("verify_reconnect")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# =========================
# Paths
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUT_DIR = BASE_DIR / "out"
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

COPILOTO_CSV_PATH = Path(os.getenv("COPILOTO_CSV_PATH", str(DATA_DIR / "vehicle_records.csv")))
PENDING_VERIFY = Path(os.getenv("PENDING_VERIFY", str(OUT_DIR / "pending_verify.csv")))
VERIFY_REPORT_PREFIX = os.getenv("VERIFY_REPORT_PREFIX", "verify_").strip()

# =========================
# Copiloto
# =========================
COPILOTO_ENDPOINT = os.getenv(
    "COPILOTO_ENDPOINT",
    "https://api.copiloto.ai/wicar-report/report-files/vehicle-records"
).strip()
COPILOTO_SIGNIN_URL = os.getenv("COPILOTO_SIGNIN_URL", "https://accounts.copiloto.ai/v1/sign-in").strip()
COPILOTO_EMAIL = os.getenv("COPILOTO_EMAIL", "").strip()
COPILOTO_PASSWORD = os.getenv("COPILOTO_PASSWORD", "").strip()

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))

# CSV columns
CSV_COL_IMEI = os.getenv("CSV_COL_IMEI", "IMEI")
CSV_LASTSEEN_COL = os.getenv("CSV_LASTSEEN_COL", "last_update_utc").strip()

# Reglas verify
# OK si last_update_utc > sent_at_utc (reconectó después del comando)
# FAIL si pasaron más de X horas sin reconectar (opcional)
MAX_HOURS_WAIT = float(os.getenv("VERIFY_MAX_HOURS_WAIT", "72"))  # 3 días por defecto

# =========================
# Helpers
# =========================
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def run_ts_str() -> str:
    return now_utc().strftime("%Y-%m-%d_%H%M%S")

def make_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=5, backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({"User-Agent": "iot-reboot-verify/1.0"})
    return s

def fetch_copiloto_token(email: str, password: str, session: requests.Session) -> str:
    if not email or not password:
        raise RuntimeError("Faltan COPILOTO_EMAIL/COPILOTO_PASSWORD.")
    r = session.post(COPILOTO_SIGNIN_URL, json={"email": email, "password": password}, timeout=45)
    if r.status_code in (401, 403):
        raise RuntimeError("Credenciales Copiloto inválidas (401/403).")
    r.raise_for_status()
    data = r.json()
    token = (data.get("data") or {}).get("token") or data.get("token") or ""
    token = str(token).strip()
    if not token:
        raise RuntimeError("No encontré token en respuesta login Copiloto (data.token).")
    return token

def download_copiloto_csv(out_path: Path) -> Path:
    s = make_session()
    token = fetch_copiloto_token(COPILOTO_EMAIL, COPILOTO_PASSWORD, session=s)
    r = s.get(COPILOTO_ENDPOINT, headers={"Authorization": f"Bearer {token}"}, timeout=90)
    r.raise_for_status()
    out_path.write_bytes(r.content)
    log.info("CSV Copiloto guardado: %s", out_path)
    return out_path

def parse_dt(x: Any) -> Optional[datetime]:
    if x is None:
        return None
    s = str(x).strip()
    if not s or s.lower() == "nan":
        return None
    # pandas parse robust
    dt = pd.to_datetime(s, errors="coerce", utc=True)
    if pd.isna(dt):
        return None
    return dt.to_pydatetime()

def save_verify_report(df: pd.DataFrame) -> Path:
    out = OUT_DIR / f"{VERIFY_REPORT_PREFIX}{run_ts_str()}.csv"
    df.to_csv(out, index=False)
    return out

# =========================
# Main
# =========================
def main():
    if not PENDING_VERIFY.exists():
        log.info("No existe pending_verify.csv (%s). Nada que verificar.", PENDING_VERIFY)
        return

    df_pending = pd.read_csv(PENDING_VERIFY)
    if df_pending.empty:
        log.info("pending_verify.csv está vacío.")
        return

    # Descarga último CSV para validar reconexión
    log.info("Descargando CSV Copiloto para verificación…")
    csv_path = download_copiloto_csv(COPILOTO_CSV_PATH)
    df_csv = pd.read_csv(csv_path)

    # Mapa IMEI -> last_update_utc actual
    df_csv["_imei"] = df_csv[CSV_COL_IMEI].astype(str).str.strip()
    df_csv["_last_seen"] = pd.to_datetime(df_csv[CSV_LASTSEEN_COL], errors="coerce", utc=True)

    last_seen_map = dict(zip(df_csv["_imei"], df_csv["_last_seen"]))

    rows_out: List[Dict[str, Any]] = []
    still_pending: List[Dict[str, Any]] = []

    now = now_utc()

    for _, r in df_pending.iterrows():
        imei = str(r.get("imei", "")).strip()
        sent_at = parse_dt(r.get("sent_at_utc"))
        last_before = parse_dt(r.get("last_seen_before_utc"))

        last_now = last_seen_map.get(imei)  # pandas Timestamp or NaT
        if last_now is pd.NaT:
            last_now = None

        # regla: reconectó si last_now > sent_at
        status = "PENDING"
        note = ""

        if sent_at and last_now is not None and pd.notna(last_now):
            last_now_dt = last_now.to_pydatetime()
            if last_now_dt > sent_at:
                status = "RECONNECTED"
                note = "last_update_utc posterior al envío"
            else:
                status = "PENDING"
                note = "sin update posterior al envío"
        else:
            status = "PENDING"
            note = "faltan timestamps (sent_at o last_update)"

        # timeout: si pasó demasiado tiempo desde el envío y no reconectó
        if status != "RECONNECTED" and sent_at:
            hours = (now - sent_at).total_seconds() / 3600.0
            if hours >= MAX_HOURS_WAIT:
                status = "NO_RECONNECT"
                note = f"superó {MAX_HOURS_WAIT}h sin reconectar"

        out_row = dict(r)
        out_row["verified_at_utc"] = now.isoformat()
        out_row["last_seen_now_utc"] = (last_now.to_pydatetime().isoformat() if last_now is not None and pd.notna(last_now) else "")
        out_row["verify_status"] = status
        out_row["verify_note"] = note
        rows_out.append(out_row)

        if status == "PENDING":
            still_pending.append(dict(r))

    df_out = pd.DataFrame(rows_out)
    report = save_verify_report(df_out)
    log.info("Verify report: %s (rows=%d)", report, len(df_out))

    # sobrescribe pending con los que siguen pendientes
    df_new_pending = pd.DataFrame(still_pending)
    df_new_pending.to_csv(PENDING_VERIFY, index=False)
    log.info("Pending actualizado: %s (rows=%d)", PENDING_VERIFY, len(df_new_pending))


if __name__ == "__main__":
    main()
