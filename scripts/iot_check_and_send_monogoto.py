import os
import time
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("send_daily")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# =========================
# Paths
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUT_DIR = BASE_DIR / "out"
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

EXCEL_PATH = Path(os.getenv("EXCEL_PATH", str(DATA_DIR / "master_status.xlsx")))
EXCEL_SHEET = os.getenv("EXCEL_SHEET", None)

COPILOTO_CSV_PATH = Path(os.getenv("COPILOTO_CSV_PATH", str(DATA_DIR / "vehicle_records.csv")))
TARGETS_PATH = Path(os.getenv("TARGETS_PATH", str(OUT_DIR / "targets_15_30.csv")))
RUN_REPORT_PREFIX = os.getenv("RUN_REPORT_PREFIX", "report_").strip()

HIST_REINCIDENCIA = Path(os.getenv("HIST_REINCIDENCIA", str(OUT_DIR / "historico_reincidencia.csv")))
PENDING_VERIFY = Path(os.getenv("PENDING_VERIFY", str(OUT_DIR / "pending_verify.csv")))

# Dedupe diario (evita mandar 2 veces mismo día al mismo IMEI)
SENT_LOG = Path(os.getenv("SENT_LOG_PATH", str(OUT_DIR / "sent_commands.csv")))

# =========================
# Ventana
# =========================
MIN_DAYS = int(os.getenv("MIN_DAYS", "15"))
MAX_DAYS = int(os.getenv("MAX_DAYS", "30"))

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

# =========================
# Monogoto
# =========================
MNG_BASE_URL = os.getenv("MNG_BASE_URL", "https://console.monogoto.io").strip()
MNG_USERNAME = os.getenv("MONOGOTO_USER", "").strip()
MNG_PASSWORD = os.getenv("MONOGOTO_PASS", "").strip()
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))
SLEEP_BETWEEN_SENDS_SEC = float(os.getenv("SLEEP_BETWEEN_SENDS_SEC", "0.25"))
TOKEN_TTL_MIN = int(os.getenv("MONOGOTO_TOKEN_TTL_MIN", "20"))
_TOKEN_CACHE = {"token": None, "exp": 0.0}

SMS_COMMAND = os.getenv(
    "SMS_COMMAND",
    "AT+GTDAT=gv300w,1,,CMD2112,0,,,,FFFF$"
).strip()

# =========================
# Master columns
# =========================
XLS_COL_VIN = os.getenv("XLS_COL_VIN", "VIN")
XLS_COL_IMEI = os.getenv("XLS_COL_IMEI", "IMEI")
XLS_COL_ACTIVO = os.getenv("XLS_COL_ACTIVO", "Activo")
XLS_COL_TEL_DISP = os.getenv("XLS_COL_TEL_DISP", "Telemetría según dispositivo")
XLS_COL_EMPRESA = os.getenv("XLS_COL_EMPRESA", "Empresa")
XLS_COL_PATENTE = os.getenv("XLS_COL_PATENTE", "Patente")
MERGE_KEY = os.getenv("MERGE_KEY", "vin").strip().lower()  # vin o imei

# =========================
# CSV columns
# =========================
CSV_COL_VIN = os.getenv("CSV_COL_VIN", "VIN")
CSV_COL_IMEI = os.getenv("CSV_COL_IMEI", "IMEI")
CSV_LASTSEEN_COL = os.getenv("CSV_LASTSEEN_COL", "last_update_utc").strip()
CSV_FILTER_SOURCE = os.getenv("CSV_FILTER_SOURCE", "COPILOTO").strip().upper()
CSV_FILTER_MODEL = os.getenv("CSV_FILTER_MODEL", "GV300W").strip().upper()

# =========================
# Helpers
# =========================
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def today_str() -> str:
    return now_utc().strftime("%Y-%m-%d")

def run_ts_str() -> str:
    return now_utc().strftime("%Y-%m-%d_%H%M%S")

def norm_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x).strip()

def make_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=5, backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.headers.update({"User-Agent": "iot-reboot-cron/1.0"})
    return s

def save_run_report(df: pd.DataFrame) -> Path:
    out = OUT_DIR / f"{RUN_REPORT_PREFIX}{run_ts_str()}.csv"
    df.to_csv(out, index=False)
    return out

def make_dedupe_key(imei: str, command: str, date_str: str) -> str:
    raw = f"{imei}|{command}|{date_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def load_csv_or_empty(path: Path, cols: List[str]) -> pd.DataFrame:
    if path.exists():
        try:
            return pd.read_csv(path)
        except Exception:
            pass
    return pd.DataFrame(columns=cols)

def append_row(path: Path, row: Dict[str, Any], cols: List[str]) -> None:
    df = load_csv_or_empty(path, cols)
    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    df.to_csv(path, index=False)

# =========================
# Copiloto
# =========================
def fetch_copiloto_token(email: str, password: str) -> str:
    if not email or not password:
        raise RuntimeError("Faltan COPILOTO_EMAIL/COPILOTO_PASSWORD.")

    sess = make_session()
    r = sess.post(COPILOTO_SIGNIN_URL, json={"email": email, "password": password}, timeout=45)
    if r.status_code in (401, 403):
        raise RuntimeError("Credenciales Copiloto inválidas (401/403).")
    r.raise_for_status()
    data = r.json()
    token = (
        data.get("accessToken") or data.get("access_token") or data.get("token")
        or (data.get("data") or {}).get("token")
        or (data.get("data") or {}).get("accessToken")
        or ""
    )
    if not token:
        raise RuntimeError("No encontré token en respuesta login Copiloto.")
    return token.strip()

def download_copiloto_csv(out_path: Path) -> Path:
    sess = make_session()
    token = fetch_copiloto_token(COPILOTO_EMAIL, COPILOTO_PASSWORD)
    r = sess.get(COPILOTO_ENDPOINT, headers={"Authorization": f"Bearer {token}"}, timeout=90)
    r.raise_for_status()
    out_path.write_bytes(r.content)
    log.info("CSV Copiloto guardado: %s", out_path)
    return out_path

def compute_days_disconnected(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["_last_seen"] = pd.to_datetime(out[CSV_LASTSEEN_COL], errors="coerce", utc=True)
    out["days_disconnected"] = ((now_utc() - out["_last_seen"]).dt.total_seconds() / 86400.0).round(0)
    return out

# =========================
# Monogoto
# =========================
def login_get_token() -> str:
    url = f"{MNG_BASE_URL.rstrip('/')}/Auth"
    payload = {"UserName": MNG_USERNAME, "Password": MNG_PASSWORD}
    r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Login Monogoto falló ({r.status_code}): {r.text}")
    data = r.json()
    token = data.get("token") or data.get("Token")
    if not token:
        raise RuntimeError("Login Monogoto sin token.")
    return token

def get_token_cached() -> str:
    now = time.time()
    if _TOKEN_CACHE["token"] and now < _TOKEN_CACHE["exp"]:
        return _TOKEN_CACHE["token"]
    if not MNG_USERNAME or not MNG_PASSWORD:
        raise RuntimeError("Faltan MONOGOTO_USER / MONOGOTO_PASS.")
    token = login_get_token()
    _TOKEN_CACHE["token"] = token
    _TOKEN_CACHE["exp"] = now + TOKEN_TTL_MIN * 60
    return token

def get_iccid_by_imei(token: str, imei: str, session: requests.Session) -> Optional[str]:
    url = f"{MNG_BASE_URL.rstrip('/')}/things"
    params = {"filterBy[IMEI]": imei.strip(), "limit": 1}
    headers = {"Authorization": f"Bearer {token}", "accept": "application/json"}
    r = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"GET /things error ({r.status_code}): {r.text}")
    items = r.json()
    if not isinstance(items, list) or not items:
        return None
    return items[0].get("ExternalUniqueId") or items[0].get("ICCID")

def send_sms_to_iccid(token: str, iccid: str, message: str, session: requests.Session) -> Tuple[bool, int, str]:
    url = f"{MNG_BASE_URL.rstrip('/')}/thing/ThingId_ICCID_{iccid}/sms"
    headers = {"Authorization": f"Bearer {token}", "accept": "application/json", "Content-Type": "application/json"}
    payload = {"Message": message, "From": "console"}
    r = session.post(url, headers=headers, json=payload, timeout=HTTP_TIMEOUT)
    ok = r.status_code in (200, 201, 202)
    return ok, r.status_code, (r.text or "").strip()

# =========================
# Reincidencia (upsert)
# =========================
REINC_COLS = [
    "imei",
    "first_sent_date",
    "last_sent_date",
    "send_count_total",
    "send_count_ok",
    "send_count_err",
    "last_status",
    "last_http_code",
    "last_txid",
    "last_command",
    "last_days_disconnected",
    "vin_last",
    "empresa_last",
    "patente_last",
    "iccid_last",
]

def update_reincidencia(hist_path: Path, rows_sent: List[Dict[str, Any]]) -> None:
    df_hist = load_csv_or_empty(hist_path, REINC_COLS)
    if df_hist.empty:
        df_hist = pd.DataFrame(columns=REINC_COLS)

    df_new = pd.DataFrame(rows_sent)
    if df_new.empty:
        df_hist.to_csv(hist_path, index=False)
        return

    # asegurar columnas
    for c in REINC_COLS:
        if c not in df_new.columns:
            df_new[c] = ""

    df_hist["imei"] = df_hist["imei"].astype(str)
    df_new["imei"] = df_new["imei"].astype(str)

    df_hist = df_hist.set_index("imei", drop=False)

    for _, r in df_new.iterrows():
        imei = str(r["imei"])
        today = r.get("last_sent_date") or today_str()

        if imei not in df_hist.index:
            df_hist.loc[imei, :] = {
                "imei": imei,
                "first_sent_date": today,
                "last_sent_date": today,
                "send_count_total": 0,
                "send_count_ok": 0,
                "send_count_err": 0,
                "last_status": "",
                "last_http_code": "",
                "last_txid": "",
                "last_command": "",
                "last_days_disconnected": "",
                "vin_last": "",
                "empresa_last": "",
                "patente_last": "",
                "iccid_last": "",
            }

        # incrementos
        df_hist.loc[imei, "last_sent_date"] = today
        df_hist.loc[imei, "send_count_total"] = int(df_hist.loc[imei, "send_count_total"]) + 1

        status = str(r.get("last_status", ""))
        if status == "OK":
            df_hist.loc[imei, "send_count_ok"] = int(df_hist.loc[imei, "send_count_ok"]) + 1
        else:
            df_hist.loc[imei, "send_count_err"] = int(df_hist.loc[imei, "send_count_err"]) + 1

        # últimos valores
        df_hist.loc[imei, "last_status"] = status
        df_hist.loc[imei, "last_http_code"] = r.get("last_http_code", "")
        df_hist.loc[imei, "last_txid"] = r.get("last_txid", "")
        df_hist.loc[imei, "last_command"] = r.get("last_command", "")
        df_hist.loc[imei, "last_days_disconnected"] = r.get("last_days_disconnected", "")
        df_hist.loc[imei, "vin_last"] = r.get("vin_last", "")
        df_hist.loc[imei, "empresa_last"] = r.get("empresa_last", "")
        df_hist.loc[imei, "patente_last"] = r.get("patente_last", "")
        df_hist.loc[imei, "iccid_last"] = r.get("iccid_last", "")

    df_hist = df_hist.reset_index(drop=True)
    df_hist.to_csv(hist_path, index=False)

# =========================
# Main
# =========================
def main():
    if not COPILOTO_EMAIL or not COPILOTO_PASSWORD:
        raise RuntimeError("Faltan COPILOTO_EMAIL / COPILOTO_PASSWORD.")
    if not MNG_USERNAME or not MNG_PASSWORD:
        raise RuntimeError("Faltan MONOGOTO_USER / MONOGOTO_PASS.")

    log.info("SMS_COMMAND: %s", SMS_COMMAND)

    # 1) Master
    df_master = pd.read_excel(EXCEL_PATH, sheet_name=EXCEL_SHEET)
    if isinstance(df_master, dict):
        first = next(iter(df_master))
        log.info("Excel con múltiples hojas, usando: %s", first)
        df_master = df_master[first]

    activo_raw = df_master[XLS_COL_ACTIVO].astype(str).str.strip().str.lower()
    df_master["_activo_bool"] = activo_raw.isin(["true", "verdadero", "1", "yes", "y"])
    tel_raw = df_master[XLS_COL_TEL_DISP].astype(str).str.strip().str.lower()
    df_master["_telemetria_disp"] = tel_raw.isin(["telemetría", "telemetria"])

    before_master = len(df_master)
    df_master = df_master[df_master["_activo_bool"] & df_master["_telemetria_disp"]].copy()
    log.info("Master filtrado: %d -> %d", before_master, len(df_master))

    if MERGE_KEY not in ("vin", "imei"):
        raise ValueError("MERGE_KEY debe ser 'vin' o 'imei'.")

    df_master["_key"] = (df_master[XLS_COL_VIN] if MERGE_KEY == "vin" else df_master[XLS_COL_IMEI]).astype(str).str.strip()
    df_master = df_master[df_master["_key"].str.lower().ne("nan") & df_master["_key"].ne("")].copy()

    # 2) CSV Copiloto
    log.info("Descargando CSV Copiloto…")
    csv_path = download_copiloto_csv(COPILOTO_CSV_PATH)
    df_csv = pd.read_csv(csv_path)

    df_csv = df_csv[
        df_csv["source"].astype(str).str.strip().str.upper().eq(CSV_FILTER_SOURCE) &
        df_csv["device_model"].astype(str).str.strip().str.upper().eq(CSV_FILTER_MODEL)
    ].copy()
    log.info("CSV filtrado: %d", len(df_csv))
    if df_csv.empty:
        log.info("CSV vacío tras filtros.")
        return

    df_csv = compute_days_disconnected(df_csv)
    df_csv["days_disconnected"] = pd.to_numeric(df_csv["days_disconnected"], errors="coerce")

    df_csv["_key"] = (df_csv[CSV_COL_VIN] if MERGE_KEY == "vin" else df_csv[CSV_COL_IMEI]).astype(str).str.strip()
    df_csv = df_csv[df_csv["_key"].str.lower().ne("nan") & df_csv["_key"].ne("")].copy()

    df_targets = df_csv[(df_csv["days_disconnected"] >= MIN_DAYS) & (df_csv["days_disconnected"] <= MAX_DAYS)].copy()
    if df_targets.empty:
        log.info("No hay targets %d..%d.", MIN_DAYS, MAX_DAYS)
        return

    df_targets = df_targets.merge(
        df_master[["_key", XLS_COL_EMPRESA, XLS_COL_PATENTE]].drop_duplicates("_key"),
        on="_key",
        how="inner"
    )
    log.info("Targets tras cruce: %d", len(df_targets))
    if df_targets.empty:
        return

    df_targets.to_csv(TARGETS_PATH, index=False)
    log.info("Targets guardados: %s", TARGETS_PATH)

    # IMEI del CSV
    df_targets["_imei_send"] = df_targets[CSV_COL_IMEI].astype(str).str.strip()
    df_targets = df_targets[df_targets["_imei_send"].str.lower().ne("nan") & df_targets["_imei_send"].ne("")].copy()
    if df_targets.empty:
        return

    # dedupe diario
    sent_cols = ["date", "imei", "iccid", "command", "dedupe_key", "status", "http_code", "txid", "note"]
    df_sentlog = load_csv_or_empty(SENT_LOG, sent_cols)
    date_str = today_str()

    session = make_session()
    token = get_token_cached()
    log.info("Monogoto token OK. Envío ACTIVADO.")

    run_rows = []
    reinc_rows = []
    pending_rows = []

    for _, r in df_targets.iterrows():
        imei = norm_str(r.get("_imei_send"))
        vin = norm_str(r.get(CSV_COL_VIN))
        empresa = norm_str(r.get(XLS_COL_EMPRESA))
        patente = norm_str(r.get(XLS_COL_PATENTE))
        days = r.get("days_disconnected")

        dkey = make_dedupe_key(imei, SMS_COMMAND, date_str)
        already = (df_sentlog["dedupe_key"] == dkey).any() if not df_sentlog.empty else False
        if already:
            continue

        iccid = get_iccid_by_imei(token, imei, session=session)
        if not iccid:
            # registra intento fallido (sin iccid)
            run_rows.append({
                "run_ts_utc": run_ts_str(), "date": date_str,
                "imei": imei, "iccid": "", "vin": vin,
                "empresa": empresa, "patente": patente,
                "days_disconnected": days, "command": SMS_COMMAND,
                "status": "NOT_FOUND_ICCID", "http_code": 404, "txid": "", "note": "ICCID no encontrado"
            })
            reinc_rows.append({
                "imei": imei,
                "first_sent_date": "",
                "last_sent_date": date_str,
                "send_count_total": 1,
                "send_count_ok": 0,
                "send_count_err": 1,
                "last_status": "ERR",
                "last_http_code": 404,
                "last_txid": "",
                "last_command": SMS_COMMAND,
                "last_days_disconnected": days,
                "vin_last": vin,
                "empresa_last": empresa,
                "patente_last": patente,
                "iccid_last": "",
            })
            time.sleep(SLEEP_BETWEEN_SENDS_SEC)
            continue

        ok, code, resp_text = send_sms_to_iccid(token, iccid, SMS_COMMAND, session=session)
        status = "OK" if ok else "ERR"
        txid = resp_text.strip()

        # guardar sentlog
        append_row(SENT_LOG, {
            "date": date_str, "imei": imei, "iccid": iccid,
            "command": SMS_COMMAND, "dedupe_key": dkey,
            "status": status, "http_code": code, "txid": txid, "note": resp_text[:500]
        }, sent_cols)

        run_rows.append({
            "run_ts_utc": run_ts_str(), "date": date_str,
            "imei": imei, "iccid": iccid, "vin": vin,
            "empresa": empresa, "patente": patente,
            "days_disconnected": days, "command": SMS_COMMAND,
            "status": status, "http_code": code, "txid": txid, "note": resp_text[:500]
        })

        # update reincidencia (solo 1 fila por IMEI)
        reinc_rows.append({
            "imei": imei,
            "last_sent_date": date_str,
            "last_status": status,
            "last_http_code": code,
            "last_txid": txid,
            "last_command": SMS_COMMAND,
            "last_days_disconnected": days,
            "vin_last": vin,
            "empresa_last": empresa,
            "patente_last": patente,
            "iccid_last": iccid,
        })

        # pending verify: guarda para validar después (job hourly)
        pending_rows.append({
            "date": date_str,
            "run_ts_utc": run_ts_str(),
            "imei": imei,
            "iccid": iccid,
            "txid": txid,
            "command": SMS_COMMAND,
        })

        time.sleep(SLEEP_BETWEEN_SENDS_SEC)

    df_run = pd.DataFrame(run_rows)
    report_path = save_run_report(df_run)
    log.info("Reporte del run: %s (rows=%d)", report_path, len(df_run))

    # actualizar reincidencia
    update_reincidencia(HIST_REINCIDENCIA, reinc_rows)
    log.info("Reincidencia actualizada: %s", HIST_REINCIDENCIA)

    # guardar pending_verify (se sobreescribe cada día, y el verificador puede ir consumiendo)
    df_pending = pd.DataFrame(pending_rows)
    df_pending.to_csv(PENDING_VERIFY, index=False)
    log.info("Pending verify guardado: %s (rows=%d)", PENDING_VERIFY, len(df_pending))


if __name__ == "__main__":
    main()
