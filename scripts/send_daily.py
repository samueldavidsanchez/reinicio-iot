# -*- coding: utf-8 -*-
import os
import time
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

from zoneinfo import ZoneInfo

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("send_daily")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# =========================
# TZ Chile (para dedupe 2x/día y fecha local)
# =========================
TZ_CL = ZoneInfo("America/Santiago")

def now_cl() -> datetime:
    return datetime.now(TZ_CL)

def today_str_cl() -> str:
    return now_cl().strftime("%Y-%m-%d")

def slot_str_cl() -> str:
    """
    Slot del día para permitir 2 envíos diarios.
    - AM: antes de 15:00 hora Chile
    - PM: desde 15:00 hora Chile
    (Tus cron ~12:00 y ~18:00 caen en slots distintos)
    """
    h = now_cl().hour
    return "AM" if h < 15 else "PM"

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def run_ts_str() -> str:
    return now_utc().strftime("%Y-%m-%d_%H%M%S")

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

# Dedupe diario (evita mandar 2 veces en el mismo slot al mismo IMEI)
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

COPILOTO_API_BASE = os.getenv("COPILOTO_API_BASE", "https://api.copiloto.ai").strip().rstrip("/")
COPILOTO_COMMAND_ENDPOINT_TMPL = os.getenv("COPILOTO_COMMAND_ENDPOINT_TMPL", "/command/{imei}").strip()

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))
SLEEP_BETWEEN_SENDS_SEC = float(os.getenv("SLEEP_BETWEEN_SENDS_SEC", "0.25"))

API_COMMAND = os.getenv(
    "COPILOTO_COMMAND_TEMPLATE",
    "AT+GTDAT=gv300w,1,,CMD97,0,,,,FFFF$"
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
# Generic helpers
# =========================
def norm_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x).strip()

def is_valid_imei(x: str) -> bool:
    s = (x or "").strip()
    return s.isdigit() and 14 <= len(s) <= 17

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
    s.headers.update({"User-Agent": "iot-reboot-cron/2.0"})
    return s

def save_run_report(df: pd.DataFrame) -> Path:
    out = OUT_DIR / f"{RUN_REPORT_PREFIX}{run_ts_str()}.csv"
    df.to_csv(out, index=False)
    return out

def make_dedupe_key(imei: str, command: str, date_slot: str) -> str:
    raw = f"{imei}|{command}|{date_slot}"
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
    sess = make_session()
    token = fetch_copiloto_token(COPILOTO_EMAIL, COPILOTO_PASSWORD, session=sess)
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

def build_command_url(imei: str) -> str:
    return f"{COPILOTO_API_BASE}{COPILOTO_COMMAND_ENDPOINT_TMPL.format(imei=imei)}"

def send_command_to_imei(token: str, imei: str, command: str, session: requests.Session) -> Tuple[bool, int, str]:
    url = build_command_url(imei)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {"command": command}
    r = session.post(url, headers=headers, json=payload, timeout=HTTP_TIMEOUT)
    ok = r.status_code in (200, 201, 202)
    text = (r.text or "").strip()
    return ok, r.status_code, text[:2000]

# =========================
# Reincidencia (upsert) - FIX dtype
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
]

def _to_int(x: Any) -> int:
    try:
        if x is None:
            return 0
        s = str(x).strip()
        if s == "" or s.lower() == "nan":
            return 0
        return int(float(s))
    except Exception:
        return 0

def update_reincidencia(hist_path: Path, rows_sent: List[Dict[str, Any]]) -> None:
    df_hist = load_csv_or_empty(hist_path, REINC_COLS)
    if df_hist.empty:
        df_hist = pd.DataFrame(columns=REINC_COLS)

    df_new = pd.DataFrame(rows_sent)
    if df_new.empty:
        df_hist.to_csv(hist_path, index=False)
        return

    for c in REINC_COLS:
        if c not in df_hist.columns:
            df_hist[c] = ""
        if c not in df_new.columns:
            df_new[c] = ""

    # fuerza a texto (evita float64 vs "")
    df_hist = df_hist.astype("string")
    df_new = df_new.astype("string")

    df_hist["imei"] = df_hist["imei"].fillna("").astype("string")
    df_new["imei"] = df_new["imei"].fillna("").astype("string")

    df_hist = df_hist.set_index("imei", drop=False)

    for _, r in df_new.iterrows():
        imei = str(r.get("imei", "")).strip()
        if not imei:
            continue

        today = str(r.get("last_sent_date") or today_str_cl())

        if imei not in df_hist.index:
            df_hist.loc[imei, :] = {
                "imei": imei,
                "first_sent_date": today,
                "last_sent_date": today,
                "send_count_total": "0",
                "send_count_ok": "0",
                "send_count_err": "0",
                "last_status": "",
                "last_http_code": "",
                "last_txid": "",
                "last_command": "",
                "last_days_disconnected": "",
                "vin_last": "",
                "empresa_last": "",
                "patente_last": "",
            }

        df_hist.loc[imei, "last_sent_date"] = today
        df_hist.loc[imei, "send_count_total"] = str(_to_int(df_hist.loc[imei, "send_count_total"]) + 1)

        status = str(r.get("last_status", "") or "")
        if status == "OK":
            df_hist.loc[imei, "send_count_ok"] = str(_to_int(df_hist.loc[imei, "send_count_ok"]) + 1)
        else:
            df_hist.loc[imei, "send_count_err"] = str(_to_int(df_hist.loc[imei, "send_count_err"]) + 1)

        df_hist.loc[imei, "last_status"] = status
        df_hist.loc[imei, "last_http_code"] = str(r.get("last_http_code", "") or "")
        df_hist.loc[imei, "last_txid"] = str(r.get("last_txid", "") or "")
        df_hist.loc[imei, "last_command"] = str(r.get("last_command", "") or "")
        df_hist.loc[imei, "last_days_disconnected"] = str(r.get("last_days_disconnected", "") or "")
        df_hist.loc[imei, "vin_last"] = str(r.get("vin_last", "") or "")
        df_hist.loc[imei, "empresa_last"] = str(r.get("empresa_last", "") or "")
        df_hist.loc[imei, "patente_last"] = str(r.get("patente_last", "") or "")

    df_hist = df_hist.reset_index(drop=True)
    df_hist.to_csv(hist_path, index=False)

# =========================
# Main
# =========================
def main():
    if not COPILOTO_EMAIL or not COPILOTO_PASSWORD:
        raise RuntimeError("Faltan COPILOTO_EMAIL / COPILOTO_PASSWORD.")

    date_str = today_str_cl()
    slot = slot_str_cl()

    log.info("API_COMMAND: %s", API_COMMAND)
    log.info("Run date (CL): %s | slot: %s", date_str, slot)

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
    df_targets = df_targets[df_targets["_imei_send"].apply(is_valid_imei)].copy()
    if df_targets.empty:
        log.info("Targets sin IMEI válido.")
        return

    # dedupe por slot (AM/PM CL)
    sent_cols = ["date", "slot", "imei", "command", "dedupe_key", "status", "http_code", "txid", "note"]
    df_sentlog = load_csv_or_empty(SENT_LOG, sent_cols)

    session = make_session()
    copiloto_token = fetch_copiloto_token(COPILOTO_EMAIL, COPILOTO_PASSWORD, session=session)
    log.info("Copiloto token OK. Envío ACTIVADO.")

    run_rows = []
    reinc_rows = []
    pending_rows = []

    for _, r in df_targets.iterrows():
        imei = norm_str(r.get("_imei_send"))
        vin = norm_str(r.get(CSV_COL_VIN))
        empresa = norm_str(r.get(XLS_COL_EMPRESA))
        patente = norm_str(r.get(XLS_COL_PATENTE))
        days = r.get("days_disconnected")
        last_seen_before = norm_str(r.get(CSV_LASTSEEN_COL))

        # ✅ Dedupe por día+slot Chile
        dkey = make_dedupe_key(imei, API_COMMAND, f"{date_str}-{slot}")
        already = (df_sentlog["dedupe_key"] == dkey).any() if not df_sentlog.empty else False
        if already:
            continue

        ok, code, resp_text = send_command_to_imei(copiloto_token, imei, API_COMMAND, session=session)
        status = "OK" if ok else "ERR"
        txid = resp_text.strip()

        append_row(SENT_LOG, {
            "date": date_str,
            "slot": slot,
            "imei": imei,
            "command": API_COMMAND,
            "dedupe_key": dkey,
            "status": status,
            "http_code": code,
            "txid": txid[:500],
            "note": resp_text[:500],
        }, sent_cols)

        run_rows.append({
            "run_ts_utc": run_ts_str(),
            "date": date_str,
            "slot": slot,
            "imei": imei,
            "vin": vin,
            "empresa": empresa,
            "patente": patente,
            "days_disconnected": days,
            "last_seen_before_utc": last_seen_before,
            "command": API_COMMAND,
            "status": status,
            "http_code": code,
            "txid": txid[:500],
            "note": resp_text[:500],
        })

        reinc_rows.append({
            "imei": imei,
            "last_sent_date": date_str,
            "last_status": status,
            "last_http_code": code,
            "last_txid": txid[:500],
            "last_command": API_COMMAND,
            "last_days_disconnected": days,
            "vin_last": vin,
            "empresa_last": empresa,
            "patente_last": patente,
        })

        pending_rows.append({
            "date": date_str,
            "slot": slot,
            "run_ts_utc": run_ts_str(),
            "imei": imei,
            "sent_at_utc": now_utc().isoformat(),
            "last_seen_before_utc": last_seen_before,
            "days_disconnected_at_send": days,
            "vin": vin,
            "empresa": empresa,
            "patente": patente,
            "command": API_COMMAND,
        })

        time.sleep(SLEEP_BETWEEN_SENDS_SEC)

    df_run = pd.DataFrame(run_rows)
    report_path = save_run_report(df_run)
    log.info("Reporte del run: %s (rows=%d)", report_path, len(df_run))

    update_reincidencia(HIST_REINCIDENCIA, reinc_rows)
    log.info("Reincidencia actualizada: %s", HIST_REINCIDENCIA)

    df_pending = pd.DataFrame(pending_rows)
    df_pending.to_csv(PENDING_VERIFY, index=False)
    log.info("Pending verify guardado: %s (rows=%d)", PENDING_VERIFY, len(df_pending))


if __name__ == "__main__":
    main()
