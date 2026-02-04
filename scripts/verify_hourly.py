import os
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Tuple, Optional

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("verify_hourly")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = Path(__file__).resolve().parent.parent
OUT_DIR = BASE_DIR / "out"
OUT_DIR.mkdir(parents=True, exist_ok=True)

PENDING_VERIFY = Path(os.getenv("PENDING_VERIFY", str(OUT_DIR / "pending_verify.csv")))
HIST_REINCIDENCIA = Path(os.getenv("HIST_REINCIDENCIA", str(OUT_DIR / "historico_reincidencia.csv")))

MNG_BASE_URL = os.getenv("MNG_BASE_URL", "https://console.monogoto.io").strip()
MNG_USERNAME = os.getenv("MONOGOTO_USER", "").strip()
MNG_PASSWORD = os.getenv("MONOGOTO_PASS", "").strip()
MONOGOTO_APIKEY = os.getenv("MONOGOTO_APIKEY", "").strip()

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))
TOKEN_TTL_MIN = int(os.getenv("MONOGOTO_TOKEN_TTL_MIN", "20"))
_TOKEN_CACHE = {"token": None, "exp": 0.0}

VERIFY_WINDOW_MIN = int(os.getenv("VERIFY_WINDOW_MIN", "180"))  # 3 horas hacia atrás
VERIFY_LIMIT = int(os.getenv("VERIFY_LIMIT", "15"))

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def to_elk_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def make_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=0.8, status_forcelist=(429,500,502,503,504), allowed_methods=("GET","POST"))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.headers.update({"User-Agent": "iot-reboot-verify/1.0"})
    return s

def login_get_token() -> str:
    url = f"{MNG_BASE_URL.rstrip('/')}/Auth"
    payload = {"UserName": MNG_USERNAME, "Password": MNG_PASSWORD}
    r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"Login Monogoto falló ({r.status_code}): {r.text}")
    data = r.json()
    token = data.get("token") or data.get("Token")
    if not token:
        raise RuntimeError("Login sin token.")
    return token

def get_token_cached() -> str:
    now = time.time()
    if _TOKEN_CACHE["token"] and now < _TOKEN_CACHE["exp"]:
        return _TOKEN_CACHE["token"]
    token = login_get_token()
    _TOKEN_CACHE["token"] = token
    _TOKEN_CACHE["exp"] = now + TOKEN_TTL_MIN * 60
    return token

def check_mt_sms_received(session: requests.Session, token: str, iccid: str, txid: str) -> Tuple[str, str]:
    """
    SUCCESS / FAILURE / PENDING / CHECK_ERROR
    """
    if not MONOGOTO_APIKEY:
        return "CHECK_ERROR", "MONOGOTO_APIKEY faltante"

    url = f"{MNG_BASE_URL.rstrip('/')}/thing/searchCDR"
    headers = {
        "Authorization": f"Bearer {token}",
        "apikey": MONOGOTO_APIKEY,
        "accept": "application/json",
        "Content-Type": "application/json",
    }

    end = now_utc()
    start = end - timedelta(minutes=VERIFY_WINDOW_MIN)

    payload = {
        "ThingIdELK": f"ThingId_ICCID_{iccid}",
        "EsDataTypeELK": "MT_SMS",
        "MessageTypeELK": "CDR",
        "gteTimestampELK": to_elk_ts(start),
        "ltTimestampELK": to_elk_ts(end),
        "limit": str(VERIFY_LIMIT),
    }

    r = session.post(url, headers=headers, json=payload, timeout=HTTP_TIMEOUT)
    if r.status_code != 200:
        return "CHECK_ERROR", f"searchCDR http={r.status_code}: {r.text[:200]}"

    try:
        data = r.json()
    except Exception:
        return "CHECK_ERROR", f"searchCDR no-JSON: {r.text[:200]}"

    items = data if isinstance(data, list) else data.get("items") or data.get("data") or []
    if not isinstance(items, list) or not items:
        return "PENDING", "sin eventos"

    txid = (txid or "").strip()
    for ev in items:
        msg = str(ev.get("message") or ev.get("Message") or "")
        if txid and txid in msg:
            mlow = msg.lower()
            if "success" in mlow:
                return "SUCCESS", msg[:300]
            if "failure" in mlow:
                return "FAILURE", msg[:300]
            return "PENDING", msg[:300]

    return "PENDING", "no aparece txId aún"

def main():
    if not PENDING_VERIFY.exists():
        log.info("No existe pending_verify.csv, nada que verificar.")
        return
    if not HIST_REINCIDENCIA.exists():
        log.info("No existe historico_reincidencia.csv, nada que actualizar.")
        return
    if not MNG_USERNAME or not MNG_PASSWORD:
        raise RuntimeError("Faltan MONOGOTO_USER / MONOGOTO_PASS.")
    if not MONOGOTO_APIKEY:
        raise RuntimeError("Falta MONOGOTO_APIKEY (customer id) para searchCDR.")

    df_pending = pd.read_csv(PENDING_VERIFY)
    if df_pending.empty:
        log.info("pending_verify.csv vacío.")
        return

    df_hist = pd.read_csv(HIST_REINCIDENCIA)
    # agregamos columnas de delivery si no existen
    for col in ["delivery_status", "delivery_note", "delivery_checked_at_utc"]:
        if col not in df_hist.columns:
            df_hist[col] = ""

    session = make_session()
    token = get_token_cached()
    log.info("Token OK. Verificando %d envíos pendientes…", len(df_pending))

    checked_at = to_elk_ts(now_utc())

    for _, r in df_pending.iterrows():
        imei = str(r.get("imei", "")).strip()
        iccid = str(r.get("iccid", "")).strip()
        txid = str(r.get("txid", "")).strip()
        if not imei or not iccid or not txid:
            continue

        st, note = check_mt_sms_received(session, token, iccid, txid)

        # actualizar fila por IMEI
        m = df_hist["imei"].astype(str) == imei
        if m.any():
            df_hist.loc[m, "delivery_status"] = st
            df_hist.loc[m, "delivery_note"] = note
            df_hist.loc[m, "delivery_checked_at_utc"] = checked_at

    df_hist.to_csv(HIST_REINCIDENCIA, index=False)
    log.info("Histórico actualizado con delivery: %s", HIST_REINCIDENCIA)


if __name__ == "__main__":
    main()
