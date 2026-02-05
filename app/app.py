import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

st.set_page_config(page_title="IoT Reboots Dashboard", layout="wide")
st.title("📡 Dashboard — Reinicios IoT (Monogoto)")

# ✅ RUTAS ROBUSTAS (funciona en local y Streamlit Cloud)
BASE_DIR = Path(__file__).resolve().parent.parent   # root del repo
HIST_PATH = BASE_DIR / "out" / "historico_reincidencia.csv"

with st.expander("🧪 Debug rutas", expanded=False):
    st.write("BASE_DIR:", str(BASE_DIR))
    st.write("HIST_PATH:", str(HIST_PATH))
    st.write("Existe HIST_PATH:", HIST_PATH.exists())
    st.write("Contenido out/:", [p.name for p in (BASE_DIR / "out").glob("*")] if (BASE_DIR / "out").exists() else "No existe carpeta out/")

@st.cache_data(ttl=60)
def load_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)

    # Normalizaciones defensivas
    if "last_sent_date" in df.columns:
        df["last_sent_date"] = pd.to_datetime(df["last_sent_date"], errors="coerce")

    # asegurar numéricos
    for c in ["send_count_total", "send_count_ok", "send_count_err", "last_days_disconnected"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # strings útiles
    for c in ["empresa_last", "patente_last", "vin_last", "imei", "iccid_last"]:
        if c in df.columns:
            df[c] = df[c].astype(str)

    return df

if not HIST_PATH.exists():
    st.error(f"No encuentro el archivo: {HIST_PATH}")
    st.info(
        "Checklist rápido:\n"
        "1) ¿Existe `out/historico_reincidencia.csv` en tu repo (en GitHub, branch main)?\n"
        "2) ¿El workflow `send_daily` lo está comiteando?\n"
        "3) Si estás en local: ¿corriste `git pull` después de que Actions lo generó?\n"
    )
    st.stop()

df = load_data(HIST_PATH)

if df.empty:
    st.warning("El histórico está vacío aún.")
    st.stop()

# ==========
# Filtros
# ==========
with st.sidebar:
    st.header("Filtros")

    if "empresa_last" in df.columns:
        empresas = ["(Todas)"] + sorted(df["empresa_last"].dropna().unique().tolist())
    else:
        empresas = ["(Todas)"]

    empresa_sel = st.selectbox("Empresa", empresas)

    days_range = st.slider("Últimos días desconectado (last_days_disconnected)", 0, 60, (0, 60))
    only_reinc = st.checkbox("Solo reincidentes (send_count_total > 1)", value=False)

# aplicar filtros
df_f = df.copy()

if empresa_sel != "(Todas)" and "empresa_last" in df_f.columns:
    df_f = df_f[df_f["empresa_last"] == empresa_sel]

if "last_days_disconnected" in df_f.columns:
    df_f = df_f[df_f["last_days_disconnected"].fillna(-1).between(days_range[0], days_range[1])]

if only_reinc and "send_count_total" in df_f.columns:
    df_f = df_f[df_f["send_count_total"].fillna(0) > 1]

# ==========
# KPIs
# ==========
total_equipos = len(df_f)
total_sms = int(df_f["send_count_total"].fillna(0).sum()) if "send_count_total" in df_f.columns else 0

reincidentes = int((df_f["send_count_total"].fillna(0) > 1).sum()) if "send_count_total" in df_f.columns else 0
no_reinc = total_equipos - reincidentes

pct_reinc = (reincidentes / total_equipos * 100) if total_equipos else 0.0
pct_no_reinc = (no_reinc / total_equipos * 100) if total_equipos else 0.0

now = datetime.now()
week_start = now - timedelta(days=7)
df_week = df_f[df_f["last_sent_date"].notna() & (df_f["last_sent_date"] >= week_start)] if "last_sent_date" in df_f.columns else df_f.iloc[0:0]
reboots_week = len(df_week)

# ==========
# Layout
# ==========
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Equipos (filtro)", total_equipos)
c2.metric("SMS enviados (acum.)", total_sms)
c3.metric("Reiniciados últimos 7 días", reboots_week)
c4.metric("Equipos reincidentes", reincidentes)
c5.metric("% Reincidencia", f"{pct_reinc:.1f}%")

st.caption(f"% No reincidentes: {pct_no_reinc:.1f}%")
st.divider()

# ==========
# Gráficos
# ==========
colA, colB = st.columns(2)

with colA:
    st.subheader("Top 10 reincidentes")
    req = ["imei", "send_count_total", "send_count_ok", "send_count_err", "empresa_last", "patente_last", "vin_last", "last_sent_date"]
    if all(c in df_f.columns for c in ["send_count_total"]):
        cols = [c for c in req if c in df_f.columns]
        top = df_f.sort_values("send_count_total", ascending=False).head(10)
        st.dataframe(top[cols], use_container_width=True)
    else:
        st.info("No existe columna send_count_total en el histórico.")

with colB:
    st.subheader("Reinicios por Empresa (acumulado)")
    if "empresa_last" in df_f.columns and "send_count_total" in df_f.columns:
        agg = df_f.groupby("empresa_last", dropna=False)["send_count_total"].sum().sort_values(ascending=False).head(15)
        st.bar_chart(agg)
    else:
        st.info("Faltan columnas empresa_last y/o send_count_total.")

st.divider()

st.subheader("Detalle (tabla filtrada)")
cols_show = [c for c in [
    "imei", "iccid_last", "empresa_last", "patente_last", "vin_last",
    "send_count_total", "send_count_ok", "send_count_err",
    "last_status", "last_http_code", "last_txid", "last_days_disconnected", "last_sent_date"
] if c in df_f.columns]

if cols_show:
    st.dataframe(df_f[cols_show].sort_values("send_count_total", ascending=False), use_container_width=True)
else:
    st.info("No hay columnas esperadas para mostrar en detalle.")
