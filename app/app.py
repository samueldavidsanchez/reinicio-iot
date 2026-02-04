import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="IoT Reboots Dashboard", layout="wide")
st.title("📡 Dashboard — Reinicios IoT (Monogoto)")

HIST_PATH = "out/historico_reincidencia.csv"

@st.cache_data(ttl=60)
def load_data():
    df = pd.read_csv(HIST_PATH)
    # Normalizaciones defensivas
    if "last_sent_date" in df.columns:
        df["last_sent_date"] = pd.to_datetime(df["last_sent_date"], errors="coerce")
    # asegurar numéricos
    for c in ["send_count_total", "send_count_ok", "send_count_err", "last_days_disconnected"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

try:
    df = load_data()
except FileNotFoundError:
    st.error(f"No encuentro el archivo: {HIST_PATH}. Ejecuta primero el job de envío para generarlo.")
    st.stop()

if df.empty:
    st.warning("El histórico está vacío aún.")
    st.stop()

# ==========
# Filtros
# ==========
with st.sidebar:
    st.header("Filtros")
    empresas = ["(Todas)"] + sorted([e for e in df.get("empresa_last", pd.Series([])).dropna().unique()])
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

# semana (últimos 7 días por last_sent_date)
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
    if "send_count_total" in df_f.columns:
        top = df_f.sort_values("send_count_total", ascending=False).head(10)
        st.dataframe(
            top[["imei", "send_count_total", "send_count_ok", "send_count_err", "empresa_last", "patente_last", "vin_last", "last_sent_date"]],
            use_container_width=True
        )
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

st.dataframe(df_f[cols_show].sort_values("send_count_total", ascending=False), use_container_width=True)
