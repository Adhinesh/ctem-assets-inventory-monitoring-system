"""
========================================================
dashboard.py
=======================================================
Run Streamlit :

streamlit run dashboard.py
"""
import streamlit as st
import pandas as pd
import requests

API = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="CTEM Dashboard",
    layout="wide"
)

st.title(" 🛡️ CTEM Asset Monitoring Dashboard")


# -------------------------------
# Helper
# -------------------------------

def get(url):
    try:
        return requests.get(API + url).json()
    except:
        return {}


# -------------------------------
# Load Data
# -------------------------------

dashboard = get("/dashboard/summary")
assets = get("/assets")
alerts = get("/alerts/changes")
vulns = get("/vulnerabilities")
ports = get("/ports")
dns = get("/dns")
exposures = get("/exposures")
scans = get("/scans")
monitor = get("/monitor/latest")


# ------------------------------------------------
# TOP METRICS
# ------------------------------------------------

col1,col2,col3,col4 = st.columns(4)

total_assets = dashboard["assets"]["total"]

new_assets = len([
    x for x in alerts["data"]
    if x["change_type"]=="asset_added"
])

removed_assets = len([
    x for x in alerts["data"]
    if x["change_type"]=="asset_removed"
])

total_alerts = alerts["total"]


col1.metric("Total Assets",total_assets)
col2.metric("New Assets",new_assets)
col3.metric("Removed Assets",removed_assets)
col4.metric("Alerts",total_alerts)


st.divider()


# ------------------------------------------------
# ASSET CHARTS
# ------------------------------------------------

c1,c2 = st.columns(2)

with c1:

    st.subheader("Assets by Criticality")

    criticality = dashboard["assets"]["by_criticality"]

    df = pd.DataFrame({
        "Criticality":criticality.keys(),
        "Count":criticality.values()
    })

    st.bar_chart(df.set_index("Criticality"))


with c2:

    st.subheader("Assets by Status")

    status = dashboard["assets"]["by_status"]

    df = pd.DataFrame({
        "Status":status.keys(),
        "Count":status.values()
    })

    st.bar_chart(df.set_index("Status"))


st.divider()



# ------------------------------------------------
# VULNERABILITIES
# ------------------------------------------------

st.subheader("Latest Vulnerabilities")

if vulns["data"]:
    df = pd.DataFrame(vulns["data"])
    st.dataframe(df,use_container_width=True)


st.divider()



# ------------------------------------------------
# EXPOSURES
# ------------------------------------------------

st.subheader("Top Risk Exposures")

if exposures["data"]:
    df = pd.DataFrame(exposures["data"])
    st.dataframe(df,use_container_width=True)


st.divider()



# ------------------------------------------------
# ALERTS
# ------------------------------------------------

st.subheader("Recent Alerts")

rows=[]

for item in alerts["data"]:

    asset=item.get("assets",{})

    rows.append({

        "Time":item["changed_at"],
        "Asset":asset.get("asset_name"),
        "IP":asset.get("ip_address"),
        "Criticality":asset.get("criticality"),
        "Type":item["change_type"],
        "Reason":item["change_reason"]

    })


df=pd.DataFrame(rows)

st.dataframe(df,use_container_width=True)


st.divider()



# ------------------------------------------------
# NEWLY ADDED ASSETS
# ------------------------------------------------

st.subheader("Newly Added Assets")

added_assets = []


for item in alerts["data"]:

    if item["change_type"] == "asset_added":

        asset = item.get("assets",{})

        added_assets.append({

            "Time": item["changed_at"],
            "Asset": asset.get("asset_name"),
            "IP": asset.get("ip_address"),
            "Criticality": asset.get("criticality"),
            "Reason": item["change_reason"]

        })


if added_assets:

    df = pd.DataFrame(added_assets)

    st.dataframe(df,use_container_width=True)

else:

    st.info("No new assets found")


st.divider()



# ------------------------------------------------
# REMOVED ASSETS
# ------------------------------------------------

st.subheader("Removed Assets")

removed_assets_list = []


for item in alerts["data"]:

    if item["change_type"] == "asset_removed":

        asset = item.get("assets",{})

        removed_assets_list.append({

            "Time": item["changed_at"],
            "Asset": asset.get("asset_name"),
            "IP": asset.get("ip_address"),
            "Criticality": asset.get("criticality"),
            "Reason": item["change_reason"]

        })


if removed_assets_list:

    df = pd.DataFrame(removed_assets_list)

    st.dataframe(df,use_container_width=True)

else:

    st.info("No removed assets found")


st.divider()



# ------------------------------------------------
# PORTS
# ------------------------------------------------

st.subheader("Open Ports")

if ports["data"]:

    df=pd.DataFrame(ports["data"])

    st.dataframe(df,use_container_width=True)


st.divider()



# ------------------------------------------------
# DNS
# ------------------------------------------------

st.subheader("DNS Records")

if dns["data"]:

    df=pd.DataFrame(dns["data"])

    st.dataframe(df,use_container_width=True)


st.divider()



# ------------------------------------------------
# SCANS
# ------------------------------------------------

st.subheader("Scan History")

if scans["data"]:

    df=pd.DataFrame(scans["data"])

    st.dataframe(df,use_container_width=True)


st.divider()



# ------------------------------------------------
# MONITOR
# ------------------------------------------------

st.subheader("Latest Monitoring Run")

st.json(monitor)