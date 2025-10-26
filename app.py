from flask import Flask, render_template, request
import requests
from pymongo import MongoClient
import datetime
import plotly.express as px
import plotly.io as pio
import config

app = Flask(__name__)

# ---------- Database ----------
client = MongoClient(config.MONGO_URI)
db = client["cti_dashboard"]
collection = db["threat_logs"]

# ---------- Helper Functions ----------
def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    return response.json()

# ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        query = request.form["query"].strip()
        result = {}

        # Determine IP or domain
        if any(c.isalpha() for c in query):
            result["source"] = "VirusTotal"
            result["data"] = check_virustotal(query)
        else:
            result["source"] = "AbuseIPDB"
            result["data"] = check_abuseipdb(query)

        # Log to MongoDB
        collection.insert_one({
            "query": query,
            "source": result["source"],
            "timestamp": datetime.datetime.now(),
            "data": result["data"]
        })

        return render_template("results.html", query=query, result=result)

    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    logs = list(collection.find().sort("timestamp", -1).limit(20))
    if not logs:
        return render_template("dashboard.html", graph_html=None, logs=[])

    sources = [log["source"] for log in logs]

    fig = px.histogram(
        x=sources,
        title="Threat Source Distribution (Last 20 Lookups)",
        labels={"x": "Source", "y": "Count"},
        color_discrete_sequence=["#ff1e1e"]
    )

    fig.update_layout(
        paper_bgcolor="#0d0d0d",
        plot_bgcolor="#0d0d0d",
        font_color="#ff1e1e"
    )

    graph_html = pio.to_html(fig, full_html=False)
    return render_template("dashboard.html", graph_html=graph_html, logs=logs)

if __name__ == "__main__":
    app.run(debug=True)
