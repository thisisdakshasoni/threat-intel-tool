from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
import httpx
from dotenv import load_dotenv
from pymongo import MongoClient
import psycopg2
from datetime import datetime
from neo4j import GraphDatabase

app = FastAPI()

# CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# DB Connections
mongo_client = MongoClient("mongodb://mongo-db:27017")
mongo_db = mongo_client["threat_db"]
ioc_logs_collection = mongo_db["ip_checks"]

pg_conn = psycopg2.connect(
    host="postgres-db",
    database="threatdb",
    user="iocuser",
    password="iocpass"
)
pg_cursor = pg_conn.cursor()

neo4j_driver = GraphDatabase.driver("bolt://neo4j-db:7687", auth=("neo4j", "test12345"))

@app.get("/")
def root():
    return {"message": "Threat Intelligence API is running"}

@app.get("/check/ip")
def check_ip(ip: str):
    vt_score, abuse_score = 0, 0

    try:
        vt_res = httpx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                           headers={"x-apikey": VT_API_KEY})
        if vt_res.status_code == 200:
            vt_score = vt_res.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except Exception as e:
        print("VT Error:", e)

    try:
        abuse_res = httpx.get("https://api.abuseipdb.com/api/v2/check",
                              headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                              params={"ipAddress": ip, "maxAgeInDays": 30})
        if abuse_res.status_code == 200:
            abuse_score = abuse_res.json()["data"]["abuseConfidenceScore"]
    except Exception as e:
        print("AbuseIPDB Error:", e)

    combined = vt_score + (abuse_score // 2)
    verdict = "malicious" if combined >= 60 else "suspicious" if combined >= 30 else "clean"
    timestamp = datetime.utcnow()

    try:
        ioc_logs_collection.insert_one({
            "ip": ip, "type": "ip", "virusTotal_score": vt_score, "abuseIPDB_score": abuse_score,
            "combined_risk": combined, "verdict": verdict, "checked_at": timestamp
        })
        pg_cursor.execute("""INSERT INTO ip_check_log (ip, verdict, vt_score, abuse_score, combined_risk, checked_at)
                             VALUES (%s, %s, %s, %s, %s, %s)""",
                          (ip, verdict, vt_score, abuse_score, combined, timestamp))
        pg_conn.commit()
        with neo4j_driver.session() as session:
            session.run("""MERGE (i:IP {value: $ip}) MERGE (v:Verdict {level: $verdict})
                           MERGE (i)-[:FLAGGED_AS]->(v)""", ip=ip, verdict=verdict)
    except Exception as e:
        print("DB Error:", e)

    return {
        "ip": ip, "verdict": verdict,
        "virusTotal_score": vt_score,
        "abuseIPDB_score": abuse_score,
        "combined_risk": combined
    }

@app.get("/check/domain")
def check_domain(domain: str):
    vt_score, verdict = 0, "clean"
    timestamp = datetime.utcnow()
    try:
        res = httpx.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                        headers={"x-apikey": VT_API_KEY})
        if res.status_code == 200:
            vt_score = res.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
            verdict = "malicious" if vt_score >= 5 else "suspicious" if vt_score >= 1 else "clean"
    except Exception as e:
        print("Domain error:", e)

    try:
        ioc_logs_collection.insert_one({
            "domain": domain, "type": "domain",
            "verdict": verdict, "vt_score": vt_score,
            "checked_at": timestamp
        })
        pg_cursor.execute("""INSERT INTO domain_check_log (domain, verdict, vt_score, checked_at)
                             VALUES (%s, %s, %s, %s)""",
                          (domain, verdict, vt_score, timestamp))
        pg_conn.commit()
        with neo4j_driver.session() as session:
            session.run("""MERGE (d:Domain {value: $domain}) MERGE (v:Verdict {level: $verdict})
                           MERGE (d)-[:FLAGGED_AS]->(v)""", domain=domain, verdict=verdict)
    except Exception as e:
        print("DB Error:", e)

    return {"domain": domain, "verdict": verdict, "virusTotal_score": vt_score}

@app.get("/check/hash")
def check_hash(hash: str):
    vt_score, verdict = 0, "clean"
    timestamp = datetime.utcnow()
    try:
        res = httpx.get(f"https://www.virustotal.com/api/v3/files/{hash}",
                        headers={"x-apikey": VT_API_KEY})
        if res.status_code == 200:
            vt_score = res.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
            verdict = "malicious" if vt_score >= 5 else "suspicious" if vt_score >= 1 else "clean"
    except Exception as e:
        print("Hash error:", e)

    try:
        ioc_logs_collection.insert_one({
            "hash": hash, "type": "file_hash",
            "verdict": verdict, "vt_score": vt_score,
            "checked_at": timestamp
        })
        pg_cursor.execute("""INSERT INTO hash_check_log (hash, verdict, vt_score, checked_at)
                             VALUES (%s, %s, %s, %s)""",
                          (hash, verdict, vt_score, timestamp))
        pg_conn.commit()
        with neo4j_driver.session() as session:
            session.run("""MERGE (h:Hash {value: $hash}) MERGE (v:Verdict {level: $verdict})
                           MERGE (h)-[:FLAGGED_AS]->(v)""", hash=hash, verdict=verdict)
    except Exception as e:
        print("DB Error:", e)

    return {"hash": hash, "verdict": verdict, "virusTotal_score": vt_score}

@app.get("/scan/shodan")
def scan_shodan(ip: str):
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key not set."}
    try:
        response = httpx.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        if response.status_code == 200:
            data = response.json()
            # Optional: log to MongoDB for history
            ioc_logs_collection.insert_one({
                "type": "shodan",
                "ip": data.get("ip_str"),
                "ports": data.get("ports"),
                "hostnames": data.get("hostnames"),
                "org": data.get("org"),
                "os": data.get("os"),
                "location": data.get("location"),
                "checked_at": datetime.utcnow()
            })
            return {
                "ip": data.get("ip_str"),
                "organization": data.get("org"),
                "os": data.get("os"),
                "open_ports": data.get("ports"),
                "hostnames": data.get("hostnames"),
                "location": data.get("location")
            }
        return {"error": f"Shodan error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# 🔍 LOG ENDPOINTS
@app.get("/logs/ip")
def get_ip_logs(limit: int = 10):
    try:
        pg_cursor.execute("""
            SELECT ip, verdict, vt_score, abuse_score, combined_risk, checked_at
            FROM ip_check_log ORDER BY checked_at DESC LIMIT %s
        """, (limit,))
        rows = pg_cursor.fetchall()
        return [
            {
                "ip": row[0], "verdict": row[1], "virusTotal_score": row[2],
                "abuseIPDB_score": row[3], "combined_risk": row[4],
                "checked_at": row[5].isoformat()
            } for row in rows
        ]
    except Exception as e:
        return {"error": str(e)}

@app.get("/logs/domain")
def get_domain_logs(limit: int = 10):
    try:
        cursor = mongo_db["ip_checks"].find({"type": "domain"}, {"_id": 0}).sort("checked_at", -1).limit(limit)
        return list(cursor)
    except Exception as e:
        return {"error": str(e)}

@app.get("/logs/hash")
def get_hash_logs(limit: int = 10):
    try:
        cursor = mongo_db["ip_checks"].find({"type": "file_hash"}, {"_id": 0}).sort("checked_at", -1).limit(limit)
        return list(cursor)
    except Exception as e:
        return {"error": str(e)}

@app.get("/logs/shodan")
def get_shodan_logs(limit: int = 10):
    try:
        cursor = mongo_db["ip_checks"].find({"type": "shodan"}, {"_id": 0}).sort("checked_at", -1).limit(limit)
        return list(cursor)
    except Exception as e:
        return {"error": str(e)}

@app.get("/graph")
def get_graph():
    try:
        result = {
            "nodes": [],
            "links": []
        }
        seen = set()

        with neo4j_driver.session() as session:
            records = session.run("""
                MATCH (a)-[r:FLAGGED_AS]->(v:Verdict)
                RETURN a.value as source, labels(a)[0] as type, v.level as verdict
            """)

            for record in records:
                source = record["source"]
                verdict = record["verdict"]
                type_ = record["type"]

                if source not in seen:
                    result["nodes"].append({"id": source, "group": type_})
                    seen.add(source)

                if verdict not in seen:
                    result["nodes"].append({"id": verdict, "group": "Verdict"})
                    seen.add(verdict)

                result["links"].append({
                    "source": source,
                    "target": verdict,
                    "label": "FLAGGED_AS"
                })

        return result

    except Exception as e:
        return {"error": str(e)}

@app.get("/graph/ip-verdict")
def get_ip_verdict_graph(limit: int = 10):
    try:
        with neo4j_driver.session() as session:
            query = """
            MATCH (i:IP)-[:FLAGGED_AS]->(v:Verdict)
            RETURN i.value AS ip, v.level AS verdict
            LIMIT $limit
            """
            results = session.run(query, limit=limit)
            nodes = []
            links = []
            seen_nodes = set()

            for record in results:
                ip = record["ip"]
                verdict = record["verdict"]

                if ip not in seen_nodes:
                    nodes.append({"id": ip, "group": "IP"})
                    seen_nodes.add(ip)
                if verdict not in seen_nodes:
                    nodes.append({"id": verdict, "group": "Verdict"})
                    seen_nodes.add(verdict)

                links.append({"source": ip, "target": verdict, "label": "FLAGGED_AS"})

            return {"nodes": nodes, "links": links}
    except Exception as e:
        return {"error": str(e)}
