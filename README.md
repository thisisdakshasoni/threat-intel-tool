# Threat Intelligence Tool 🚨

This project is a full-stack Threat Intelligence Dashboard that allows real-time scanning and analysis of potential Indicators of Compromise (IOCs) like IPs, domains, hashes, and Shodan-exposed services.

---

## 🔍 Features
- **Live IOC Scanning** via VirusTotal, AbuseIPDB, and Shodan APIs
- **Integrated with MongoDB, PostgreSQL, Neo4j**
- **Real-time Logs** in frontend (React)
- **Neo4j Threat Graph View** with IP ➝ Verdict relationships
- **Export Graph to PNG** from dashboard
- **Dockerized Backend & Frontend**

---

## 🛠️ Tech Stack

| Layer       | Technology                   |
|-------------|-------------------------------|
| Frontend    | React.js + Tailwind CSS       |
| Backend     | FastAPI                       |
| Database    | MongoDB + PostgreSQL          |
| Graph DB    | Neo4j                         |
| APIs Used   | VirusTotal, AbuseIPDB, Shodan |
| Container   | Docker, Docker Compose        |

---

## ✅ Functionality Walkthrough

1. **Scan Types**
   - IP Reputation (VirusTotal + AbuseIPDB)
   - Domain Analysis (VirusTotal)
   - File Hash Detection (VirusTotal)
   - Shodan Open Ports Detection

2. **Logs**
   - Live scan logs shown for IP, Domain, Hash, and Shodan
   - Pulled from PostgreSQL and MongoDB

3. **Graph View**
   - Visualizes `IP ➝ Verdict` relationships
   - Data pulled from Neo4j
   - Nodes: IPs/Hashes/Domains
   - Edges: FLAGGED_AS relation with Verdict

4. **Export Graph**
   - Click “Export PNG” to download graph snapshot

---

## ⚙️ Setup

### 1. Environment Variables (.env)
```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
```

### 2. Run Dockerized Stack
```bash
docker-compose up --build
```

### 3. Access
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- Neo4j Browser: http://localhost:7474


![Uploading Screenshot 2025-06-02 231752.png…]()


