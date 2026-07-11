# Security Incident Analysis Dashboard

## Objective
Analyze 2,099,971 network traffic records from the CICIDS 2017 
dataset to identify attack patterns, suspicious IPs, and key 
security metrics using SQL and Power BI.

## Tools & Technologies
- SQL (DB Browser for SQLite)
- Power BI Desktop
- Dataset: CICIDS 2017 — Canadian Institute for Cybersecurity
- GitHub

## Dataset
- **Source:** CICIDS 2017 — Canadian Institute for Cybersecurity
- **Total records:** 2,099,971
- **Attack types identified:** 27
- **Unique IPs:** 174

## Key Findings
- **24.64%** of total traffic was malicious (517,410 events)
- **172.16.0.1** was the most active malicious IP with 441,714 
  events across 22 different attack types
- **Portscan** and **DoS Hulk** were the most frequent attacks
  with 7.57% and 7.55% respectively
- **TCP** was the dominant protocol in malicious traffic
- **DDoS** accounted for 4.53% of total traffic (95,144 events)

## Dashboard Preview
dashboard_01.png

## SQL Queries

### Unified View
```sql
CREATE VIEW logs AS
SELECT * FROM friday
UNION ALL
SELECT * FROM monday
UNION ALL
SELECT * FROM thursday
UNION ALL
SELECT * FROM tuesday
UNION ALL
SELECT * FROM wednesday;
```

### Attack Distribution
```sql
SELECT 
    "Label" as tipo_ataque,
    COUNT(*) as total,
    ROUND(COUNT(*) * 100.0 / 
        (SELECT COUNT(*) FROM logs), 2) as porcentaje
FROM logs
GROUP BY "Label"
ORDER BY total DESC;
```

### Top Suspicious IPs
```sql
SELECT 
    (("Src IP dec" / 16777216) % 256) || '.' ||
    (("Src IP dec" / 65536) % 256) || '.' ||
    (("Src IP dec" / 256) % 256) || '.' ||
    ("Src IP dec" % 256) as ip_origen,
    CAST(COUNT(*) AS TEXT) as total_eventos,
    CAST(COUNT(DISTINCT Label) AS TEXT) as tipos_ataque_distintos
FROM logs
WHERE Label != 'BENIGN'
GROUP BY "Src IP dec"
ORDER BY COUNT(*) DESC
LIMIT 10;
```

### Security KPIs
```sql
SELECT
    COUNT(*) as total_eventos,
    SUM(CASE WHEN Label != 'BENIGN' THEN 1 ELSE 0 END) 
        as total_maliciosos,
    SUM(CASE WHEN Label = 'BENIGN' THEN 1 ELSE 0 END) 
        as total_benignos,
    ROUND(SUM(CASE WHEN Label != 'BENIGN' THEN 1 ELSE 0 END) 
        * 100.0 / COUNT(*), 2) as porcentaje_malicioso,
    COUNT(DISTINCT "Src IP dec") as ips_unicas
FROM logs;
```

### Attacks by Protocol
```sql
SELECT 
    CASE Protocol
        WHEN 6 THEN 'TCP'
        WHEN 17 THEN 'UDP'
        WHEN 0 THEN 'HOPOPT'
        WHEN 1 THEN 'ICMP'
        ELSE 'Other'
    END as protocolo,
    COUNT(*) as total_eventos,
    SUM(CASE WHEN Label != 'BENIGN' THEN 1 ELSE 0 END) 
        as eventos_maliciosos
FROM logs
GROUP BY Protocol
ORDER BY eventos_maliciosos DESC;
```

## Dashboard Components
- **KPI Cards:** Total events, benign traffic, 
  malicious events, malicious %, unique IPs
- **Bar Chart:** Top attack types by volume
- **Column Chart:** Malicious events by protocol
- **Table:** Top 7 suspicious IPs with event count
  and attack diversity
- **Donut Chart:** Benign vs malicious traffic distribution

## Skills Demonstrated
- SQL querying and data analysis
- Security data interpretation
- KPI definition and measurement
- Network traffic analysis
- Power BI dashboard development
- Cybersecurity threat identification

## Author
María Isabel Araujo Robalino
IT Security Professional | Security Analyst

