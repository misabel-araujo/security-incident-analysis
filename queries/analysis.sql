-- =============================================
-- Security Incident Analysis - SQL Queries
-- Dataset: CICIDS 2017
-- Author: María Isabel Araujo Robalino
-- =============================================

-- 1. Unified View
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

-- 2. Total records verification
SELECT COUNT(*) as total_registros FROM logs;

-- 3. Attack Distribution
SELECT 
    "Label" as tipo_ataque,
    COUNT(*) as total,
    ROUND(COUNT(*) * 100.0 / 
        (SELECT COUNT(*) FROM logs), 2) as porcentaje
FROM logs
GROUP BY "Label"
ORDER BY total DESC;

-- 4. Top Suspicious IPs
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

-- 5. Security KPIs
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

-- 6. Attacks by Protocol
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
