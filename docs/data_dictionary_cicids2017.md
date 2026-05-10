# CICIDS2017 Data Dictionary

_Generated: 2026-05-10 16:10_

## 1. Source

- **Dataset:** CICIDS2017 (Canadian Institute for Cybersecurity)
- **Authors:** Sharafaldin, Lashkari, Ghorbani (2018)
- **Paper:** "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"
- **Distribution:** GeneratedLabelledFlows.zip (preserves IPs, ports, timestamps)
- **URL:** https://www.unb.ca/cic/datasets/ids-2017.html

## 2. Volume

- **Total events:** 3,119,345
- **Total columns:** 88
- **Files:** 8 CSVs covering Mon–Fri, 3–7 July 2017
- **Storage:** ~1 GB raw CSV → ~150-250 MB parquet (cleaned)

### Per-Day Breakdown

| Day | Rows | Earliest | Latest |
|---|---|---|---|
| Monday | 529,918 | 2017-07-03 08:55:58 | 2017-07-03 17:01:34 |
| Tuesday | 445,909 | 2017-07-04 08:53:00 | 2017-07-04 17:00:00 |
| Wednesday | 692,703 | 2017-07-05 08:42:00 | 2017-07-05 17:10:00 |
| Thursday | 747,570 | 2017-07-06 08:59:00 | 2017-07-06 17:04:00 |
| Friday | 703,245 | 2017-07-07 08:59:00 | 2017-07-07 17:02:00 |

## 3. Attack Categories

### Attack Family Distribution (high-level grouping)

| Attack Family | Event Count | Percentage |
|---|---|---|
| Benign | 2,273,097 | 72.87% |
| Unlabeled | 288,602 | 9.25% |
| DoS | 252,661 | 8.1% |
| Reconnaissance | 158,930 | 5.09% |
| DDoS | 128,027 | 4.1% |
| Brute Force | 13,835 | 0.44% |
| Web Attack | 2,180 | 0.07% |
| Botnet | 1,966 | 0.06% |
| Infiltration | 36 | 0.0% |
| Exploit | 11 | 0.0% |

### Detailed Label Distribution

| Label | Attack Family | Event Count |
|---|---|---|
| BENIGN | Benign | 2,273,097 |
| Unlabeled | Unlabeled | 288,602 |
| DoS Hulk | DoS | 231,073 |
| PortScan | Reconnaissance | 158,930 |
| DDoS | DDoS | 128,027 |
| DoS GoldenEye | DoS | 10,293 |
| FTP-Patator | Brute Force | 7,938 |
| SSH-Patator | Brute Force | 5,897 |
| DoS slowloris | DoS | 5,796 |
| DoS Slowhttptest | DoS | 5,499 |
| Bot | Botnet | 1,966 |
| Web Attack - Brute Force | Web Attack | 1,507 |
| Web Attack - XSS | Web Attack | 652 |
| Infiltration | Infiltration | 36 |
| Web Attack - Sql Injection | Web Attack | 21 |
| Heartbleed | Exploit | 11 |

## 4. Documented Attack Windows

| Day | Attack | First Seen | Last Seen | Events |
|---|---|---|---|---|
| Friday | Bot | 2017-07-07 09:34:00 | 2017-07-07 12:59:00 | 1,966 |
| Friday | PortScan | 2017-07-07 13:05:00 | 2017-07-07 15:23:00 | 158,930 |
| Friday | DDoS | 2017-07-07 15:56:00 | 2017-07-07 16:16:00 | 128,027 |
| Thursday | Web Attack - Brute Force | 2017-07-06 09:15:00 | 2017-07-06 10:00:00 | 1,507 |
| Thursday | Web Attack - XSS | 2017-07-06 10:15:00 | 2017-07-06 10:35:00 | 652 |
| Thursday | Web Attack - Sql Injection | 2017-07-06 10:40:00 | 2017-07-06 10:42:00 | 21 |
| Thursday | Infiltration | 2017-07-06 14:19:00 | 2017-07-06 15:45:00 | 36 |
| Tuesday | FTP-Patator | 2017-07-04 09:17:00 | 2017-07-04 10:30:00 | 7,938 |
| Tuesday | SSH-Patator | 2017-07-04 14:09:00 | 2017-07-04 15:11:00 | 5,897 |
| Wednesday | DoS slowloris | 2017-07-05 09:01:00 | 2017-07-05 14:25:00 | 5,796 |
| Wednesday | DoS Slowhttptest | 2017-07-05 10:15:00 | 2017-07-05 10:37:00 | 5,499 |
| Wednesday | DoS Hulk | 2017-07-05 10:43:00 | 2017-07-05 11:07:00 | 231,073 |
| Wednesday | DoS GoldenEye | 2017-07-05 11:10:00 | 2017-07-05 11:19:00 | 10,293 |
| Wednesday | Heartbleed | 2017-07-05 15:12:00 | 2017-07-05 15:32:00 | 11 |

## 5. Schema (Cleaned `stg_cicids_final`)

| Column | Type |
|---|---|
| `Flow ID` | VARCHAR |
| `Source IP` | VARCHAR |
| `Destination IP` | VARCHAR |
| `Source Port` | INTEGER |
| `Destination Port` | INTEGER |
| `Protocol` | INTEGER |
| `Flow Duration` | INTEGER |
| `Total Fwd Packets` | INTEGER |
| `Total Backward Packets` | INTEGER |
| `Total Length of Fwd Packets` | INTEGER |
| `Total Length of Bwd Packets` | INTEGER |
| `Fwd Packet Length Max` | INTEGER |
| `Fwd Packet Length Min` | INTEGER |
| `Bwd Packet Length Max` | INTEGER |
| `Bwd Packet Length Min` | INTEGER |
| `Flow IAT Max` | BIGINT |
| `Flow IAT Min` | BIGINT |
| `Fwd IAT Total` | BIGINT |
| `Fwd IAT Max` | BIGINT |
| `Fwd IAT Min` | BIGINT |
| `Bwd IAT Total` | BIGINT |
| `Bwd IAT Max` | BIGINT |
| `Bwd IAT Min` | BIGINT |
| `Fwd PSH Flags` | INTEGER |
| `Bwd PSH Flags` | INTEGER |
| `Fwd URG Flags` | INTEGER |
| `Bwd URG Flags` | INTEGER |
| `Fwd Header Length` | INTEGER |
| `Bwd Header Length` | INTEGER |
| `Min Packet Length` | INTEGER |
| `Max Packet Length` | INTEGER |
| `FIN Flag Count` | INTEGER |
| `SYN Flag Count` | INTEGER |
| `RST Flag Count` | INTEGER |
| `PSH Flag Count` | INTEGER |
| `ACK Flag Count` | INTEGER |
| `URG Flag Count` | INTEGER |
| `CWE Flag Count` | INTEGER |
| `ECE Flag Count` | INTEGER |
| `Down/Up Ratio` | INTEGER |
| `Fwd Avg Bytes/Bulk` | INTEGER |
| `Fwd Avg Packets/Bulk` | INTEGER |
| `Fwd Avg Bulk Rate` | INTEGER |
| `Bwd Avg Bytes/Bulk` | INTEGER |
| `Bwd Avg Packets/Bulk` | INTEGER |
| `Bwd Avg Bulk Rate` | INTEGER |
| `Subflow Fwd Packets` | INTEGER |
| `Subflow Fwd Bytes` | INTEGER |
| `Subflow Bwd Packets` | INTEGER |
| `Subflow Bwd Bytes` | INTEGER |
| `Init_Win_bytes_forward` | INTEGER |
| `Init_Win_bytes_backward` | INTEGER |
| `act_data_pkt_fwd` | INTEGER |
| `min_seg_size_forward` | INTEGER |
| `Active Max` | BIGINT |
| `Active Min` | BIGINT |
| `Idle Max` | BIGINT |
| `Idle Min` | BIGINT |
| `Fwd Packet Length Mean` | DOUBLE |
| `Fwd Packet Length Std` | DOUBLE |
| `Bwd Packet Length Mean` | DOUBLE |
| `Bwd Packet Length Std` | DOUBLE |
| `Flow Bytes/s` | DOUBLE |
| `Flow Packets/s` | DOUBLE |
| `Flow IAT Mean` | DOUBLE |
| `Flow IAT Std` | DOUBLE |
| `Fwd IAT Mean` | DOUBLE |
| `Fwd IAT Std` | DOUBLE |
| `Bwd IAT Mean` | DOUBLE |
| `Bwd IAT Std` | DOUBLE |
| `Fwd Packets/s` | DOUBLE |
| `Bwd Packets/s` | DOUBLE |
| `Packet Length Mean` | DOUBLE |
| `Packet Length Std` | DOUBLE |
| `Packet Length Variance` | DOUBLE |
| `Average Packet Size` | DOUBLE |
| `Avg Fwd Segment Size` | DOUBLE |
| `Avg Bwd Segment Size` | DOUBLE |
| `Active Mean` | DOUBLE |
| `Active Std` | DOUBLE |
| `Idle Mean` | DOUBLE |
| `Idle Std` | DOUBLE |
| `event_time_raw` | VARCHAR |
| `label_clean` | VARCHAR |
| `attack_family` | VARCHAR |
| `is_attack` | INTEGER |
| `source_day` | VARCHAR |
| `event_time` | TIMESTAMP |

## 6. Derived Columns (Added During Cleaning)

| Column | Type | Purpose |
|---|---|---|
| `label_clean` | VARCHAR | Normalized label (em-dash artifact `\x96` replaced with `-`, NULLs marked 'Unlabeled') |
| `attack_family` | VARCHAR | High-level grouping (Benign/DoS/DDoS/Reconnaissance/Brute Force/Web Attack/Botnet/Infiltration/Exploit/Unlabeled) |
| `is_attack` | INTEGER | Binary ML target (0=Benign, 1=Attack, NULL=Unlabeled — excluded from supervised training) |
| `source_day` | VARCHAR | Day of week (added during ETL for time analysis) |
| `event_time` | TIMESTAMP | Parsed timestamp with AM/PM business-hour inference |

## 7. Data Quality Issues Encountered & Resolved

This dataset has well-known issues. Below are the ones encountered and how they were handled:

### Issue 1: Inconsistent Timestamp Formats
- **Problem:** Monday uses `dd/mm/YYYY HH:MM:SS` (zero-padded with seconds); other days use `d/m/YYYY H:MM` (no padding, no seconds)
- **Resolution:** Branched parser logic by `source_day`

### Issue 2: 12-Hour Format Without AM/PM Markers
- **Problem:** Times appear as 1:00, 2:00, etc. with no AM/PM. Could mean morning or afternoon.
- **Resolution:** Used CICIDS2017 documentation (8 AM – 5 PM business hours) to infer: hours 1-5 → PM, hours 8-12 → AM
- **Validation:** Parsed attack times match documented attack windows exactly (e.g. Heartbleed at 15:12-15:32 matches docs)

### Issue 3: Inf/NaN Values in Numeric Columns
- **Problem:** `Flow Bytes/s` and `Flow Packets/s` contain `Infinity`, `inf`, and `NaN` strings (~5,700 rows)
- **Resolution:** Cast via `CASE WHEN ILIKE '%inf%' OR '%nan%' THEN NULL ELSE TRY_CAST(...) END`

### Issue 4: Encoding Artifact in Web Attack Labels
- **Problem:** Latin-1 character `\x96` (em-dash) appears in labels like `Web Attack \x96 XSS`
- **Resolution:** Loaded WebAttacks file via pandas with `encoding='latin-1'`; normalized via REGEXP_REPLACE

### Issue 5: Broken CSV Parsing in WebAttacks File
- **Problem:** DuckDB's `read_csv` with `ignore_errors=true` silently produced 288,602 NULL-filled phantom rows
- **Resolution:** Used pandas (which handles the file cleanly), then pushed to DuckDB

### Issue 6: Genuine Unlabeled Rows (Known Dataset Flaw)
- **Problem:** 288,602 Thursday-WebAttacks rows have empty Label fields — a documented CICIDS2017 quality issue from the original CICFlowMeter generation
- **Resolution:** Marked as 'Unlabeled' (`is_attack = NULL`); excluded from supervised ML training, included in volumetric BI dashboards for transparency

### Issue 7: Severe Class Imbalance
- **Problem:** ~80:20 Benign:Attack ratio; some attacks (Infiltration: 36, Heartbleed: 11) have <50 samples
- **Resolution:** Will use SMOTE oversampling + class-weighted losses in Week 4 ML phase

### Issue 8: Duplicate Column Name (`Fwd Header Length` & `Fwd Header Length_1`)
- **Problem:** Original dataset accidentally duplicated this column
- **Resolution:** Dropped `Fwd Header Length_1` during column selection

## 8. Network Topology (Inferred from Data)

### Internal Network (192.168.10.0/24)

| IP | Role | Evidence |
|---|---|---|
| `192.168.10.50` | **Primary Web Server (Victim)** | Receives 555K attacks: DoS, DDoS, Recon, Brute Force, Web Attack |
| `192.168.10.51` | Secondary Server | 11 Heartbleed attacks |
| `192.168.10.5/8/9/14/15` | Workstations (Bot-compromised) | All show Botnet in source and destination |
| `192.168.10.8` | Insider Threat Origin | Source of 36 Infiltration events |
| `192.168.10.3` | Internal Service (DNS/AD) | Highest volume, no attacks |
| `192.168.10.1` | Gateway/Router | High volume, no attacks |

### External Actors

| IP | Role |
|---|---|
| `205.174.165.73` | **The Documented External Attacker** — DDoS source, Heartbleed exploitation |

## 9. Geographic Mapping Strategy

- **External IPs identified:** 19,035 (mostly benign destinations from internal browsing)
- **External attackers:** 1 (`205.174.165.73`)
- **Approach:** "Network Communication Footprint" map — shows where internal hosts reach out, with the single attacker IP highlighted
- **Internal network visualization:** separate dashboard component (host-to-host attack graph)
- **Enrichment plan (Week 3):** MaxMind GeoLite2-City lookup for all 19,035 external IPs; AbuseIPDB enrichment for top-N suspicious IPs (rate-limit aware)
- **External IP master list:** `data/interim/external_ips_master.csv`

## 10. Files Generated in Week 1

| Artifact | Path |
|---|---|
| Cleaned dataset (Parquet) | `data/interim/cicids_clean.parquet` |
| EDA staging database | `data/interim/cicids_eda.duckdb` |
| External IPs to geocode | `data/interim/external_ips_to_geocode.csv` |
| External attacker profile | `data/interim/external_attackers_profile.csv` |
| Master external IP list | `data/interim/external_ips_master.csv` |
| PostgreSQL stratified sample | `staging.stg_cicids_sample` (12,047 rows) |
| EDA notebook | `notebooks/01_cicids2017_eda.ipynb` |
| EDA visualizations | `docs/figures/01_*.png` through `05_*.png` |

## 11. CICIDS2017 Source Files Used

| File | Day | Primary Attacks |
|---|---|---|
| `Monday-WorkingHours.pcap_ISCX.csv` | Mon | None (benign baseline) |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | Tue | FTP-Patator, SSH-Patator |
| `Wednesday-workingHours.pcap_ISCX.csv` | Wed | DoS variants, Heartbleed |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Thu AM | Web attacks (XSS, SQLi, BF) — **had encoding issues** |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Thu PM | Infiltration |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Fri AM | Botnet |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Fri PM | PortScan |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Fri PM | DDoS |
