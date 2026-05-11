┌─────────────────────────────────────────────────────────────┐
│  INPUT: ctx.transformed_df (2.83M rows × 93 cols)           │
│         ctx.enriched_ip_data (dict of IP → geo+reputation)  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 1: Resolve dim_asset surrogate keys                   │
│    - Find distinct IPs (src + dest)                         │
│    - Look up existing dim_asset rows                        │
│    - INSERT missing IPs with geo enrichment merged in       │
│    - Build {ip → asset_sk} mapping                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 2: Resolve dim_port surrogate keys                    │
│    - Find distinct observed ports (src + dest)              │
│    - Look up existing dim_port rows                         │
│    - INSERT missing ports (uncategorized)                   │
│    - Build {port → port_sk} mapping                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 3: Resolve attack/protocol FKs                        │
│    - Build {attack_label → attack_sk} from dim_attack_type  │
│    - Build {protocol_num → protocol_sk} from dim_protocol   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 4: Apply mappings to DataFrame                        │
│    - Map src_ip → src_asset_sk                              │
│    - Map dest_ip → dest_asset_sk                            │
│    - Map src_port → src_port_sk                             │
│    - Map dest_port → dest_port_sk                           │
│    - Map attack_label → attack_sk                           │
│    - Map protocol_num → protocol_sk                         │
│    - Drop unmapped/unneeded columns                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 5: TRUNCATE fact_security_event (full reload)         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 6: Bulk COPY to fact_security_event                   │
│    - Write DataFrame to CSV in C:\temp                      │
│    - psycopg2 COPY FROM STDIN                               │
│    - ~30-60 seconds for 2.83M rows                          │
└─────────────────────────────────────────────────────────────┘