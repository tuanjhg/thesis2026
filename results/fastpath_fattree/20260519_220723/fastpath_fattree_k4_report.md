# Fastpath Ryu + Mininet Fat-Tree k=4 Report

- Run ID: `20260519_220723`
- Topology: k=4, switches=20, hosts=16
- Attacker/Victim: `h0 (10.0.0.1)` -> `h15 (10.3.1.2)`
- Ryu topology seen: switches=20, links=64, hosts=16
- Pingall loss: 0.0%
- Result: **8/8 scenarios passed**

| Scenario | Attack | Tier | Action | POST ms | Installed switches | Flow count | Pass |
|---|---:|---:|---|---:|---:|---:|---|
| S1 | BENIGN | T0 | pass | 3.12 | 0 | 0 | PASS |
| S2 | SYN_LOW | T2 | ratelimit | 4.09 | 20 | 20 | PASS |
| S3 | SYN_HIGH | T3 | redirect | 3.62 | 20 | 20 | PASS |
| S4 | UDP_AMP | T3 | redirect | 3.76 | 20 | 20 | PASS |
| S5 | MULTI | T4 | drop | 4.01 | 20 | 20 | PASS |
| S6 | CARPET | T4 | drop | 4.03 | 20 | 20 | PASS |
| S7 | SLOW_RATE | T2 | ratelimit | 4.06 | 20 | 20 | PASS |
| S8 | BURST | T3 | redirect | 4.04 | 20 | 20 | PASS |

JSON detail: `/mnt/d/Khóa luận/Src_2/results/fastpath_fattree/20260519_220723/fastpath_fattree_k4_results.json`
