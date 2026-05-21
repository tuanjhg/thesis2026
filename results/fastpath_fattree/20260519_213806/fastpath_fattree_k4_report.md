# Fastpath Ryu + Mininet Fat-Tree k=4 Report

- Run ID: `20260519_213806`
- Topology: k=4, switches=20, hosts=16
- Attacker/Victim: `h0 (10.0.0.1)` -> `h15 (10.3.1.2)`
- Ryu topology seen: switches=20, links=62, hosts=22
- Result: **8/8 scenarios passed**
- Scope: control-plane fastpath verification (Ryu REST + OpenFlow Flow-Mod install on all 20 switches).
- Caveat: data-plane connectivity under the current Ryu L2 learning app is not healthy (`pingall_loss_pct=100.0`), so this run proves rule installation, not end-to-end goodput recovery. S6 also needs an explicit hping3 interface for `--rand-dest` traffic generation.

| Scenario | Attack | Tier | Action | POST ms | Installed switches | Flow count | Pass |
|---|---:|---:|---|---:|---:|---:|---|
| S1 | BENIGN | T0 | pass | 23.24 | 0 | 0 | PASS |
| S2 | SYN_LOW | T2 | ratelimit | 22.35 | 20 | 20 | PASS |
| S3 | SYN_HIGH | T3 | redirect | 16.23 | 20 | 20 | PASS |
| S4 | UDP_AMP | T3 | redirect | 13.66 | 20 | 20 | PASS |
| S5 | MULTI | T4 | drop | 27.79 | 20 | 20 | PASS |
| S6 | CARPET | T4 | drop | 23.33 | 20 | 20 | PASS |
| S7 | SLOW_RATE | T2 | ratelimit | 27.65 | 20 | 20 | PASS |
| S8 | BURST | T3 | redirect | 24.83 | 20 | 20 | PASS |

JSON detail: `/mnt/d/Khóa luận/Src_2/results/fastpath_fattree/20260519_213806/fastpath_fattree_k4_results.json`
