# Verify Summary

- Generated: 2026-05-17T23:57:47
- Run folder: `evaluation/verify_runs/20260517_212343`
- Scope: Group B synthetic AI/Baseline and Group C Mininet local Kafka/E2E.

| # | Group | Check | Target | Measured | Result | Evidence |
|---:|---|---|---|---|---|---|
| 1 | B | AI S1_normal_baseline target tier | T0-T0 | T0, verdict=PASS | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S1_normal_baseline_summary.json` |
| 2 | B | AI S2_sudden_udp_flood target tier | T3-T3 | T4, verdict=FAIL | **FAIL** | `evaluation/verify_runs/20260517_212343/group_b_ai/S2_sudden_udp_flood_summary.json` |
| 3 | B | AI S3_gradual_syn_ramp target tier | T2-T3 | T3, verdict=PASS | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S3_gradual_syn_ramp_summary.json` |
| 4 | B | AI S8_proactive_t2_vs_reactive_t3 target tier | T3-T3 | T4, verdict=FAIL | **FAIL** | `evaluation/verify_runs/20260517_212343/group_b_ai/S8_proactive_t2_vs_reactive_t3_summary.json` |
| 5 | B | Baseline S1_normal_baseline target tier | T0-T0 | T0, verdict=PASS | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_baseline/S1_normal_baseline_summary.json` |
| 6 | B | Baseline S2_sudden_udp_flood target tier | T3-T3 | T3, verdict=PASS | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_baseline/S2_sudden_udp_flood_summary.json` |
| 7 | B | Baseline S3_gradual_syn_ramp target tier | T2-T3 | T3, verdict=PASS | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_baseline/S3_gradual_syn_ramp_summary.json` |
| 8 | B | Baseline S8_proactive_t2_vs_reactive_t3 target tier | T3-T3 | T3, verdict=PASS | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_baseline/S8_proactive_t2_vs_reactive_t3_summary.json` |
| 9 | B | AI S1_normal_baseline windows | >0 | 100 | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S1_normal_baseline.jsonl` |
| 10 | B | AI S2_sudden_udp_flood windows | >0 | 110 | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S2_sudden_udp_flood.jsonl` |
| 11 | B | AI S3_gradual_syn_ramp windows | >0 | 120 | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S3_gradual_syn_ramp.jsonl` |
| 12 | B | AI S8_proactive_t2_vs_reactive_t3 windows | >0 | 120 | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S8_proactive_t2_vs_reactive_t3.jsonl` |
| 13 | B | AI S3 T3 latency recorded | n>0 when T3 acted | p50=4003.36ms, n=1 | **PASS** | `evaluation/verify_runs/20260517_212343/group_b_ai/S3_gradual_syn_ramp_summary.json` |
| 14 | B | AI S8 no over-escalation | max T3 | T4 | **FAIL** | `evaluation/verify_runs/20260517_212343/group_b_ai/S8_proactive_t2_vs_reactive_t3_summary.json` |
| 15 | C | Kafka compose ps captured | log exists | exists | **PASS** | `evaluation/verify_runs/20260517_212343/logs/group_c_docker_compose_ps.log` |
| 16 | C | Kafka health | healthy or skipped | skipped (transport=http) | **PASS** | `evaluation/verify_runs/20260517_212343/logs/group_c_docker_compose_ps.log` |
| 17 | C | Mininet collector windows | >0 computed windows | computed | **PASS** | `evaluation/results/collector_*.log` |
| 18 | C | Collector transport | Kafka connected or HTTP direct | HTTP direct | **PASS** | `evaluation/results/collector_*.log` |
| 19 | C | Mininet AI run log | log exists | exists | **PASS** | `evaluation/verify_runs/20260517_212343/logs/group_c_e2e_ai.log` |
| 20 | C | Mininet AI JSON output | exists | real_e2e_ai_udplag_20260517_235620.json | **PASS** | `evaluation/results/real_e2e_ai_*.json` |
| 21 | C | Mininet baseline run log | log exists | exists | **PASS** | `evaluation/verify_runs/20260517_212343/logs/group_c_e2e_baseline.log` |
| 22 | C | Mininet baseline JSON output | exists | real_e2e_baseline_udplag_20260517_235813.json | **PASS** | `evaluation/results/real_e2e_baseline_*.json` |

## Totals

- PASS: 19/22
- FAIL: 3/22

## Notes

- Group B AI ran with `mode=legacy` because the available scaler is 17-feature while the newer spec path expects 22-feature scaling.
- Group C Mininet traffic and NetFlow collection ran; collector logs show computed windows.
- Kafka transport was bypassed for the final Group C smoke run with `E2E_TRANSPORT=http`; the evaluator polled the Mininet collector REST endpoint directly.
- The final Group C smoke profile used `k=2`, `duration=5`, `attack=udplag` after the full Kafka-backed `k=4`, `duration=60` attempt stalled in the WSL/Docker path.