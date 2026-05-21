# Ryu Fast-Path + Frontend Visualization — Setup Guide

Hai thành phần mới bổ sung cho testbed [single-server](../onap/TESTBED_SINGLE_SERVER.md):

1. **Ryu fast-path SDN controller** — chạy song song ONAP slow-path để
   mitigate ở dataplane trong vài ms.
2. **Frontend visualization** — web UI (Cytoscape.js + FastAPI) hiển thị
   topology và scenario S1–S8 theo thời gian thực.

---

## 1. Kiến trúc dual-path

```
                                M3 AI quyết định tier
                                          │
                       ┌──────────────────┴──────────────────┐
                       ▼                                     ▼
              ┌────────────────┐                  ┌────────────────────┐
              │   FAST PATH    │                  │     SLOW PATH      │
              │   Ryu :8080    │                  │   CLAMP :30258     │
              │   POST /pad/   │                  │   POST /restservi… │
              │   tier         │                  │                    │
              └────────┬───────┘                  └─────────┬──────────┘
                       │ ~ms                                │ ~giây
                       ▼                                    ▼
              OpenFlow Flow-Mod                    Policy PDP eval Drools
              install trên OVS                              ▼
              switches:                            SO.instantiate VNF
              · tier 2 → ratelimit                          ▼
              · tier 3 → redirect → scrubber       kubectl create pod
              · tier 4 → drop                               ▼
                                                   VNF pod /health OK
              ▼                                                       ▼
              ─────────── dataplane unified mitigation ─────────────
```

| | Fast path (Ryu) | Slow path (ONAP) |
|---|---|---|
| Latency tier → action | ~ms (Flow-Mod) | ~giây (CLAMP+Policy+SO+kubectl) |
| Vị trí enforcement | OVS dataplane | VNF pod user-space |
| Audit | Ryu log | CLAMP loop event + Policy decision |
| Recovery khi pod chết | Không phụ thuộc | Phải re-instantiate |
| Persistent | Không (rule expire idle 30s) | Có (pod stays alive) |
| Mục tiêu | Cắt máu ngay | Mitigation lâu dài + steering |

→ Fast-path **bù** cho khoảng trống ~1–3 giây mà slow-path cần để spawn VNF.

---

## 2. Cài đặt

### 2.1 Python deps

Trong virtualenv của project (Ryu pin eventlet cũ — nên có venv riêng):

```bash
# venv riêng cho Ryu (để khỏi đụng pipeline deps)
python3 -m venv .venv-ryu
source .venv-ryu/bin/activate
pip install ryu==4.34 eventlet==0.30.2 webob
deactivate

# Frontend backend dùng venv chính của pipeline
pip install -r frontend/requirements.txt
```

### 2.2 Mininet — đổi `failMode='standalone'` thành `'secure'`

Trong [testbed/mininet/fat_tree_topology.py](../testbed/mininet/fat_tree_topology.py)
sửa 3 chỗ `failMode='standalone'` → `failMode='secure'` và bật RemoteController:

```python
net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink,
              autoSetMacs=True)
net.addController('c0', ip='127.0.0.1', port=6633)
# ...
net.addSwitch(f'c{i+1}', protocols='OpenFlow13',
              dpid=_dpid(0x10, i), failMode='secure')
```

`failMode='secure'` = switch **chỉ forward khi có controller**; nếu Ryu
sập, traffic dừng (đúng yêu cầu fail-secure cho testbed thật).

### 2.3 Khởi động (thứ tự bắt buộc)

```bash
# Bước 1: dựng sandbox netns + private OVS daemon
sudo scripts/start_single_server_testbed.sh

# Bước 2: start Ryu trong sandbox netns
sudo scripts/start_ryu_fastpath.sh --daemon

# Bước 3: launch Mininet fat-tree (sẽ tự connect tới Ryu)
sudo ip netns exec mn-sandbox env OVS_RUNDIR=/var/run/openvswitch-mn \
    python3 testbed/mininet/fat_tree_topology.py --remote &

# Bước 4: start frontend (root netns)
scripts/start_frontend.sh --daemon

# Bước 5: mở UI
xdg-open http://localhost:8088
```

Khi UI mở, bạn sẽ thấy:
- Fat-tree k=4 layout (4 core, 8 agg, 8 edge, 16 hosts)
- Sidebar trái: 8 nút S1..S8 + Reset
- Sidebar phải: metrics + event log

---

## 3. Chạy scenario qua UI

Click `S3 · SYN high` → backend POST `/api/scenario/S3` → `scripts/run_scenario.sh S3`:

1. `scenario_state.reset(scenario="S3", attacker="h0", victim="h15", attack_type="SYN_HIGH")`
2. UI cập nhật: h0 màu đỏ (attacker), h15 màu vàng (victim), đường đi
   h0→e0_0→a0_0→c1→a3_0→e3_1→h15 được tô đỏ dày
3. hping3 trong sandbox netns flood SYN
4. M1 sFlow → M2 features → M3 phát hiện tier=3
5. **Fast path**: Ryu nhận POST `/pad/tier`, install Flow-Mod `set_field
   ipv4_dst=10.244.5.42, output:NORMAL` (redirect tới scrubber) — UI hiển
   thị "Fast-path: redirect, 1 rule, 8 ms"
6. **Slow path**: CLAMP nhận POST, Policy eval, SO instantiate scrubber
   pod — UI hiển thị "Slow-path: clamp_received → ... → vnf_active, 2400 ms"
7. Metric "Attack pps" tăng vọt, "Drop pps" tăng theo, "Victim in pps" giảm
8. Sau 30s scenario tự dừng, Ryu rules clear, UI về trạng thái idle

Reset thủ công: nút **Reset / clear rules**.

---

## 4. REST API tham chiếu

| Path | Method | Mô tả |
|---|---|---|
| `/pad/topology` | GET (Ryu) | Switches + links + hosts (từ LLDP) |
| `/pad/flows` | GET (Ryu) | Rules fast-path đang installed |
| `/pad/stats` | GET (Ryu) | Snapshot MAC table + tier history |
| `/pad/tier` | POST (Ryu) | Push tier decision → Flow-Mod |
| `/pad/tier` | DELETE (Ryu) | Clear toàn bộ fast-path rules |
| `/api/topology` | GET (FastAPI) | Topology cho frontend (merge Ryu + fake) |
| `/api/state` | GET (FastAPI) | Scenario state snapshot |
| `/api/vnfs` | GET (FastAPI) | Kubectl probe VNF pods ở ns `pad-onap` |
| `/api/metrics` | GET (FastAPI) | Prometheus snapshot (best-effort) |
| `/api/scenario/{id}` | POST (FastAPI) | Trigger S1..S8 hoặc `stop` / `reset` |
| `/ws` | WS (FastAPI) | Live push state + topology mỗi 1s |

---

## 5. Integration vào pipeline

Trong `pipeline/s4_orchestration/orchestrator.py`, thay chỗ chỉ gọi DMaaP/
CLAMP bằng dual_path_publisher:

```python
from pipeline.s5_fastpath.dual_path_publisher import publish

# Sau khi M3 cho ra tier:
publish(src_ip=flow.src_ip, dst_ip=flow.dst_ip,
        tier=int(decision.tier), attack_type=decision.attack_type)
```

Hàm này **chạy song song** 2 path qua `ThreadPoolExecutor` và ghi cả 2
latency vào `scenario_state.json` để frontend đọc.

---

## 6. Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|---|---|---|
| UI không load topology | Ryu chưa start hoặc port 8080 unreachable | `curl http://10.99.99.2:8080/pad/topology` |
| Switches không connect Ryu | `failMode='standalone'` còn nguyên | Sửa thành `'secure'` |
| Tier POST trả 502 | Ryu chạy nhưng `--observe-links` thiếu | Restart với `--observe-links` |
| WebSocket close ngay | uvicorn không có `websockets` package | `pip install websockets` |
| `ip netns exec mn-sandbox` perm denied | Cần root | `sudo` |
| Mininet vẫn chạy nhưng frontend không thấy host | Frontend dùng fake topology mặc định — đúng | Click 1 scenario để verify path highlight |

---

## 7. Files đã tạo

```
pipeline/s5_fastpath/
  __init__.py
  tier_to_flowmod.py        # tier (0..4) → FlowDirective
  ryu_app.py                # Ryu app + REST API
  scenario_state.py         # /tmp/pad-onap/scenario_state.json
  dual_path_publisher.py    # publish() → Ryu + CLAMP đồng thời

frontend/
  requirements.txt          # fastapi, uvicorn, httpx
  backend.py                # FastAPI + WebSocket
  static/
    index.html              # 3-pane layout
    style.css               # dark theme
    app.js                  # Cytoscape.js + WS client

scripts/
  start_ryu_fastpath.sh     # ryu-manager trong sandbox netns
  start_frontend.sh         # uvicorn frontend.backend:app
  run_scenario.sh           # S1..S8 dispatcher

docs/
  RYU_FASTPATH_AND_FRONTEND.md   # file này
```
