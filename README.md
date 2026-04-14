# PAD-ONAP: AI-Augmented NFV Orchestration for Proactive DDoS Defense

Hệ thống phát hiện và phòng thủ DDoS chủ động dựa trên AI kết hợp NFV/ONAP trong Cloud Data Center.

---

## 1. Cấu trúc Dự án & Hiệu năng Mô hình

```text
Src_2/
├── testbed/              # Hạ tầng mô phỏng mạng (gNMI, NetFlow, Mininet, Docker Stack)
├── pipeline/             # Mạch AI Inference (XGBoost, Transformer+LSTM, AI Output)
├── pad_onap_v3/          # Checkpoint Models đã train (XGBoost 4-class, TF_V3, Scaler)
└── scripts/              # Kịch bản tự động kiểm thử
```

**Hiệu năng (CICDDoS2019):**  
XGBoost 4-class (Accuracy 90.6%, AUC 99.1%); Transformer+LSTM (AUC h0: 99.4%, rớt chậm chỉ ~0.29%/horizon). Detect 17 đặc trưng (window=100s, step=50s).

---

## 2. Hướng dẫn Cài đặt & Chuẩn bị

**Yêu cầu hệ thống:** Python 3.9+, Docker Compose >= 2.0.
```bash
# Cài đặt thư viện Python lõi
pip install xgboost torch shap pandas scikit-learn prometheus-client
```

---

## 3. Chạy Toàn bộ Pipeline (End-to-End)

Luồng chạy bao gồm: **Testbed (Sinh dữ liệu/giả lập mạng)** ➜ **Bộ Collector (Gom Netflow)** ➜ **Live Pipeline (Chạy AI Inference)**.

### Cách A: Chạy qua Docker Compose (Khuyên dùng)
Cách này tự động bật tất cả các service nền (gNMI, Netflow Collector, Prometheus, Grafana).
```bash
# 1. Bật Testbed Background Stack
cd testbed
docker compose up -d

# 2. Quay lại thư mục gốc, bật Live AI Inference (kết nối vào Testbed)
cd ..
python pipeline/s3_ai/live_pipeline.py \
    --collector http://localhost:7070 \
    --model-dir ./pad_onap_v3/models \
    --data-dir  ./pad_onap_v3/processed \
    --interval  1.0
```

*(Dashboard Grafana giám sát có sẵn tại `http://localhost:3000`)*

### Cách B: Chạy chay (Windows Terminal / Không Docker)
Mở 3 Terminal riêng biệt tại thư mục gốc:
```bash
# Terminal 1: Bật gNMI Simulator giả lập thiết bị
python testbed/gnmi_simulator/main.py

# Terminal 2: Bật NetFlow Collector (synthetic mode kéo từ gNMI)
python testbed/netflow_collector/collector.py --mode synthetic --gnmi http://localhost:8080 --interval 1.0

# Terminal 3: Chạy Live AI Pipeline
python pipeline/s3_ai/live_pipeline.py --collector http://localhost:7070 --model-dir ./pad_onap_v3/models --data-dir ./pad_onap_v3/processed --interval 1.0
```

---

## 4. Tương tác & Giả lập Tấn Công (Anomaly Injector)

Khi Live Pipeline đang chạy, mở thêm 1 terminal để bơm tấn công DDoS ngẫu nhiên:

```bash
# Chọn kịch bản tấn công (udp_flood, syn_flood, bw_ramp, cpu_spike)
curl -X POST http://localhost:8080/attack/start \
     -H "Content-Type: application/json" -d '{"type":"udp_flood","target":"r1"}'

# Dừng tấn công
curl -X POST http://localhost:8080/attack/stop -H "Content-Type: application/json" -d '{}'
```
Bạn sẽ thấy `live_pipeline` trên Terminal ngay lập tức phát hiện Tier 3/4 và xuất Proactive Forecast đi kèm SHAP top-features JSON payload.

---

## 5. Inference Độc lập / Testing (AI Developers)

Khảo nghiệm model offline trên tệp test lớn mà không cần testbed.
```bash
# Replay toàn bộ test-set để ghi file JSON phân tích:
python pipeline/s3_ai/inference_layer.py --model-dir ./pad_onap_v3/models --data-dir ./pad_onap_v3/processed --n-samples 500 --out ./pad_onap_v3/models/inference_results.json
```

**Sử dụng trực tiếp qua Code:**
```python
import numpy as np
from pipeline.s3_ai.inference_layer import InferenceEngine

# Auto-mount model
engine = InferenceEngine.load(model_dir='./pad_onap_v3/models', data_dir='./pad_onap_v3/processed', shap_enabled=True)

# Fake array 17 features 
features = np.random.rand(17).astype(np.float32) 
print(engine.infer(features))  # Trả về payload json với AttackType, Tier, Forecast
```

---

## 6. Lỗi thường gặp (Troubleshooting)

1. **Lỗi `Address already in use` (Port 8080 / 7070)**: 
   - Có thể service cũ chưa tắt hẳn. Đổi port qua params `--port 8081` nếu chạy chay, hoặc `docker compose down` trước khi up lại.
2. **Lỗi `Connection refused` Collector đến gNMI**: 
   - Trong Docker, hãy dùng cấu hình kết nối container `--gnmi http://gnmi-simulator:8080` thay vì localhost.
3. **Inference báo thiếu file Models**: 
   - `pad_onap_v3/models/` bắt buộc phải có đủ 4 file gồm: `xgboost_v3.json`, `transformer_v3.pt`, `scaler.pkl`, `tf_best_config.json`.

---

## 7. Tích hợp lên Môi trường ONAP Thực tế (Phase 3 & 4)

Sau khi kiểm thử Local bằng Live Pipeline thành công, hệ thống đã sẵn sàng để tích hợp vào luồng Orchestration thực tế của ONAP Server (M3/M4). 
Kiến trúc decoupled qua object `AIOutputPayload` đảm bảo tính "Plug-and-Play" mà không cần sửa core AI.

**Bước 1: Bật DMaaP Publisher**
ONAP Policy/CLAMP nhận cảnh báo qua bus DMaaP (Data Movement as a Platform). Bạn chỉ cần:
- Expose script `live_pipeline.py` đẩy `AIOutputPayload` dưới dạng POST request thay vì `print` ra console.
- Thay đổi biến môi trường trỏ thẳng vào IP của ONAP Server (VD: `http://<onap-ip>:3904/events/unauthenticated.DCAE_CL_OUTPUT/`).

**Bước 2: Cấu hình ONAP Policy (Bắt sự kiện phân tầng)**
Dữ liệu nhả ra từ AI Pipeline đã tuân thủ chuẩn tự động điều phối **5-Tier Response**:
- **T0**: Mạng lưới an toàn, bỏ qua.
- **T1 / T2**: Cảnh báo sớm (Proactive) / Kích hoạt standby VNF Firewall.
- **T3**: Scale-out VNF Scrubber qua SDNC để hứng traffic.
- **T4**: Bóp băng thông hoặc Blackhole khẩn cấp (Sustained attack).

*Lưu ý: Không cần thiết lập lại hay thay đổi thuật toán ở M2 Inference Layer. Mọi quyết định kéo thả/Scale VNF đều dựa vào chỉ số `Response Tier` đã được Map từ giá trị Dự báo & Độ tin cậy của AI.*
