#!/usr/bin/env python3
"""
PAD-ONAP: Real NetFlow E2E Evaluation Pipeline
==============================================
So sánh hiệu năng AI (Proactive) vs Threshold (Reactive) trên Mininet.
Dữ liệu được trích xuất từ packet thật (softflowd) và chạy qua 2 bộ điều phối.
"""
import os, sys, time, json, threading, logging, argparse
from pathlib import Path
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt

# Thêm đường dẫn gốc vào python path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from pipeline.s4_orchestration.orchestrator import Orchestrator
from evaluation.baseline_threshold import BaselineOrchestrator
from testbed.netflow_collector.collector import parse_netflow_v5, FlowFeatureExtractor

# Thiết lập log
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('E2E_Eval')

class E2EEvaluator:
    def __init__(self, args):
        self.args = args
        self.results_ai = []
        self.results_base = []
        self.timestamps = []
        self.stop_event = threading.Event()
        
        # 1. Khởi tạo 2 bộ não xử lý (AI và Ngưỡng tĩnh)
        # Tắt shap_enabled để đảm bảo xử lý real-time mượt mà trên Mininet
        self.ai_orch = Orchestrator(
            model_dir=args.model_dir, 
            data_dir=args.data_dir, 
            eval_mode=True,
            shap_enabled=args.shap, # Bật/tắt dựa trên tham số dòng lệnh
            latency_port=9298
        )
        self.base_orch = BaselineOrchestrator(
            eval_mode=True,
            latency_port=9299
        )

    def _run_orchestration(self, x_raw):
        """Chạy song song 2 orchestrator trên cùng 1 vector đặc trưng"""
        res_ai = self.ai_orch._step(x_raw)
        res_base = self.base_orch._step(x_raw)
        
        self.results_ai.append(res_ai['tier'])
        self.results_base.append(res_base['tier'])
        self.timestamps.append(time.time())
        
        print(f"Window {len(self.results_ai):03d} | AI: T{res_ai['tier']} ({'Proactive' if res_ai['proactive'] else 'Normal'}) | Base: T{res_base['tier']}")

    def run_mininet_test(self):
        # Import Mininet bên trong để tránh lỗi trên Windows nếu chỉ check code
        from mininet.net import Mininet
        from testbed.mininet.fat_tree_topology import build_fat_tree, attacker_victim
        
        logger.info(f"*** Khởi tạo Mininet Fat-Tree k={self.args.k}")
        net = build_fat_tree(k=self.args.k)
        net.start()
        time.sleep(3) # Đợi mạng ổn định
        
        attacker, victim = attacker_victim(net)
        logger.info(f"*** Attacker: {attacker.name} -> Victim: {victim.name}")
        
        # Bật softflowd trên tất cả host để xuất packet thật thành NetFlow v5
        logger.info("*** Khởi động softflowd trên các hosts...")
        for host in net.hosts:
            host.cmd(f'softflowd -i {host.intf().name} -n 127.0.0.1:6343 -v 5 -d &')
        
        # Bộ trích xuất đặc trưng từ packet UDP 6343
        extractor = FlowFeatureExtractor(window_sec=5.0)
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 6343))
        sock.settimeout(1.0)

        logger.info(">>> Phase 1: Baseline (Normal traffic) - 30 giây")
        t_start = time.time()
        while time.time() - t_start < 30:
            self._collect_and_step(sock, extractor)

        logger.info(f">>> Phase 2: UDP Flood Attack - {self.args.duration} giây")
        # Sử dụng hping3 flood thật sự
        attacker.cmd(f'hping3 --udp --flood -p 80 {victim.IP()} &')
        t_attack = time.time()
        while time.time() - t_attack < self.args.duration:
            self._collect_and_step(sock, extractor)

        logger.info(">>> Phase 3: Recovery (Ngừng tấn công) - 20 giây")
        attacker.cmd('pkill hping3')
        t_stop = time.time()
        while time.time() - t_stop < 20:
            self._collect_and_step(sock, extractor)

        logger.info("*** Kết thúc kiểm thử. Dừng Mininet.")
        net.stop()
        sock.close()
        self.generate_report()

    def _collect_and_step(self, sock, extractor):
        """Hứng NetFlow packets và đẩy vào AI mỗi khi đủ cửa sổ thời gian"""
        try:
            data, _ = sock.recvfrom(65535)
            flows = parse_netflow_v5(data)
            if flows:
                extractor.add_flows(flows)
        except socket.timeout:
            pass
        
        # Kiểm tra nếu đã đến lúc tính toán feature window (mỗi 5s)
        # Chúng ta dùng một biến đếm window đơn giản dựa trên thời gian
        now = time.time()
        if not hasattr(self, '_last_compute'): self._last_compute = now
        
        if now - self._last_compute >= 5.0:
            vec = extractor.compute()
            if vec:
                x = np.array([vec['features'][k] for k in vec['feature_names']], dtype=np.float32)
                self._run_orchestration(x)
            self._last_compute = now

    def generate_report(self):
        out_dir = _ROOT / 'evaluation' / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Vẽ biểu đồ so sánh Response Tier
        plt.figure(figsize=(12, 6))
        x_axis = np.arange(len(self.results_ai)) * 5 # Mỗi window 5s
        
        plt.step(x_axis, self.results_ai, label='AI-Augmented (Proactive)', color='#1f77b4', linewidth=2, where='post')
        plt.step(x_axis, self.results_base, label='Threshold-based (Reactive)', color='#d62728', linestyle='--', linewidth=2, where='post')
        
        plt.title('DDoS Response Comparison: Real Mininet Traffic', fontsize=14)
        plt.xlabel('Time (seconds)', fontsize=12)
        plt.ylabel('Response Tier (T0-T4)', fontsize=12)
        plt.yticks([0, 1, 2, 3, 4], ['T0:Normal', 'T1:Alert', 'T2:Preempt', 'T3:Mitigate', 'T4:Block'])
        plt.legend(loc='upper left')
        plt.grid(True, linestyle=':', alpha=0.6)
        
        # Đánh dấu thời điểm tấn công (giả định bắt đầu ở giây thứ 30)
        plt.axvline(x=30, color='gray', linestyle='-.', alpha=0.5)
        plt.text(31, 0.5, 'Attack Start', color='gray', rotation=0)

        img_path = out_dir / f'real_e2e_comparison_{ts}.png'
        plt.savefig(img_path, dpi=300)
        logger.info(f"[✓] Biểu đồ so sánh đã lưu: {img_path}")
        
        # 2. Xuất số liệu JSON để hậu xử lý
        report_data = {
            'timestamp': ts,
            'config': {'k': self.args.k, 'duration': self.args.duration},
            'series': {
                'ai_tiers': self.results_ai,
                'base_tiers': self.results_base,
                'time_axis': x_axis.tolist()
            }
        }
        json_path = out_dir / f'real_e2e_data_{ts}.json'
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        logger.info(f"[✓] Dữ liệu JSON đã lưu: {json_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PAD-ONAP: Real NetFlow E2E Evaluation')
    parser.add_argument('--k', type=int, default=4, help='Fat-tree k-factor')
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')
    parser.add_argument('--model-dir', default=str(_ROOT/'pad_onap_v3'/'models'))
    parser.add_argument('--data-dir', default=str(_ROOT/'pad_onap_v3'/'processed'))
    parser.add_argument('--shap', action='store_true', help='Enable SHAP explainability (slows down processing)')
    args = parser.parse_args()
    
    # Check root
    if os.name != 'nt' and os.geteuid() != 0:
        print("\n[!] ERROR: Script này phải chạy bằng 'sudo' để khởi tạo Mininet.\n")
        sys.exit(1)
        
    evaluator = E2EEvaluator(args)
    try:
        evaluator.run_mininet_test()
    except KeyboardInterrupt:
        logger.info("Dừng script bởi người dùng.")
        os.system('sudo mn -c')
