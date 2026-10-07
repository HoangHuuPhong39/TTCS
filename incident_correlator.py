"""
incident_correlator.py - Gom các alert Wazuh thành "Incident" trước khi lưu trữ hoặc gọi LLM.
Phiên bản Thread-safe thiết kế tối ưu cho kiến trúc Flask / WSGI.

Cơ chế:
1. Gom theo IP nguồn (data.srcip / data.win.eventdata.ipAddress). Nếu không có IP thì gom theo host (agent.name).
2. Debounce Timer: Khi có alert mới, gia hạn timer thêm DEBOUNCE_SECONDS (mặc định 20s).
   Nếu sau khoảng này không có alert mới phát sinh từ cùng nguồn -> chốt incident.
3. Max Duration: Nếu đợt tấn công kéo dài quá MAX_INCIDENT_DURATION_SECONDS (10 phút) -> ép chốt để tránh treo dữ liệu.
4. Trả về Context tổng hợp gồm: alert đại diện (level cao nhất), danh sách rule liên quan, số lượng alert, khoảng thời gian.
"""

import os
import threading
import logging
from datetime import datetime, timedelta
from typing import Callable, Optional

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_SECONDS = int(os.getenv("INCIDENT_WINDOW_SECONDS", "300"))
DEBOUNCE_SECONDS = int(os.getenv("INCIDENT_DEBOUNCE_SECONDS", "20"))
MAX_INCIDENT_DURATION_SECONDS = int(os.getenv("INCIDENT_MAX_SECONDS", "600"))
MAX_SAMPLE_ALERTS = 5

_IGNORED_IPS = {"", "-", "::1", "127.0.0.1", "0.0.0.0"}


def _now() -> datetime:
    return datetime.now()


def extract_ip(alert: dict) -> Optional[str]:
    data = alert.get("data") or {}
    ip = data.get("srcip") or ((data.get("win") or {}).get("eventdata") or {}).get("ipAddress")
    if ip and str(ip).strip() not in _IGNORED_IPS:
        return str(ip).strip()
    return None


def extract_key(alert: dict) -> str:
    ip = extract_ip(alert)
    if ip:
        return ip
    agent_name = (alert.get("agent") or {}).get("name") if isinstance(alert.get("agent"), dict) else alert.get("agent", "unknown")
    return f"host:{agent_name}"


class Incident:
    def __init__(self, key: str, first_alert: dict):
        self.key = key
        self.alerts: list[dict] = [first_alert]
        self.first_seen = _now()
        self.last_seen = self.first_seen
        self.timer: Optional[threading.Timer] = None
        self.deadline: Optional[datetime] = None

    def add_alert(self, alert: dict) -> None:
        self.alerts.append(alert)
        self.last_seen = _now()

    def is_expired_by_max_duration(self) -> bool:
        return (_now() - self.first_seen).total_seconds() >= MAX_INCIDENT_DURATION_SECONDS

    def to_context(self) -> dict:
        rules = []
        for a in self.alerts:
            r = a.get("rule")
            if isinstance(r, dict):
                rules.append(r)
            elif "rule_id" in a:
                rules.append({"id": a.get("rule_id"), "description": a.get("description"), "level": a.get("level", 0)})

        # Chọn alert đại diện có rule level cao nhất
        def get_lvl(a):
            if isinstance(a.get("rule"), dict):
                return a.get("rule", {}).get("level", 0)
            return a.get("level", 0)

        top_alert = max(self.alerts, key=get_lvl)
        rule_ids = sorted({str(r.get("id")) for r in rules if r.get("id")})
        rule_descs = sorted({r.get("description") for r in rules if r.get("description")})
        
        target_hosts = set()
        for a in self.alerts:
            ag = a.get("agent")
            name = ag.get("name") if isinstance(ag, dict) else ag
            if name:
                target_hosts.add(str(name))

        return {
            "key": self.key,
            "source_ip": None if self.key.startswith("host:") else self.key,
            "alert_count": len(self.alerts),
            "rule_ids": rule_ids,
            "rule_descriptions": rule_descs,
            "target_hosts": sorted(target_hosts),
            "max_level": max((r.get("level", 0) for r in rules), default=0),
            "first_seen": self.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            "last_seen": self.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_seconds": int((self.last_seen - self.first_seen).total_seconds()),
            "top_alert": top_alert,
            "sample_alerts": self.alerts[-MAX_SAMPLE_ALERTS:],
        }


class IncidentCorrelator:
    def __init__(self, on_incident_ready: Optional[Callable[[dict], None]] = None):
        self._incidents: dict[str, Incident] = {}
        self._lock = threading.Lock()
        self._on_incident_ready = on_incident_ready

    def ingest(self, alert: dict) -> dict:
        """
        Nạp alert vào correlator:
        - Nếu sự cố đã quá max duration -> chốt ngay
        - Ngược lại -> đặt / gia hạn debounce timer
        Trả về thông tin tóm tắt.
        """
        key = extract_key(alert)
        now = _now()

        with self._lock:
            incident = self._incidents.get(key)
            if incident and (now - incident.last_seen).total_seconds() <= CORRELATION_WINDOW_SECONDS:
                incident.add_alert(alert)
            else:
                incident = Incident(key, alert)
                self._incidents[key] = incident

            # Hủy timer cũ nếu có
            if incident.timer and incident.timer.is_alive():
                incident.timer.cancel()

            # Kiểm tra thời gian tối đa
            if incident.is_expired_by_max_duration():
                self._finalize_locked(key)
                return {"status": "finalized", "key": key, "reason": "max_duration_reached"}

            # Tạo timer mới cho debounce
            incident.deadline = now + timedelta(seconds=DEBOUNCE_SECONDS)
            t = threading.Timer(DEBOUNCE_SECONDS, self._on_timer_fired, args=[key])
            t.daemon = True
            incident.timer = t
            t.start()

            return {
                "status": "grouped",
                "key": key,
                "current_count": len(incident.alerts),
                "seconds_left": DEBOUNCE_SECONDS
            }

    def _on_timer_fired(self, key: str):
        with self._lock:
            self._finalize_locked(key)

    def _finalize_locked(self, key: str):
        incident = self._incidents.pop(key, None)
        if incident is None:
            return

        if incident.timer and incident.timer.is_alive():
            incident.timer.cancel()

        ctx = incident.to_context()
        logger.info(f"[+] Incident chốt: Nguồn {key} ({ctx['alert_count']} cảnh báo, max level {ctx['max_level']})")

        if self._on_incident_ready:
            try:
                # Chạy callback trong luồng riêng để không block lock
                threading.Thread(target=self._on_incident_ready, args=[ctx], daemon=True).start()
            except Exception as e:
                logger.error(f"[!] Lỗi khi gọi callback incident {key}: {e}")

    def status(self) -> list:
        """Lấy danh sách các incident đang trong cửa sổ gom nhóm."""
        now = _now()
        with self._lock:
            result = []
            for inc in self._incidents.values():
                secs_left = max(0, int((inc.deadline - now).total_seconds())) if inc.deadline else 0
                result.append({
                    "key": inc.key,
                    "alert_count": len(inc.alerts),
                    "seconds_left": secs_left,
                    "first_seen": inc.first_seen.strftime('%H:%M:%S'),
                    "last_seen": inc.last_seen.strftime('%H:%M:%S'),
                })
            return result
