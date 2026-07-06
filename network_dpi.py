"""
Deep Packet Inspection (DPI) Feature for Agentic Security Tool

Performs real-time packet analysis on live network traffic to detect:
- Suspicious C2/malware ports
- Large payload transfers
- Cleartext credentials
- DNS tunneling attempts
- Non-standard HTTP traffic

Uses scapy library for packet capture and analysis.
"""

from datetime import datetime
import json
import re


def run(send_event):
    """
    Execute Deep Packet Inspection on live network traffic.
    
    Args:
        send_event: Callback function to report suspicious findings
                   Signature: send_event(feature_name, priority, data_dict, severity)
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
    except ImportError:
        send_event(
            'network_dpi',
            25,
            {"error": "scapy not installed, DPI skipped"},
            "medium"
        )
        return

    # Configuration
    SUSPICIOUS_PORTS = {4444, 1337, 31337, 8080, 9001}
    LARGE_PAYLOAD_THRESHOLD = 9000
    DNS_SUBDOMAIN_THRESHOLD = 50
    TIMEOUT = 30
    PACKET_LIMIT = 200

    # Statistics tracking
    stats = {
        "total_packets": 0,
        "suspicious_count": 0,
        "threats": []
    }

    def is_cleartext_credentials(payload_str):
        """
        Check for common cleartext credential patterns in payload.
        
        Args:
            payload_str: Payload string to analyze
            
        Returns:
            tuple: (found: bool, credential_type: str)
        """
        try:
            patterns = {
                "password_field": r"password=",
                "passwd_field": r"passwd=",
                "basic_auth": r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"
            }
            
            for cred_type, pattern in patterns.items():
                if re.search(pattern, payload_str, re.IGNORECASE):
                    return True, cred_type
            
            return False, None
        except Exception:
            return False, None

    def check_dns_tunneling(dns_packet):
        """
        Check for DNS tunneling signs (long subdomain labels).
        
        Args:
            dns_packet: Scapy DNS packet object
            
        Returns:
            tuple: (suspicious: bool, long_label: str)
        """
        try:
            if not dns_packet.haslayer(DNSQR):
                return False, None
            
            qname = dns_packet[DNSQR].qname.decode('utf-8', errors='ignore')
            labels = qname.split('.')
            
            for label in labels:
                if len(label) > DNS_SUBDOMAIN_THRESHOLD:
                    return True, label
            
            return False, None
        except Exception:
            return False, None

    def process_packet(packet):
        """
        Analyze individual packet for suspicious activity.
        
        Args:
            packet: Scapy packet object
        """
        try:
            stats["total_packets"] += 1
            
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            timestamp = datetime.utcnow().isoformat() + "Z"
            
            # TCP Analysis
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload_size = len(packet[TCP].payload)
                
                # Check suspicious ports
                if dst_port in SUSPICIOUS_PORTS:
                    stats["suspicious_count"] += 1
                    stats["threats"].append("suspicious_c2_port")
                    send_event(
                        'network_dpi',
                        25,
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "reason": f"Suspicious port {dst_port} detected (known C2/malware port)",
                            "payload_size": payload_size,
                            "timestamp": timestamp
                        },
                        "high"
                    )
                
                # Check large payload
                if payload_size > LARGE_PAYLOAD_THRESHOLD:
                    stats["suspicious_count"] += 1
                    stats["threats"].append("large_payload")
                    send_event(
                        'network_dpi',
                        25,
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "reason": f"Large payload detected ({payload_size} bytes exceeds {LARGE_PAYLOAD_THRESHOLD} threshold)",
                            "payload_size": payload_size,
                            "timestamp": timestamp
                        },
                        "medium"
                    )
                
                # Check cleartext credentials
                if packet.haslayer(Raw):
                    try:
                        payload_str = packet[Raw].load.decode('utf-8', errors='ignore')
                        has_creds, cred_type = is_cleartext_credentials(payload_str)
                        
                        if has_creds:
                            stats["suspicious_count"] += 1
                            stats["threats"].append("cleartext_credentials")
                            send_event(
                                'network_dpi',
                                25,
                                {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": "TCP",
                                    "reason": f"Cleartext credentials detected ({cred_type})",
                                    "payload_size": payload_size,
                                    "timestamp": timestamp
                                },
                                "critical"
                            )
                    except Exception:
                        pass
                
                # Check non-standard HTTP
                if dst_port in {80, 443, 8080} or src_port in {80, 443, 8080}:
                    if packet.haslayer(Raw):
                        try:
                            payload_str = packet[Raw].load.decode('utf-8', errors='ignore')
                            if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                                # HTTP traffic detected
                                if dst_port not in {80, 443}:
                                    stats["suspicious_count"] += 1
                                    stats["threats"].append("nonstandard_http")
                                    send_event(
                                        'network_dpi',
                                        25,
                                        {
                                            "src_ip": src_ip,
                                            "dst_ip": dst_ip,
                                            "src_port": src_port,
                                            "dst_port": dst_port,
                                            "protocol": "TCP",
                                            "reason": f"HTTP traffic on non-standard port {dst_port}",
                                            "payload_size": payload_size,
                                            "timestamp": timestamp
                                        },
                                        "low"
                                    )
                        except Exception:
                            pass
            
            # UDP Analysis
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload_size = len(packet[UDP].payload)
                
                # Check suspicious ports
                if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
                    stats["suspicious_count"] += 1
                    stats["threats"].append("suspicious_c2_port")
                    suspicious_port = dst_port if dst_port in SUSPICIOUS_PORTS else src_port
                    send_event(
                        'network_dpi',
                        25,
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "UDP",
                            "reason": f"Suspicious port {suspicious_port} detected (known C2/malware port)",
                            "payload_size": payload_size,
                            "timestamp": timestamp
                        },
                        "high"
                    )
                
                # Check large payload
                if payload_size > LARGE_PAYLOAD_THRESHOLD:
                    stats["suspicious_count"] += 1
                    stats["threats"].append("large_payload")
                    send_event(
                        'network_dpi',
                        25,
                        {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": "UDP",
                            "reason": f"Large payload detected ({payload_size} bytes exceeds {LARGE_PAYLOAD_THRESHOLD} threshold)",
                            "payload_size": payload_size,
                            "timestamp": timestamp
                        },
                        "medium"
                    )
                
                # Check DNS tunneling (DNS uses UDP port 53)
                if dst_port == 53 or src_port == 53:
                    if packet.haslayer(DNS):
                        is_tunneling, long_label = check_dns_tunneling(packet[DNS])
                        if is_tunneling:
                            stats["suspicious_count"] += 1
                            stats["threats"].append("dns_tunneling")
                            send_event(
                                'network_dpi',
                                25,
                                {
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": "DNS",
                                    "reason": f"DNS tunneling signs detected (subdomain label length: {len(long_label)} chars)",
                                    "payload_size": payload_size,
                                    "timestamp": timestamp
                                },
                                "high"
                            )
        
        except Exception:
            pass

    try:
        # Perform packet capture
        sniff(
            prn=process_packet,
            store=False,
            timeout=TIMEOUT,
            iface=None,  # Use default interface
            count=PACKET_LIMIT
        )
    except PermissionError:
        send_event(
            'network_dpi',
            25,
            {"error": "Insufficient permissions for packet capture (requires root/admin)"},
            "medium"
        )
        return
    except Exception as e:
        send_event(
            'network_dpi',
            25,
            {"error": f"Packet capture error: {str(e)}"},
            "medium"
        )
        return

    # Send summary event
    top_threat = max(set(stats["threats"]), key=stats["threats"].count) if stats["threats"] else "none"
    
    send_event(
        'network_dpi_summary',
        25,
        {
            "total_packets": stats["total_packets"],
            "suspicious_count": stats["suspicious_count"],
            "top_threat": top_threat
        },
        'info'
    )


if __name__ == "__main__":
    def mock_send(event_type, feature_id, data, severity):
        """Mock send_event for testing without live network capture."""
        print(f"[{severity.upper()}] Event: {event_type} | Feature: {feature_id}")
        print(json.dumps(data, indent=2))
    
    run(mock_send)
