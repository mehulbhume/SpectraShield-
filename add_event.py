import sqlite3

conn = sqlite3.connect('edr_database.db')
conn.execute("""
    INSERT INTO events (hostname, event_type, feature_id, severity, mitre_id, mitre_technique, timestamp, data)
    VALUES ('AaruPC', 'firewall_rule_applied', 15, 'info', 'T1562.004', 'Impair Defenses', '2026-06-27T20:21:00', '{}')
""")
conn.commit()
conn.close()
print('Event added!')