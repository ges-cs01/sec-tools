#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests

API_KEY = "<YOUR_API_KEY>"
HOOK_URL = "<HOOK_URL>" 
CUSTOMER_ID = 1 # Specific - maybe need to change

def main():
    if len(sys.argv) < 2:
        return

    alert_file = sys.argv[1]
    
    try:
        with open(alert_file, 'r') as f:
            content = f.read().strip()
        if not content:
            return
        if '\n' in content:
            content = content.split('\n')[0]
        
        alert_json = json.loads(content)

    except json.JSONDecodeError:
        with open('/tmp/wazuh_bad_alert.log', 'a') as debug_f:
            debug_f.write(f"Malformed content at char 0: {content}\n")
        return
    except Exception as e:
        return

    lvl = alert_json.get("rule", {}).get("level", 0)
    severity = 1 if lvl < 5 else 3 if lvl < 10 else 5

    payload = {
        "alert_title": alert_json.get("rule", {}).get("description"),
        "alert_description": f"Wazuh Alert: {alert_json.get('full_log')}",
        "alert_source": "Wazuh",
        "alert_severity_id": severity,
        "alert_status_id": 1,
        "alert_customer_id": CUSTOMER_ID,
        "alert_source_content": alert_json
    }

    response = requests.post(HOOK_URL, json=payload, headers={"Authorization": f"Bearer {API_KEY}"}, verify=False)
    print(f"Status Code: {response.status_code}")
    print(f"Response Text: {response.text}")

if __name__ == "__main__":
    main()
