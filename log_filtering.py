import re
import json
from queries import supabase

# ==============================
# Fetch Data from Supabase
# ==============================
def fetch_logs():
    try:
        response = supabase.table("asset_logs").select("*").execute()
        return response.data
    except Exception as e:
        print(f"Database Error: {e}")
        return []

# ==============================
# Regex Search
# Searches asset_name, event,
# message and source
# ==============================
def regex_search(data, pattern):
    if not pattern:
        return data

    try:
        results = []

        for log in data:
            text = (
                str(log.get("asset_name", "")) + " " +
                str(log.get("event", "")) + " " +
                str(log.get("message", "")) + " " +
                str(log.get("source", ""))
            )

            if re.search(pattern, text, re.IGNORECASE):
                results.append(log)

        return results

    except re.error:
        print("Invalid Regular Expression")
        return []

# ==============================
# Filtering
# ==============================
def filter_logs(data, severity=None, event=None, status=None):

    filtered = data

    if severity:
        filtered = [
            log for log in filtered
            if str(log.get("severity", "")).lower() == severity.lower()
        ]

    if event:
        filtered = [
            log for log in filtered
            if str(log.get("event", "")).lower() == event.lower()
        ]

    if status:
        filtered = [
            log for log in filtered
            if str(log.get("current_status", "")).lower() == status.lower()
        ]

    return filtered

# ==============================
# Pagination
# ==============================
def paginate(data, page=1, limit=10):

    if page < 1:
        page = 1

    if limit < 1:
        limit = 10

    start = (page - 1) * limit
    end = start + limit

    return {
        "page": page,
        "limit": limit,
        "total_records": len(data),
        "results": data[start:end]
    }

# ==============================
# Main
# ==============================
if __name__ == "__main__":

    logs = fetch_logs()

    print("\n===== Monitoring History Search =====\n")

    pattern = input("Regex Search (press Enter to skip): ").strip()

    severity = input("Severity (High/Medium/Low): ").strip()
    if severity == "":
        severity = None

    event = input("Event (NEW_ASSET/REMOVED_ASSET/STATUS_CHANGED): ").strip()
    if event == "":
        event = None

    status = input("Current Status (active/inactive): ").strip()
    if status == "":
        status = None

    page = int(input("Page Number (default 1): ") or 1)
    limit = int(input("Records Per Page (default 10): ") or 10)
    # Search
    logs = regex_search(logs, pattern)

    # Filter
    logs = filter_logs(logs, severity, event, status)

    # Pagination
    output = paginate(logs, page, limit)

    print("\n===== JSON Output =====\n")
    print(json.dumps(output, indent=4, default=str))