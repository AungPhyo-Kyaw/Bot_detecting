
import re
from collections import defaultdict

# Path to the log file
logFile = "sample-log.log"

# Pattern to extract IP, endpoint, and status code
logPattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+[A-Z]{2}\s+-\s+\[[^\]]+\]\s+"(?:GET|POST)\s(?P<endpoint>[^"]+)\sHTTP/1.1"\s(?P<status>\d+)'
)
#Threshold to get flag as supscious ip
highRequestThreshould = 50
error404Threshould = 10
APIAccessThreshould = 5

#Tracking the count of each ip
requestCount = defaultdict(int)
error404Count = defaultdict(int)
apiAccessCount = defaultdict(int)

# Reading and analyzing the log 
with open(logFile, 'r') as f:
    for line in f:
        match = logPattern.search(line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = int(match.group("status"))

            requestCount[ip] += 1
            if status == 404:
                error404Count[ip] += 1
            if "/api/" in endpoint:
                apiAccessCount[ip] += 1

# Flagging the suspicious IPs based on the analyxing log
print("Suspicious IPs are:")
for ip in requestCount:
    reasons = []
    if requestCount[ip] > 50:
        reasons.append("High request count")
    if error404Count[ip] > 10:
        reasons.append("Frequent 404 errors")
    if apiAccessCount[ip] > 5:
        reasons.append("Repeated access to api/endpoints")
    if reasons:
        print(f"{ip}: {', '.join(reasons)}")
