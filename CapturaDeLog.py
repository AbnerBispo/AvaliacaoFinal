import csv
import win32evtlog

server = 'localhost'
log_type = 'Security'
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

events = win32evtlog.OpenEventLog(server, log_type)

with open('logs_login_falhos.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Time', 'EventID', 'Source', 'Mensagem'])

    total = 0
    while total < 50:
        logs = win32evtlog.ReadEventLog(events, flags, 0)
        if not logs:
            break
        for event in logs:
            if event.EventID == 4625:  # Login falho
                time = event.TimeGenerated.Format()
                msg = ' | '.join(str(i) for i in event.StringInserts) if event.StringInserts else 'Sem detalhes'
                writer.writerow([time, event.EventID, event.SourceName, msg])
                total += 1
