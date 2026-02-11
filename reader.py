import csv

def log_file_format():
    with open("./network_traffic.log", "r") as log_file:
        list_log = [line for line in csv.reader(log_file)]
        return list_log



def IP_detection_from_an_external_source(list_log):
    list_ip = [row[1] for row in list_log if row[1][0:2] != "10" and row[1][0:7] != "192.168"]
    return list_ip


