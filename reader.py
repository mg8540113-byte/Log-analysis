import csv
# ייצוא כל הלוגים לתוך מטריצה
def log_file_format():
    with open("./network_traffic.log", "r") as log_file:
        list_log = [line for line in csv.reader(log_file)]
        return list_log


# החזרת כל כתובות ה IP ממקור חיצוני
def IP_detection_from_an_external_source(list_log):
    list_ip = [row[1] for row in list_log if row[1][0:3] != "10." and row[1][0:7] != "192.168"]
    return list_ip


# בדיקת כניסות מפורטים מסוכנים, מחזיר את כל השורה, מקבל את כל המטריצה
def identifying_dangerous_port(list_log):
    list_port = [row for row in list_log if row[3] in ["23", "22", "3389"]]
    return list_port

# סינון רשימות עם תעבורה גדולה מ 5000
def packet_filtering_5000(list_log):
    list_large = [row for row in list_log if int(row[5]) > 5000]
    return list_large

# הוספת תגית לכל שורה אם גדול מ 5000 או קטן
def normal_large_tick(list_log ):
    list_tick = [row + ["Normal"] if int(row[5]) <= 5000 else row + ["Large"]for row in list_log]
    return list_tick


def number_of_IP_instances(list_log):
    list_ip = [row[1] for row in list_log]
    num_ip = {ip: list_ip.count(ip) for ip in set(list_ip)}
    return num_ip


# יצוא מילון עם מספר פורט והפרוטוקול שלו
def protocol_check(list_log):
    dict_port_protocol = {row[3]: row[4] for row in list_log}
    return dict_port_protocol



# סינון כתובות עם סכונים
def List_risks(list_log):
    dict_risks = {}
    for row in list_log:
        tast = []
        if row[0][11:13] in ["00","01","02","03","04","05"]:
            tast.append("NIGHT_ACTIVITY")
        if int(row[5]) > 5000:
            tast.append("LARGE_PACKET")
        if row[3] in ["23", "22", "3389"]:
            tast.append("SENSITIVE_PORT")
        if row[1][0:3] != "10." and row[1][0:7] != "192.168":
            tast.append("EXTERNAL_IP")
        if len(tast) == 0:
            continue
        if row[1] in dict_risks:
            dict_risks[row[1]] += (tast)
            dict_risks[row[1]] = set(dict_risks[row[1]])
            dict_risks[row[1]] = list(dict_risks[row[1]])
        else:
            dict_risks[row[1]] = tast
    return dict_risks



def addresses_with_two_risks(dict_risks):
    dict_two_risks = {}
    for key, value in dict_risks.items():
        if len(value) >= 2:
            dict_two_risks[key] = value
    return dict_two_risks

    







        