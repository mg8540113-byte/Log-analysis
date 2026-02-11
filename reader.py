import csv
# קריאת קובץ הלוגים - מקבלת כפרמטר את הנתיב
def log_file_format(path):
    with open(path, "r") as log_file:
        list_log = [line for line in csv.reader(log_file)]
        return list_log





