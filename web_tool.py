from dotenv import *
import requests as rq
import time
import sys
from logo import logo
import os
from json import *
import tkinter as tk
from tkinter import messagebox

root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)
if __name__ == "__main__":
    try:


        def clear_screen():
            os.system("cls" if os.name == "nt" else "clear")
        print(f"{logo}")
        user_web = input(f"{"\n" * 2}Please Enter The Web Domin: ")
        xcv = user_web
        choices = int(input("1 - SubDomains\n2 - Webinfo\n"))
        if choices != 1 and choices != 2:
            raise Exception("")
        print(f"{"\n" * 3}Getting the info", end="")


        start_time = time.time()
        while time.time() - start_time < 19:
            for i in range(4):
                if time.time() - start_time >= 17:
                    break
                sys.stdout.write("\rGetting the info" + "." * i + " " * (4 - i))
                sys.stdout.flush()
                time.sleep(0.5)



        # API KEYS
        load_dotenv()
        ip_key = os.getenv("ip")
        g_sub_key = os.getenv("dom")



        # Web info Key

        Web_info_key = {
            "x-Apikey" : g_sub_key
        }


        # Web info API Calls

        web_info= rq.get(f"https://www.virustotal.com/api/v3/domains/{user_web}",headers=Web_info_key)
        sub_domins = rq.get(f"https://www.virustotal.com/api/v3/domains/{user_web}/subdomains",headers=Web_info_key)




        # Web info JSON form

        subs = sub_domins.json()
        web_ginfo = web_info.json()


        # Web IP prams

        Web_current_ip = web_ginfo["data"]["attributes"]["last_dns_records"]
        for x in Web_current_ip:
            if x["type"] == "A":
                web_ip = x["value"]
        Web_ip_prams = {
            "ipAddress": web_ip,
            "maxAgeInDays": 90
        }
        Web_ip_key = {
            "Key": ip_key,
            "Accept": "application/json"
        }

        # Web IP API Calls
        ip = rq.get("https://api.abuseipdb.com/api/v2/check",params=Web_ip_prams,headers=Web_ip_key)


        # Web IP info JSON form

        ip_json = ip.json()

        web_ip = ip_json["data"]["ipAddress"]
        web_ip_vertion = ip_json["data"]["ipVersion"]


        # clearing the above
        clear_screen()


        # Web_Domains
        if choices == 1:
            print(f"{"\n" * 3}Web SubDomains:")
            for item in subs["data"]:
                print(item["id"])


        # Web_Reputation

        clearnce = web_ginfo["data"]["attributes"]["last_analysis_stats"]["malicious"]
        clearnce2 = web_ginfo["data"]["attributes"]["last_analysis_stats"]["suspicious"]
        reports = ip_json["data"]["totalReports"]






        if choices == 2:
            if int(clearnce) > 0 or int(clearnce2) > 0 :
                print(f"{"\n" * 3}🔴 This Web is Not Clear ")
            elif int(clearnce) == 0 and int(clearnce2 ) == 0:
                print(f"{"\n" * 3}🟢 This Web is Clear")
                print(
                f"The Web Current Domain: {web_ginfo["data"]["id"]}\nThe Web Server IP is: {web_ip}\nThe Web ipVersion: IPv{web_ip_vertion}\nTheres ({reports}) Total Reports on This Web ")


        # saving the res
        save = input(f"{"\n" * 2}Do You Want To Save The Result into A json file (y/n) ?")
        if "y" in save:
            data = {
                f"{user_web}_info":{
                    "The Web Current Domain": web_ginfo["data"]["id"],
                    "The Web Server IP is" : web_ip,
                    "The Web ipVersion" : web_ip_vertion,
                    "TotalReports":reports
                },
                f"{user_web}_subdomains":{
                    "subdomains":[x["id"] for x in subs["data"]]
                }

            }
            with open(f"{user_web}.json" , "w") as x:
                dump(data,x,indent=4)

    except:
        messagebox.showinfo("Dev-NotHex",
                            "Make Sure Your Choice is Valid & Make Sure The Domin is valid \nexample.com ✔️\nhttpx://xxx.example.com/ ❌")

    root.destroy()
