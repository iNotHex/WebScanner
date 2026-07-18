from dotenv import *
import requests as rq
import time
import sys
from logo import logo
import os
from json import *
import tkinter as tk
from tkinter import messagebox

from dotenv import load_dotenv
import requests as rq
import time
import sys
from logo import logo
import os
from json import dump
import tkinter as tk
from tkinter import messagebox


root = tk.Tk()
root.withdraw()
root.attributes("-topmost", True)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":

    try:

        print(logo)

        user_web = input("\n\nPlease Enter The Web Domain: ")

        # Clean domain input
        user_web = user_web.strip().lower()
        user_web = user_web.replace("https://", "")
        user_web = user_web.replace("http://", "")
        user_web = user_web.replace("www.", "")
        user_web = user_web.split("/")[0]


        choices = int(
            input(
                "1 - SubDomains\n"
                "2 - Webinfo\n"
            )
        )


        if choices not in [1, 2]:
            raise Exception("Invalid choice")


        print("\n\nGetting the info", end="")


        start_time = time.time()

        while time.time() - start_time < 5:

            for i in range(4):

                sys.stdout.write(
                    "\rGetting the info" +
                    "." * i +
                    " " * (4 - i)
                )

                sys.stdout.flush()
                time.sleep(0.5)



        # Load API keys

        load_dotenv()

        ip_key = os.getenv("ip")
        vt_key = os.getenv("dom")


        if not ip_key or not vt_key:
            raise Exception("Missing API keys in .env")


        # VirusTotal headers

        vt_headers = {
            "x-Apikey": vt_key
        }


        # VirusTotal requests

        web_info = rq.get(
            f"https://www.virustotal.com/api/v3/domains/{user_web}",
            headers=vt_headers
        )


        sub_domains = rq.get(
            f"https://www.virustotal.com/api/v3/domains/{user_web}/subdomains",
            headers=vt_headers
        )


        if web_info.status_code != 200:
            raise Exception(
                f"VirusTotal Error: {web_info.status_code}"
            )


        web_data = web_info.json()
        subs = sub_domains.json()



        # Get website IP

        dns_records = (
            web_data["data"]
            ["attributes"]
            .get("last_dns_records", [])
        )


        web_ip = None


        for record in dns_records:

            if record.get("type") == "A":
                web_ip = record.get("value")
                break


        if web_ip is None:
            raise Exception(
                "No IPv4 address found"
            )


        # AbuseIPDB

        abuse_params = {
            "ipAddress": web_ip,
            "maxAgeInDays": 90
        }


        abuse_headers = {
            "Key": ip_key,
            "Accept": "application/json"
        }


        ip_request = rq.get(
            "https://api.abuseipdb.com/api/v2/check",
            params=abuse_params,
            headers=abuse_headers
        )


        if ip_request.status_code != 200:
            raise Exception(
                f"AbuseIPDB Error: {ip_request.status_code}"
            )


        ip_data = ip_request.json()
        ip_info = ip_data["data"]

        web_ip_version = ip_info["ipVersion"]
        reports = ip_info["totalReports"]

        clear_screen()

        # Show Subdomains

        if choices == 1:

            print("\n\nWeb SubDomains:\n")

            if "data" in subs and len(subs["data"]) > 0:

                for item in subs["data"]:
                    print(item["id"])

            else:

                print("No subdomains found")

        # Website reputation

        analysis = (
            web_data["data"]
            ["attributes"]
            ["last_analysis_stats"]
        )

        malicious = analysis["malicious"]
        suspicious = analysis["suspicious"]

        if choices == 2:

            if malicious > 0 or suspicious > 0:

                print(
                    "\n\n🔴 This Web is Not Clear"
                )


            else:

                print(
                    "\n\n🟢 This Web is Clear"
                )

            print(
                f"""
    The Web Current Domain: {user_web}
    The Web Server IP: {web_ip}
    The Web IP Version: IPv{web_ip_version}
    Total Reports: {reports}
    """
            )

        # Save JSON result

        save = input(
            "\n\nDo You Want To Save The Result into JSON file (y/n)? "
        )

        if save.lower().startswith("y"):
            result = {

                "domain_info": {

                    "domain": user_web,

                    "server_ip": web_ip,

                    "ip_version": web_ip_version,

                    "total_reports": reports

                },

                "subdomains": [

                    item["id"]

                    for item in subs.get("data", [])

                ]

            }

            with open(
                    f"{user_web}.json",
                    "w"
            ) as file:
                dump(
                    result,
                    file,
                    indent=4
                )

            print(
                f"\nSaved as {user_web}.json"
            )



    except Exception as e:

        messagebox.showinfo(
            "Dev-NotHex",
            f"""
    Error:

    Make sure the domain is valid.

    Example:
    google.com ✔️

    Not:
    https://google.com/path ❌
    """
        )

    root.destroy()



