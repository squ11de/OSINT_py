#Hello! if you do not know where to get the API keys they can be grathred by making an account for

#IBM X-Force, VirusTotal and OTX. After making those accounts you can go here to get the keys:

 

#X-Force - https://exchange.xforce.ibmcloud.com/settings/api

#VirusTotal - https://www.virustotal.com/gui/user/<Your_User_name_here>/apikey

#OTX - https://otx.alienvault.com/api

#AbuseIPDB - https://www.abuseipdb.com/account/api


#You also need to run the following command in terminal  
#[pip3 install requests] this will install python library needed to make GET requests to Vt, Otx and X-Force
#[pip3 install bs4] this will be used to help parse spur



import requests
from bs4 import BeautifulSoup


xforce_api_key = "YOUR_X-FROCE_API_KEY_HERE"
xforce_api_password = "YOUR_X-FORCE_API_PASSWORD_HERE"
virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY_HERE"
otx_api_key = "YOUR_OTX_API_KEY_HERE"





def domain():
    user_input = input("Please enter a Domain: ")

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{user_input}"
        headers = {"x-apikey": virustotal_api_key}
        response = requests.get(url, headers=headers)
        data = response.json()
        analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = analysis_stats.get("malicious", 0)
        non_malicious_count = analysis_stats.get("undetected", 0) + analysis_stats.get("harmless", 0)
        registrar = data.get("data", {}).get("attributes", {}).get("registrar", "")
        print("OSINT")
        print(f"-{user_input}")
        if malicious_count == 0 and non_malicious_count == 0:
            print("VirusTotal | Unknown")
        elif registrar:
            print(f"VirusTotal | {malicious_count}/{malicious_count + non_malicious_count} | {registrar}")
        else:
            print(f"VirusTotal | {malicious_count}/{malicious_count + non_malicious_count}")
    except:
        print("VirusTotal | Domain does not exist")



    try:
        url = f"https://exchange.xforce.ibmcloud.com/api/url/{user_input}"
        headers = {'Accept': 'application/json'}
        auth = (xforce_api_key, xforce_api_password)
        response = requests.get(url, headers=headers, auth=auth)
        data = response.json()
        risk_score = data.get('result', {}).get('score')
        if risk_score is not None:
            print(f"X-Force | Risk {risk_score}")
        else:
            print("X-Force | Risk Unknown")
    except:
        print("X-Force | Risk Unknown")

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{user_input}/"
        headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        response = requests.get(url, headers=headers).json()
        if isinstance(response, dict) and response.get('error') == 'unable to parse domain or hostname':
            print("OTX | Unknown")
        else:
            score = response.get("pulse_info", {}).get("count", 0)
            print(f"OTX | Pulses {score}")
    except:
        print("OTX | Unknown")
    try:
        url = f"https://www.whois.com/whois/{user_input}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for pre in soup.find_all('pre'):
            if "Creation Date:" in pre.text:
                for line in pre.text.split('\n'):
                    if line.startswith('Creation Date:'):
                        creation_date = line.split(': ')[1].strip()
                        print(f"Whois | Domain {user_input} was created on {creation_date}")
    except:
        print("Whois | Domain does not exist")



















def hash():
    user_input = input("Please enter a hash: ")

   
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{user_input}"
        headers = {"x-apikey": virustotal_api_key}
        response = requests.get(url, headers=headers)
        data = response.json()
        analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = analysis_stats.get("malicious", 0)
        total_detections = sum(analysis_stats.values())

        signature_info = data.get("data", {}).get("attributes", {}).get("signature_info", {})
        signature_verified = signature_info.get("verified", "No verification info found")
        signature_product = signature_info.get("product", "No product info found")
        print("OSINT")
        print(f"-{user_input}")
        if total_detections == 0:
            print("VirusTotal | Unknown")
        elif signature_verified != "No verification info found":
            print(f"VirusTotal | {malicious_count}/{total_detections} | File is signed | {signature_product}")
        else:
            print(f"VirusTotal | {malicious_count}/{total_detections} | File is not signed")
    except:
        print("Error occurred while getting data from VirusTotal")
    
    try:
        xforce_url = 'https://exchange.xforce.ibmcloud.com/api/malware/' + f'{user_input}'
        xforce_headers = {'Accept': 'application/json'}
        xforce_auth = (xforce_api_key, xforce_api_password)
        xforce_response = requests.get(xforce_url, headers=xforce_headers, auth=xforce_auth)
        xforce_data = xforce_response.json()
        xforce_risk_score = xforce_data['malware']['risk']
        print(f"X-Force | Risk {xforce_risk_score}")
    except KeyError:
        print("X-Force | Risk Unknown")



    
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/file/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()

        if isinstance(otx_response, dict) and otx_response.get('detail') == 'endpoint not found':
            print("OTX | Unknown")
        else:
            score = otx_response.get("pulse_info", {}).get("count", 0)
            formatted_otx_score = f"OTX | {score}"
            print(formatted_otx_score)
    
    
    except KeyError:
            print("OTX will not error")














def ip():
    user_input = input("Please enter an IP address: ")


    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{user_input}"
        headers = {"x-apikey": virustotal_api_key}
        response = requests.get(url, headers=headers)
        data = response.json()
        analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = analysis_stats.get("malicious", 0)
        total_detections = sum(analysis_stats.values())
        print("OSINT")
        print(f"-{user_input}")

        country = data.get("data", {}).get("attributes", {}).get("country", "No country info found")
        if total_detections == 0:
            print("VirusTotal | Unknown")
        else:
            print(f"VirusTotal | {malicious_count}/{total_detections} | {country}")
    except:
        print("VirusTotal | Unknown")

    try:
        abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={user_input}&maxAgeInDays=90"
        abuseipdb_headers = {"Accept": "application/json", "Key": abuseipdb_api_key}
        abuseipdb_response = requests.get(abuseipdb_url, headers=abuseipdb_headers).json()
        abuseipdb_score = abuseipdb_response["data"]["abuseConfidenceScore"]
        abuseipdb_country = abuseipdb_response["data"]["countryCode"]
        abuseipdb_total_reports = abuseipdb_response["data"]["totalReports"]
        abuseipdb_isp = abuseipdb_response["data"]["isp"]
        abuseipdb_format_score = (f"AbuseIPDB | IP Score: {abuseipdb_score} | Country: {abuseipdb_country} | Total Reports: {abuseipdb_total_reports} | ISP: {abuseipdb_isp}")
        print(abuseipdb_format_score)
   
    except KeyError:
        abuseipdb_format_score = "AbuseIPDB | Unknown"
        print(abuseipdb_format_score)



    try:
        url = 'https://exchange.xforce.ibmcloud.com/api/ipr/' + f'{user_input}'
        headers = {'Accept': 'application/json'}
        auth = ('ba1a8671-d2c2-4ffd-ba4e-69624afe8c10', '0184d324-d1a1-4687-987c-c51d978c8214')
        response = requests.get(url, headers=headers, auth=auth)
        data = response.json()
        risk_score = data['score']
        print(f"X-Force | Risk {risk_score}")
    except KeyError:    
        print("X-Force | Unknown")


    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()
        if isinstance(otx_response, dict) and otx_response.get('detail') == f'Invalid IP ({user_input})':
            print("OTX | Unknown")
        else:
            score = otx_response.get("pulse_info", {}).get("count", 0)
            formatted_otx_score = f"OTX | Pulses {score}"
            print(formatted_otx_score)

    except KeyError:
        formatted_otx_score = "OTX | Unknown"


    try:
        spur_url = f"https://spur.us/context/{user_input}/"
        spur_headers = {"Accept": "application/html", }

        response = requests.get(spur_url, headers=spur_headers)

        soup = BeautifulSoup(response.text, 'html.parser')

        description_tag = soup.find('meta', attrs={'name': 'description'})
        title_tag = soup.find('title')

        if description_tag:
            description_content = description_tag.get('content').lower()
            if 'vpn' in description_content and ('is part of' in description_content or 'users can hide their activity' in description_content):
                title_content = title_tag.get_text()
                vpn_name = title_content.split('(')[1].split(')')[0]
                spur_score = f"Spur | This IP is associated with{vpn_name}"
                print(spur_score)
            
            elif "tor" in description_content and ('is part of' in description_content or 'users can hide their activity' in description_content):
                print("Spur | This IP is associated with Tor.")
            
            else:
                print("Spur | This IP is not associated with a VPN.")
        else:
            print("Spur | Unknown")
    except:
        print("Error")


















    

if __name__ == "__main__":
    
    ascii_art = """
                                                      ,----, 
    ,----..                               ,--.      ,/   .`| 
   /   /   \   .--.--.      ,---,       ,--.'|    ,`   .'  : 
  /   .     : /  /    '. ,`--.' |   ,--,:  : |  ;    ;     / 
 .   /   ;.  \  :  /`. / |   :  :,`--.'`|  ' :.'___,/    ,'  
.   ;   /  ` ;  |  |--`  :   |  '|   :  :  | ||    :     |   
;   |  ; \ ; |  :  ;_    |   :  |:   |   \ | :;    |.';  ;   
|   :  | ; | '\  \    `. '   '  ;|   : '  '; |`----'  |  |   
.   |  ' ' ' : `----.   \|   |  '|   ' ;.    ;    '   :  ;   
'   ;  \; /  | __ \  \  |'   :  ;|   | | \   |    |   |  '   
 \   \  ',  / /  /`--'  /|   |  ''   : |  ; .'    '   :  |   
  ;   :    / '--'.     / '   :  ||   | '`--'      ;   |.'    
   \   \ .'    `--'---'  ;   |.' '   : |          '---'      
    `---`                '---'   ;   |.'                     
                                 '---'

                                 By tluikey
"""

    print(ascii_art)
    while True:
        print()
        ur_choice = input("Would you like to perform OSINT on a Hash, Domain, or IP? ").lower()
        if ur_choice == "hash":
            hash()
            break
        elif ur_choice == "domain":
            domain()
            break
        elif ur_choice == "ip":
            ip()
            break
        else:
            print("Invalid input. Please enter hash, domain, or ip. Check your spelling!")





