#Hello! if you do not know where to get the API keys they can be grathred by making an account for

#IBM X-Force, VirusTotal and OTX. After making those accounts you can go here to get the keys:

 

#X-Force - https://exchange.xforce.ibmcloud.com/settings/api

#VirusTotal - https://www.virustotal.com/gui/user/<Your_User_name_here>/apikey

#OTX - https://otx.alienvault.com/api


#You also need to run the following command in terminal  
#[pip3 install requests] this will install python library needed to make GET requests to Vt, Otx and X-Force


import requests

xforce_api_key = "YOUR_X-FROCE_API_KEY_HERE"
xforce_api_password = "YOUR_X-FORCE_API_PASSWORD_HERE"
virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY_HERE"
otx_api_key = "YOUR_OTX_API_KEY_HERE"





def domain():
    user_input = input("Please enter a URL: ")

    # X-Force API request
    try:
        url = 'https://exchange.xforce.ibmcloud.com/api/url/' + f'{user_input}'
        headers = {'Accept': 'application/json'}
        auth = (xforce_api_key, xforce_api_password)
        response = requests.get(url, headers=headers, auth=auth)
        data = response.json()
        risk_score = data['result']['score']
        formatted_xf_score = f"X-Force | Risk {risk_score}"
    except KeyError:
        formatted_xf_score = "X-Force | Site does not exist"

    # VirusTotal API request
    try:
        virustotal_url = 'https://www.virustotal.com/api/v3/domains/' + f'{user_input}'
        virustotal_headers = {"x-apikey": virustotal_api_key}
        virustotal_response = requests.get(virustotal_url, headers=virustotal_headers)
        virustotal_data = virustotal_response.json()
        malicious_count = virustotal_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        formatted_vt_score = f"VirusTotal | {malicious_count}"
    except KeyError:
        formatted_vt_score = "VirusTotal | Site does not exist"

    # OTX API request
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()
        score = otx_response.get("pulse_info", {}).get("count", 0)
        formatted_otx_score = f"OTX | pulses {score}"
    except KeyError:
        formatted_otx_score = "OTX will not have a key error lol"           

    
    if formatted_vt_score == "VirusTotal | Site does not exist" and formatted_xf_score == "X-Force | Site does not exist":
        print("-------------------")  
        print("OSINT")
        print("-" + user_input)
        print(formatted_vt_score)
        print(formatted_xf_score)
        print("OTX | Site does not exist")


    else:
        print("-------------------")        
        print("OSINT")
        print("-" + user_input)
        print(formatted_vt_score)
        print(formatted_xf_score)
        print(formatted_otx_score)

   

def hash():
    user_input = input("Please enter a hash: ")

    # X-Force API request
    try:
        xforce_url = 'https://exchange.xforce.ibmcloud.com/api/malware/' + f'{user_input}'
        xforce_headers = {'Accept': 'application/json'}
        xforce_auth = (xforce_api_key, xforce_api_password)
        xforce_response = requests.get(xforce_url, headers=xforce_headers, auth=xforce_auth)
        xforce_data = xforce_response.json()
        xforce_risk_score = xforce_data['malware']['risk']
        formatted_xforce_risk_score = xforce_risk_score.capitalize()
        formatted_xf_score = f"X-Force | {formatted_xforce_risk_score}"
    except KeyError:
        formatted_xf_score = "X-Force | Hash does not exist"

    # VirusTotal API request
    try:
        virustotal_url = "https://www.virustotal.com/api/v3/files/" + f'{user_input}'
        virustotal_headers = {"x-apikey": virustotal_api_key}
        virustotal_response = requests.get(virustotal_url, headers=virustotal_headers)
        virustotal_data = virustotal_response.json()
        file_hash = virustotal_data["data"]["id"]
        result = virustotal_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        formatted_vt_score = f"VirusTotal | {result}"
    except KeyError:
        formatted_vt_score = "VirusTotal | Hash does not exist"

    # OTX API request
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/file/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()
        score = otx_response.get("pulse_info", {}).get("count", 0)
        formatted_otx_score = f"OTX | {score}"
    except KeyError:
        formatted_otx_score = "OTX | Hash does not exist"

    if formatted_vt_score == "VirusTotal | Hash does not exist" and formatted_xf_score == "X-Force | Hash does not exist":
        print("-------------------")
        print("OSINT")
        print("-" + user_input)
        print(formatted_vt_score)
        print(formatted_xf_score)
        print("OTX | Hash does not exist")


    else:
        print("-------------------")    
        print("OSINT")
        print("-" + user_input)
        print(formatted_vt_score)
        print(formatted_xf_score)
        print(formatted_otx_score)





def ip():
    user_input = input("Please enter an IP address: ")

    try:
        # X-Force API request
        url = 'https://exchange.xforce.ibmcloud.com/api/ipr/' + f'{user_input}'
        headers = {'Accept': 'application/json'}
        auth = (xforce_api_key, xforce_api_password)
        response = requests.get(url, headers=headers, auth=auth)
        data = response.json()
        risk_score = data['score']
        formatted_xf_score = f"X-Force | {risk_score}"
    except KeyError:    
        formatted_xf_score = "X-Force | IP does not exist"

    try:
        # VirusTotal API request
        virustotal_url = "https://www.virustotal.com/api/v3/ip_addresses/" + f'{user_input}'
        virustotal_headers = {"x-apikey": virustotal_api_key}
        virustotal_response = requests.get(virustotal_url, headers=virustotal_headers)
        virustotal_data = virustotal_response.json()
        result = virustotal_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        formatted_vt_score = f"VirusTotal | {result}"
    except KeyError:
        formatted_vt_score = "VirusTotal | IP does not exist"

    try:
        # OTX API request
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()
        pulse_count = otx_response["pulse_info"]["count"]
        formatted_otx_score = f"OTX | {pulse_count}"
    except KeyError:
        formatted_otx_score = "OTX | IP does not exist"
    
    
    if formatted_vt_score == "VirusTotal | IP does not exist" and formatted_xf_score == "X-Force | IP does not exist":
        print("-------------------")
        print("OSINT")
        print("-" + user_input)
        print(formatted_vt_score)
        print(formatted_xf_score)
        print("OTX | IP does not exist")
        
    else:
        print("-------------------")   
        print("OSINT")
        print("-" + user_input)
        print(formatted_vt_score)
        print(formatted_xf_score)
        print(formatted_otx_score)

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
        ur_choice = input("Would you like to perform OSINT on a Hash, Domain, or IP address? ").lower()
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
            print("Invalid input. Please enter Hash, Domain, or IP. Check your spelling!")


