#Hello! if you do not know where to get the API keys they can be grathred by making an account for

#IBM X-Force, VirusTotal and OTX. After making those accounts you can go here to get the keys:

 

#X-Force - https://exchange.xforce.ibmcloud.com/settings/api

#VirusTotal - https://www.virustotal.com/gui/user/<Your_User_name_here>/apikey

#OTX - https://otx.alienvault.com/api


#You also need to run the following command in terminal  
#[pip3 install requests] this will install python library needed to make GET requests to Vt, Otx and X-Force
#[pip3 install bs4] this will be used to help parse spur



import requests
from bs4 import BeautifulSoup

xforce_api_key = ""
xforce_api_password = ""
virustotal_api_key = ""
otx_api_key = ""
abuseipdb_api_key = ""



def vt_format_score(type, source, score, non_malicious, country):
    formatted_score = f"{source} | {type} Malicious: {score}/{non_malicious} | Country: {country}"
    print(formatted_score)
    return formatted_score

def xforce_format_score(type, source, score):
    formatted_score = f"{source} | {type} Risk: {score}"
    print(formatted_score)
    return formatted_score

def otx_format_score(type, source, score):
    formatted_score = f"{source} | {type} Pulses: {score}"
    print(formatted_score)
    return formatted_score

def abuseipdb_format_score(type, source, score, country, total_reports, isp):
    formatted_score = f"{source} | {type} Score: {score} | Country: {country} | Total Reports: {total_reports} | ISP: {isp}"
    print(formatted_score)
    return formatted_score


def vt_format_score_domain(type, source, score, non_malicious, registrar=""):
    formatted_score = f"{source} | {type} Malicious: {score}/{non_malicious} {registrar}"
    print(formatted_score)

def xforce_format_score_domain(type, source, score):
    formatted_score = f"{source} | {type} Risk: {score}"
    print(formatted_score)
    return formatted_score

def otx_format_score_domain(type, source, score):
    formatted_score = f"{source} | {type} Pulses: {score}"
    print(formatted_score)
    return formatted_score

def error_score(type, source):
    error_score = f"{source} | {type} Unknown"
    print(error_score)
    return error_score


def error_score(type, source):
    error_score = f"{source} | {type} Unknown"
    print(error_score)
    return error_score







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
        if registrar:
            vt_format_score_domain("Domain", "VirusTotal", malicious_count, non_malicious_count, f"| {registrar}")
        else:
            vt_format_score_domain("Domain", "VirusTotal", malicious_count, non_malicious_count, "")
    except:
        error_score("Domain", "VirusTotal")

    try:
        url = f"https://exchange.xforce.ibmcloud.com/api/url/{user_input}"
        headers = {'Accept': 'application/json'}
        auth = (xforce_api_key, xforce_api_password)
        response = requests.get(url, headers=headers, auth=auth)
        data = response.json()
        risk_score = data.get('result', {}).get('score')
        if risk_score is not None:
            xforce_format_score_domain("Domain", "X-Force", risk_score)
        else:
            error_score("Domain", "X-Force")
    except:
        error_score("Domain", "X-Force")


    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{user_input}/"
        headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        response = requests.get(url, headers=headers).json()
        if isinstance(response, dict) and response.get('error') == 'unable to parse domain or hostname':
            error_score("Domain", "OTX")
        else:
            score = response.get("pulse_info", {}).get("count", 0)
            otx_format_score_domain("Domain", "OTX", score)
    except:
        error_score("Domain", "OTX")

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
        error_score("Domain", "Whois")









def hash():
    user_input = input("Please enter a hash: ")

    try:
        xforce_url = 'https://exchange.xforce.ibmcloud.com/api/malware/' + f'{user_input}'
        xforce_headers = {'Accept': 'application/json'}
        xforce_auth = (xforce_api_key, xforce_api_password)
        xforce_response = requests.get(xforce_url, headers=xforce_headers, auth=xforce_auth)
        xforce_data = xforce_response.json()
        xforce_risk_score = xforce_data['malware']['risk']
        xforce_format_score("Hash", "X-Force", xforce_risk_score)
    except KeyError:
        error_score("Hash", "X-Force")
        


    try:
        virustotal_url = "https://www.virustotal.com/api/v3/files/" + f'{user_input}'
        virustotal_headers = {"x-apikey": virustotal_api_key}
        virustotal_response = requests.get(virustotal_url, headers=virustotal_headers)
        virustotal_data = virustotal_response.json()
        file_hash = virustotal_data["data"]["id"]
        result = virustotal_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        vt_format_score("Hash", "VirusTotal", result)        
    except KeyError:
        error_score("Hash", "VirusTotal")

    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/file/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()

        if isinstance(otx_response, dict) and otx_response.get('detail') == 'endpoint not found':
            error_score("Hash", "OTX")  

        else:
            score = otx_response.get("pulse_info", {}).get("count", 0)
            formatted_otx_score = f"OTX | {score}"
            print(formatted_otx_score) 

    
    
    except KeyError:
            print("OTX will not error")













def ip():
    user_input = input("Please enter an IP address: ")


    try:
        virustotal_url = "https://www.virustotal.com/api/v3/ip_addresses/" + f'{user_input}'
        virustotal_headers = {"x-apikey": virustotal_api_key}
        virustotal_response = requests.get(virustotal_url, headers=virustotal_headers)
        virustotal_data = virustotal_response.json()
        result = virustotal_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        non_malicious = virustotal_data["data"]["attributes"]["last_analysis_stats"]["undetected"]
        country = virustotal_data["data"]["attributes"]["country"]
        vt_format_score("IP", "VirusTotal", result, non_malicious, country)
    
    except KeyError:
        vt_format_score("IP", "VirusTotal", "IP does not exist")


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
        abuseipdb_format_score = "AbuseIPDB | IP does not exist"
        print(abuseipdb_format_score)



    try:
        url = 'https://exchange.xforce.ibmcloud.com/api/ipr/' + f'{user_input}'
        headers = {'Accept': 'application/json'}
        auth = ('ba1a8671-d2c2-4ffd-ba4e-69624afe8c10', '0184d324-d1a1-4687-987c-c51d978c8214')
        response = requests.get(url, headers=headers, auth=auth)
        data = response.json()
        risk_score = data['score']
        xforce_format_score("IP", "X-Force", risk_score)
    except KeyError:    
        xforce_format_score("IP", "X-Force", "IP does not exist")



    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{user_input}/"
        otx_headers = {"X-OTX-API-KEY": otx_api_key, "Accept": "application/json", "User-Agent": "OTX Python SDK"}
        otx_response = requests.get(otx_url, headers=otx_headers).json()
        if isinstance(otx_response, dict) and otx_response.get('detail') == f'Invalid IP ({user_input})':
            otx_format_score("IP", "OTX", "IP does not exist")
        else:
            score = otx_response.get("pulse_info", {}).get("count", 0)
            otx_format_score("IP", "OTX", score)


    except KeyError:
        formatted_otx_score = "OTX | IP does not exist"
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
            print("Description tag not found")
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


