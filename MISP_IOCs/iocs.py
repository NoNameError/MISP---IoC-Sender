from pymisp import PyMISP, MISPEvent
import ssl
import sys


MISP_URL = "" #your MISP IP
MISP_KEY = "" #your MISP api key

MISP_VERIFYCERT = False 


EVENT_INFO = "Pivoted IOCs (CTI - Automation)"
THREAT_LEVEL = 4  
ANALYSIS = 1     
DISTRIBUTION = 2  



def get_misp_connection():
    try:
        if not MISP_VERIFYCERT:
            if hasattr(ssl, '_create_unverified_context'):
                ssl._create_default_https_context = ssl._create_unverified_context
        
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT, 'json')
        print(f"[Success] Conected to MISP in {MISP_URL}")
        return misp
    except Exception as e:
        print(f"[ERROR] Failed to connect on your MISP account. Please verify your URL/Key/SSL.: {e}")
        sys.exit(1)

def get_ioc_input():
    print("\n--- Input ---")
    print("Place tour IOCs (Hash, IP, Domains[...])")
    print("Type 'END' on a new line to finish and send.")
    
    iocs_raw = []
    while True:
        line = input("IOC (ou 'END'): ")
        if line.upper() == 'END':
            break
        iocs_raw.append(line)

    iocs_list = []
    for raw_item in iocs_raw:
        if ',' in raw_item:
            parts = [part.strip() for part in raw_item.split(',') if part.strip()]
        else:
            parts = [part.strip() for part in raw_item.split() if part.strip()]
        iocs_list.extend(parts)
        
    return list(set(iocs_list))

def get_misp_ioc_type(ioc):
   
    ioc_len = len(ioc)
    
    if ioc.isalnum() and not any(c.isspace() for c in ioc):
        if ioc_len == 32:
            return "md5"
        elif ioc_len == 40:
            return "sha1"
        elif ioc_len == 64:
            return "sha256"
            
    if ioc.lower().startswith("ja3"): 
        return "ja3-fingerprint"
    
    return "text"

def main():
    
    misp = get_misp_connection()
    iocs_to_send = get_ioc_input()
    
    if not iocs_to_send:
        print("\nNo IOC inserted. Finishing the script.")
        return

    print(f"\nTotal de {len(iocs_to_send)} Unique IOCs to process.")
    print("--- Creating MISP event ---")

    event = MISPEvent()
    event.info = EVENT_INFO
    event.threat_level_id = THREAT_LEVEL
    event.analysis = ANALYSIS
    event.distribution = DISTRIBUTION
    

    new_event = misp.add_event(event, pythonify=True)
    if not new_event:
        print("[FATAL ERROR] Unable to create event in MISP.")
        return
        
    event_id = new_event.id
    print(f"[SUCCESS] MISP Event created with ID: {event_id}. Title: {EVENT_INFO}")
    print("--- Adding (IOCs) to the Event ---")

   
    for ioc in iocs_to_send:
        misp_type = get_misp_ioc_type(ioc)
        
       
        try:
            misp.add_attribute(
                new_event, 
                {"type": misp_type, "value": ioc, "category": "Artifacts dropped", "comment": "Collected IOCs from manual pivoting"},
                pythonify=True
            )
            print(f"   [OK] Adding: {ioc} (MISP: {misp_type})")
        except Exception as e:
            print(f"   [Failure] wasn't possible add IOCs {ioc}. Error: {e}")



    print("\n--- Succes - process finished: IOC's already on your MISP ---")
    print(f"Verify the event in: {MISP_URL}/events/view/{event_id}")


if __name__ == "__main__":

    main()

