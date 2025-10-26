from pymisp import PyMISP, MISPEvent
import ssl
import sys


MISP_URL = "" #your MISP IP
MISP_KEY = "" #your MISP api key

MISP_VERIFYCERT = False 


EVENT_INFO = "IOCs de Pivoting em Infra Maliciosa (Automação CTI)"
THREAT_LEVEL = 4  
ANALYSIS = 1     
DISTRIBUTION = 2  



def get_misp_connection():
    try:
        if not MISP_VERIFYCERT:
            if hasattr(ssl, '_create_unverified_context'):
                ssl._create_default_https_context = ssl._create_unverified_context
        
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT, 'json')
        print(f"[SUCESSO] Conectado ao MISP em {MISP_URL}")
        return misp
    except Exception as e:
        print(f"[ERRO] Falha ao conectar ao MISP. Verifique URL/Key/SSL. Detalhes: {e}")
        sys.exit(1)

def get_ioc_input():
    print("\n--- Entrada de IOCs ---")
    print("Cole os IOCs (Hash, IP, Domínio, etc.) um por linha ou separados por vírgula/espaço.")
    print("Digite 'FIM' em uma nova linha para terminar a entrada.")
    
    iocs_raw = []
    while True:
        line = input("IOC (ou 'FIM'): ")
        if line.upper() == 'FIM':
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
        print("\nNenhum IOC inserido. Encerrando o script.")
        return

    print(f"\nTotal de {len(iocs_to_send)} IOCs únicos para processar.")
    print("--- Iniciando Criação do Evento MISP ---")

    event = MISPEvent()
    event.info = EVENT_INFO
    event.threat_level_id = THREAT_LEVEL
    event.analysis = ANALYSIS
    event.distribution = DISTRIBUTION
    

    new_event = misp.add_event(event, pythonify=True)
    if not new_event:
        print("[ERRO FATAL] Não foi possível criar o evento no MISP.")
        return
        
    event_id = new_event.id
    print(f"[SUCESSO] Evento MISP criado com ID: {event_id}. Título: {EVENT_INFO}")
    print("--- Adicionando Atributos (IOCs) ao Evento ---")

   
    for ioc in iocs_to_send:
        misp_type = get_misp_ioc_type(ioc)
        
       
        try:
            misp.add_attribute(
                new_event, 
                {"type": misp_type, "value": ioc, "category": "Artifacts dropped", "comment": "IOC coletado via pivoting de infra maliciosa"},
                pythonify=True
            )
            print(f"   [OK] Adicionado: {ioc} (Tipo MISP: {misp_type})")
        except Exception as e:
            print(f"   [FALHA] Não foi possível adicionar o IOC {ioc}. Erro: {e}")



    print("\n--- Processo de Envio Concluído ---")
    print(f"Verifique o evento em: {MISP_URL}/events/view/{event_id}")


if __name__ == "__main__":

    main()
