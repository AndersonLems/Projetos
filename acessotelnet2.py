
import telnetlib
import time
import re
import paramiko
import argparse

try:
    input = raw_input
except NameError:
    pass

def expand_onu_ids(onu_range_str):
    result = []
    for part in onu_range_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            result.extend(range(start, end + 1))
        else:
            result.append(int(part))
    return result

def onu_id_em_faixa(onu_id, texto_faixa):
    partes = texto_faixa.split(',')
    for parte in partes:
        if '-' in parte:
            inicio, fim = map(int, parte.split('-'))
            if inicio <= onu_id <= fim:
                return True
        elif parte.isdigit() and int(parte) == onu_id:
            return True
    return False

def buscar_onu_fiberhome(serial, lines):
    onu_data = {}
    serial = serial.lower()
    #Regex principal
    white_pattern = re.compile(
        r'set white phy addr (\S+)\s+pas\s+\S+\s+ac\s+add\s+sl\s+(\d+)\s+(?:p|li)\s+(\d+)\s+o\s+(\d+)\s+ty\s+(\S+)',
        re.IGNORECASE
    )
    #inicio do laço
    for line in lines:
        #Captura informações da onu
        match = white_pattern.search(line)
        if match:
            s, slot, pon, onu_id, tipo = match.groups()
            if s.lower() == serial:
                if s not in onu_data:
                    onu_data[s] = {
                        "slot": int(slot),
                        "pon": int(pon),
                        "onu_id": int(onu_id),
                        "commands": []
                    }
                onu_data[s]["commands"].append(line.strip())

    for line in lines:
        #percorre as informações da onu
        for s, data in onu_data.items():
            slot = data["slot"]
            pon = data["pon"]
            onu_id = data["onu_id"]
            #Regex para diversas versões fiberhome
            if (
                re.search(rf"sl\s+{slot}\s+(p|li)\s+{pon}\b", line, re.IGNORECASE) or
                re.search(rf"slot\s+{slot}\s+(pon|li)\s+{pon}\b", line, re.IGNORECASE) or
                re.search(rf"sl\s+{slot}\s+{pon}\s+{onu_id}", line, re.IGNORECASE) or  # ex: sl 1 3 65
                re.search(rf"slot\s+{slot}\s+pon\s+{pon}\s+onu\s+{onu_id}", line, re.IGNORECASE)
            ):
                #Regex para diversas versões fiberhome
                match_onu = (
                    re.search(rf'\so {onu_id}\s', line) or
                    re.search(rf'\sonu {onu_id}\s', line) or
                    re.search(rf'\s{onu_id}\s', line)  # ID isolado
                )
                #Se a onu corresponder, adiciona os comandos
                if match_onu:
                    data["commands"].append(line.strip())
                    continue
                #Caso o ID da ONU esteja em range 1-4, 1-30
                match_faixa = re.search(r'o ([\d\-,]+)', line)
                if match_faixa:
                    faixa = match_faixa.group(1)
                    if onu_id_em_faixa(onu_id, faixa):
                        data["commands"].append(line.strip())

    return list(onu_data.values())[0] if onu_data else None

def buscar_onu_zte(serial, lines):
    dados_onu = {}
    serial = serial.lower()
    chassi_atual, slot_atual, pon_atual = None, None, None
    capture_commands_interface, capture_commands_mng, capture_commands_vport = False, False, False
    #Regex
    interface_pattern = re.compile(r'interface\s+gpon(?:_|-)olt(?:_|-)(\d+)/(\d+)/(\d+)', re.IGNORECASE)
    interface_onu_pattern = re.compile(r'interface\s+gpon(?:-|_)onu(?:-|_)?(\d+)/(\d+)/(\d+):(\d+)', re.IGNORECASE)
    interface_vport_pattern = re.compile(r'interface\svport-(\d+)/(\d+)/(\d+).(\d+):\d+', re.IGNORECASE)
    pon_onu_mng_pattern = re.compile(r'pon-onu-mng\s+gpon(?:-|_)onu(?:-|_)?(\d+)/(\d+)/(\d+):(\d+)', re.IGNORECASE)
    onu_pattern = re.compile(r'onu\s+(\d+)\s+type\s+\S+\s+sn\s+(\S+)', re.IGNORECASE)
    delimitadores_fim = ('end', 'exit', 'hostname', '!', '', '$')
    
    for line in lines:
        line = line.strip()

        if line.lower() in delimitadores_fim:
            if serial in dados_onu and (
                capture_commands_interface or
                capture_commands_mng or
                capture_commands_vport
            ):
                dados_onu[serial]["commands"].append("!")
                capture_commands_interface = False
                capture_commands_mng = False
                capture_commands_vport = False
            continue

    
        #Correspondência da interface gpon
        match_interface = interface_pattern.match(line)
        #print(match_interface)
        if match_interface:
            chassi_atual, slot_atual, pon_atual = match_interface.groups()
            continue
        
        #Procurar correspendências de ONU's
        match_onu = onu_pattern.match(line)
        #print(match_onu)
        if match_onu:
            id, serial_number = match_onu.groups()
            if serial_number.lower() == serial:
                id_onu = int(id)
                dados_onu[serial] = {
                    "chassi":int(chassi_atual),
                    "slot": int(slot_atual),
                    "pon": int(pon_atual),
                    "id": id_onu,
                    "commands": [line]
                    
                }
            elif serial in dados_onu:
                capture_commands_interface = False

        #Procurar correspendências de interface ONU
        match_interface_onu = interface_onu_pattern.match(line)
        #print(match_interface_onu)
        if match_interface_onu:
            chassi_str,slot_str,pon_str, id_interface = match_interface_onu.groups()
            slotpon_str = f"{chassi_str}/{slot_str}/{pon_str}"
            if serial in dados_onu:
                if slotpon_str == f"{dados_onu[serial]['chassi']}/{dados_onu[serial]['slot']}/{dados_onu[serial]['pon']}" and int(id_interface) == dados_onu[serial]['id']:
                    capture_commands_interface = True
                    dados_onu[serial]["commands"].append(line)
                elif capture_commands_interface:
                    capture_commands_interface = False
                    
            continue
        if capture_commands_interface and serial in dados_onu:
            dados_onu[serial]["commands"].append(line)


        #Procurar correspendências de Vport
        match_interface_vport = interface_vport_pattern.match(line)
        #print(match_interface_vport)
        if match_interface_vport:
            chassi_str,slot_str,pon_str, id_vport = match_interface_vport.groups()
            slotpon_str = f"{chassi_str}/{slot_str}/{pon_str}"
            if serial in dados_onu:
                if slotpon_str == f"{dados_onu[serial]['chassi']}/{dados_onu[serial]['slot']}/{dados_onu[serial]['pon']}" and int(id_vport) == dados_onu[serial]['id']:
                    capture_commands_vport = True
                    dados_onu[serial]["commands"].append(line)
                elif capture_commands_vport:
                    capture_commands_vport = False
                    
            continue
        if capture_commands_vport and serial in dados_onu:
            dados_onu[serial]["commands"].append(line)
            

        #Procurar correspendências de ONU MNG        
        match_pon_onu_mng = pon_onu_mng_pattern.match(line)
        #print(match_pon_onu_mng)
        if match_pon_onu_mng:
            chassi_str, slot_str, pon_str, id_mng  = match_pon_onu_mng.groups()
            slotpon_str = f"{chassi_str}/{slot_str}/{pon_str}"
            if serial in dados_onu:
                if slotpon_str == f"{dados_onu[serial]['chassi']}/{dados_onu[serial]['slot']}/{dados_onu[serial]['pon']}" and int(id_mng) == dados_onu[serial]['id']:
                    capture_commands_mng = True
                    dados_onu[serial]["commands"].append(line)
                elif capture_commands_mng:
                    capture_commands_mng = False
                    dados_onu[serial]["commands"].append("!")
            continue

        if capture_commands_mng and serial in dados_onu:
            dados_onu[serial]["commands"].append(line)
            continue
    return dados_onu.get(serial)

            


    return list(onu_data.values())[0] if onu_data else None

def buscar_onu_datacom(serial, lines):  
    serial = serial.lower()
    dados_onu = {}
    chassi_atual, slot_atual, pon_atual = None, None, None
    capture_commands_onu = False
    #Regex
    interface_gpon_pattern = re.compile(r'interface\sgpon\s(\d+)/(\d+)/(\d+)', re.IGNORECASE)
    onu_pattern = re.compile(r'onu\s(\d+)', re.IGNORECASE)
    onu_serial_pattern = re.compile(r'serial-number\s(\S+)', re.IGNORECASE)
    service_port_regex = re.compile(
        r'service-port\s+(\d+)\s*(?:\s|\n)\s*gpon\s+(\d+)/(\d+)/(\d+)\s+onu\s+(\d+).*',
        re.IGNORECASE
    )
    # Inicio do laço
    for line in lines:
        line = line.strip()
        #Captura interface
        match_interface = interface_gpon_pattern.match(line)
        if match_interface:
            if capture_commands_onu:
                break
            chassi_atual, slot_atual, pon_atual = match_interface.groups()
            continue
        #Captura ID da onu    
        match_onu = onu_pattern.match(line)
        if match_onu:
            id_str = match_onu.group(1)
            if capture_commands_onu and novo_id != int(id_str):
                break
            novo_id = int(id_str)
        #Captura serial
        match_serial_regex = onu_serial_pattern.match(line)
        if match_serial_regex:
            serial_str = match_serial_regex.group(1)
            if serial_str.lower() == serial:
                dados_onu[serial] = {
                    "chassi": int(chassi_atual),
                    "slot": int(slot_atual),
                    "pon": int(pon_atual),
                    "id": int(id_str),
                    "commands": [
                        f"interface gpon {chassi_atual}/{slot_atual}/{pon_atual}",
                        f"onu {id_str}",
                        f"serial-number {serial_str}"
                    ]
                }
                capture_commands_onu = True
            continue
        #Captura enquanto houver o serial informado dentro dos dados da onu    
        if capture_commands_onu and serial in dados_onu:
            dados_onu[serial]["commands"].append(line)

    if serial not in dados_onu:
        return None
    #Inicio laço service port
    for i in range(len(lines) - 2):
        linha1 = lines[i+1].strip()
        linha2 = lines[i+2].strip()
        bloco = f"{linha1}\n{linha2}"
        match_sp = service_port_regex.match(bloco)
        if match_sp:
            sp_id, chassi_sp, slot_sp, pon_sp, onu_sp = match_sp.groups()
            if (int(chassi_sp), int(slot_sp), int(pon_sp), int(onu_sp)) == (
                dados_onu[serial]["chassi"],
                dados_onu[serial]["slot"],
                dados_onu[serial]["pon"],
                dados_onu[serial]["id"]
            ):
                dados_onu[serial]["commands"].append(bloco)

    return dados_onu.get(serial)

def buscar_onu_parks(serial, lines):
    serial = serial.lower()
    dados_onu = {}
    slot_atual, pon_atual = None, None
    capture_commands_onu = False

    interface_gpon_pattern = re.compile(r'interface\s+gpon(\d+)/(\d+)', re.IGNORECASE)
    onu_pattern = re.compile(r'onu\s+add\s+serial-number\s+(\S+)', re.IGNORECASE)

    for line in lines:
        line = line.strip()
        #Captura interface
        match_interface = interface_gpon_pattern.match(line)
        if match_interface:
            if capture_commands_onu:
                break
            slot_atual, pon_atual = match_interface.groups()
            continue
        #Captura info da onu    
        match_onu = onu_pattern.match(line)
        if match_onu:
            serial_number_str = match_onu.group(1)
            if serial_number_str.lower() == serial:
                dados_onu[serial] = {
                    "slot": slot_atual,
                    "pon": pon_atual,
                    "serial": serial_number_str,
                    "commands": [
                        f"interface gpon{slot_atual}/{pon_atual}",
                        line
                    ]
                }
                capture_commands_onu = True
            continue
        #Controle de captura de comandos, para quando a onu mudar ou quando não tiver o comando onu serial
        if capture_commands_onu and serial in dados_onu:
            match_outro_onu = re.match(r'onu\s+(\S+)', line, re.IGNORECASE)
            if match_outro_onu:
                if match_outro_onu.group(1).lower() != serial and len(dados_onu[serial]['commands']) > 2:
                    break
            if f"onu {dados_onu[serial]['serial']}" in line:        
                dados_onu[serial]["commands"].append(line)
            else:
                break
    if serial not in dados_onu:
        return None
    return dados_onu.get(serial)

def buscar_onu_huawei(serial, lines):
    serial = serial.lower()
    dados_onu = {}
    chassi_atual, slot_atual = None, None
    capture_commands_onu = False
    slot_ref = pon_ref = id_ref = None

    interface_gpon_pattern = re.compile(r'interface\s+gpon\s+(\d+)/(\d+)', re.IGNORECASE)
    onu_pattern = re.compile(r'ont\s+add\s+(\d+)\s+(\d+)\s+sn-auth\s+"([^"]+)"',re.IGNORECASE | re.DOTALL)
    comando_onu_generic = re.compile(r'ont\s+\S+\s+(\d+)\s+(\d+)', re.IGNORECASE)

    for line in lines:
        line = line.strip()

        # Captura interface GPON
        match_interface = interface_gpon_pattern.match(line)
        if match_interface:
            chassi_atual, slot_atual = match_interface.groups()

        # Captura ont add com serial
        match_onu = onu_pattern.search(line)
        if match_onu:
            pon, id_onu, serial_onu = match_onu.groups()
            print(serial_onu.lower(), serial)
            if serial_onu.lower() == serial:
                slot_ref = int(slot_atual)
                pon_ref = int(pon)
                id_ref = int(id_onu)
                dados_onu[serial] = {
                    "chassi": int(chassi_atual),
                    "slot": slot_ref,
                    "pon": pon_ref,
                    "id": id_ref,
                    "serial": serial_onu,
                    "commands": [line]
                }
                capture_commands_onu = True
            continue
        #Captura as linhas de comandos   
        if capture_commands_onu and serial in dados_onu:
            match_cmd = comando_onu_generic.search(line)
            if match_cmd:
                pon_cmd, id_cmd = map(int, match_cmd.groups())
                if pon_cmd != pon_ref or id_cmd != id_ref:
                    break
            dados_onu[serial]["commands"].append(line)

    # ONT PORT e SERVICE PORT
    if serial in dados_onu:
        for line in lines:
            print (line)
            line = line.strip()
            chassi = pon = dados_onu[serial]["chassi"]
            slot = pon = dados_onu[serial]["slot"]
            pon = dados_onu[serial]["pon"]
            onu_id = dados_onu[serial]["id"]
            if re.search(rf"ont\s+port\s+native-vlan\s+{pon}\s+{onu_id}", line, re.IGNORECASE) or \
               re.search(rf"ont\s+port\s+route\s+{pon}\s+{onu_id}", line, re.IGNORECASE):
                dados_onu[serial]["commands"].append(line)
            if re.search(rf"service-port\s+\d+\s+vlan\s+\d+\s+gpon\s+{chassi}/{slot}/{pon}\s+ont\s+{onu_id}", line, re.IGNORECASE):
                dados_onu[serial]["commands"].append(line)

    return dados_onu.get(serial)

def conectar_telnet_fiberhome(ip, usuario, senha_login, senha_enable, porta=23):
    print(f"Conectando via Telnet na OLT {ip}:{porta} (Fiberhome)...")
    tn = telnetlib.Telnet(ip, porta, timeout=10)
    tn.read_until(b"Username:", timeout=5)
    tn.write(usuario.encode('ascii') + b"\n")
    tn.read_until(b"Password:", timeout=5)
    tn.write(senha_login.encode('ascii') + b"\n")
    time.sleep(1)

    tn.write(b"terminal length 0\n")
    time.sleep(0.5)
    tn.write(b"enable\n")
    time.sleep(0.5)
    tn.write(senha_enable.encode('ascii') + b"\n")
    time.sleep(0.5)
    tn.write(b"show startup-config\n")
    time.sleep(1)

    saida = b""
    timeout_total = 60
    inicio = time.time()

    while True:
        saida += tn.read_very_eager()
        linhas = saida.decode('utf-8', errors='ignore').splitlines()
        if any(l.strip().startswith("!@@@@time:") for l in linhas):
            break
        if time.time() - inicio > timeout_total:
            print("⚠ Tempo limite excedido. A saída pode estar incompleta.")
            break
        time.sleep(0.5)

    output = saida.decode('utf-8', errors='ignore')
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()

def conectar_telnet_zte(ip, usuario, senha, porta=23):
    print(f"Conectando via Telnet na OLT ZTE {ip}:{porta}...")
    tn = telnetlib.Telnet(ip, porta, timeout=10)

    tn.read_until(b"Username:", timeout=5)
    tn.write(usuario.encode('ascii') + b"\n")
    tn.read_until(b"Password:", timeout=5)
    tn.write(senha.encode('ascii') + b"\n")
    time.sleep(1)
    tn.write(b"terminal length 0\n")
    time.sleep(0.5)
    tn.write(b"show running-config\n")
    time.sleep(1)
    saida_prompt= tn.read_until(b"#", timeout=5)

    linhas_prompt = saida_prompt.strip().split(b"\n")
    if len(linhas_prompt) >= 2:
        linha_prompt = linhas_prompt[-1].strip()
    else:
        linha_prompt = saida_prompt.strip()

    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", linha_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"ZXAN"

    saida = b""
    timeout_total = 90
    inicio = time.time()

    while True:
        try:
            saida += tn.read_very_eager()
            if  b"end\r\n" in saida:
                print ("saida encontrada")
                break
            time.sleep(0.5)
        except EOFError:
            break

    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()

def conectar_ssh_zte(ip, usuario, senha, porta=22):
    print(f"Conectando via SSH na OLT ZTE {ip}:{porta}...")
    try:
        # Cria o transporte com ciphers e kex compatíveis
        transport = paramiko.Transport((ip, porta))
        transport.get_security_options().ciphers = [
            'aes128-cbc', 'aes256-cbc', '3des-cbc'
        ]
        transport.get_security_options().kex = [
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1'
        ]
        transport.connect(username=usuario, password=senha)
        # Cria o cliente com o transport definido
        client = paramiko.SSHClient()
        client._transport = transport

        shell = client.invoke_shell()
        shell.settimeout(1)
        # Aguarda prompt inicial
        time.sleep(1)
        shell.send('\n')
        time.sleep(1)
        output = shell.recv(4096)
        match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", output)
        prompt_name = match_prompt.group(1) if match_prompt else b"ZXAN"
        #print(f"Prompt identificado: {prompt_name.decode(errors='ignore')}")
        # Comandos para obter a config
        shell.send("terminal length 0\n")
        time.sleep(1)
        shell.send("show running-config\n")
        time.sleep(1)
        saida = b""
        timeout_total = 90
        inicio = time.time()
        while True:
            try:
                saida += shell.recv(4096)
                if b"end\r\n" + prompt_name + b"#" in saida:
                    break
                if time.time() - inicio > timeout_total:
                    print("⚠ Tempo limite excedido. Saída pode estar incompleta.")
                    break
                time.sleep(0.5)
            except Exception:
                break
        with open("saida_startup_config.txt", "w") as f:
            f.write(saida.decode(errors='ignore'))
        linhas = saida.decode(errors='ignore').splitlines()
        return linhas
    except Exception as e:
        return []

def conectar_ssh_datacom(ip, usuario, senha, porta=22):
    print(f"Conectando via SSH na OLT Datacom {ip}:{porta}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=usuario, password=senha, port=porta)

    shell = client.invoke_shell()
    shell.settimeout(1)

    def esperar_prompt(timeout=5):
        saida = b""
        inicio = time.time()
        while True:
            if time.time() - inicio > timeout:
                break
            try:
                saida += shell.recv(1024)
                if b"#" in saida:
                    break
            except:
                pass
        return saida

    # Aguardar prompt inicial
    saida_prompt = esperar_prompt()
    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", saida_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"DATACOM"
    print(prompt_name)

    shell.send("paginate false\n")
    time.sleep(0.5)
    shell.send("show running-config\n")
    time.sleep(1)

    saida = b""
    timeout_total = 90
    inicio = time.time()

    while True:
        try:
            saida += shell.recv(4096)
            if prompt_name + b"#" in saida:
                print("saida encontrada")
                break
            if time.time() - inicio > timeout_total:
                print("⚠ Tempo limite excedido. Saída pode estar incompleta.")
                break
            time.sleep(0.5)
        except:
            break

    client.close()
    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()

def conectar_telnet_datacom(ip, usuario, senha, porta=23):
    print(f"Conectando via Telnet na OLT Datacom {ip}:{porta}...")
    tn = telnetlib.Telnet(ip, porta, timeout=10)
    
    tn.read_until(b"Username:", timeout=5)
    tn.write(usuario.encode('ascii') + b"\n")
    tn.read_until(b"Password:", timeout=5)
    tn.write(senha.encode('ascii') + b"\n")
    time.sleep(1)
    
    saida_prompt= tn.read_until(b"#", timeout=5)
    tn.write(b"paginate false\n")
    time.sleep(0.5)
    tn.write(b"show running-config\n")
    time.sleep(1)

    saida_prompt = tn.read_until(b"#", timeout=5)
    linhas_prompt = saida_prompt.strip().split(b"\n")
    if len(linhas_prompt) >= 2:
        linha_prompt = linhas_prompt[-1].strip()
    else:
        linha_prompt = saida_prompt.strip()

    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", linha_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"DATACOM"
    
    saida = b""
    timeout_total = 90
    inicio = time.time()
    
    while True:
        try:
            saida += tn.read_very_eager()
            #print(saida_decodificada)
            if prompt_name + b"#" in saida:
                print ("saida encontrada")
                break
            time.sleep(0.5)
        except EOFError:
            break

    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()
 
def conectar_telnet_parks(ip, usuario, senha, porta=23):
    print(f"Conectando via Telnet na OLT Parks {ip}:{porta}...")
    tn = telnetlib.Telnet(ip, porta, timeout=10)
    
    tn.read_until(b"Username:", timeout=5)
    tn.write(usuario.encode('ascii') + b"\n")
    tn.read_until(b"Password:", timeout=5)
    tn.write(senha.encode('ascii') + b"\n")
    time.sleep(1)
    
    saida_prompt= tn.read_until(b"#", timeout=5)
    tn.write(b"terminal length 0\n")
    time.sleep(0.5)
    tn.write(b"show running-config\n")
    time.sleep(1)

    saida_prompt = tn.read_until(b"#", timeout=5)
    linhas_prompt = saida_prompt.strip().split(b"\n")
    if len(linhas_prompt) >= 2:
        linha_prompt = linhas_prompt[-1].strip()
    else:
        linha_prompt = saida_prompt.strip()

    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", linha_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"PARKS"
    
    saida = b""
    timeout_total = 90
    inicio = time.time()
    
    while True:
        try:
            saida += tn.read_very_eager()
            print(saida)
            #print(saida_decodificada)
            if prompt_name + b"#" in saida:
                print ("saida encontrada")
                break
            time.sleep(0.5)
        except EOFError:
            break

    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()
 
def conectar_ssh_parks(ip, usuario, senha, porta=23):
    print(f"Conectando via SSH na OLT Parks {ip}:{porta}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=usuario, password=senha, port=porta)

    shell = client.invoke_shell()
    shell.settimeout(1)

    def esperar_prompt(timeout=5):
        saida = b""
        inicio = time.time()
        while True:
            if time.time() - inicio > timeout:
                break
            try:
                saida += shell.recv(1024)
                if b"#" in saida:
                    break
            except:
                pass
        return saida

    # Aguardar prompt inicial
    saida_prompt = esperar_prompt()
    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", saida_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"Parks"
    print(prompt_name + b"#")

    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.send("show running-config\n")
    time.sleep(1)

    saida = b""
    timeout_total = 90
    inicio = time.time()

    while True:
        try:
            saida += shell.recv(4096)
            if saida.strip().endswith(prompt_name + b"#"):
                print("saida encontrada")
                break
            if time.time() - inicio > timeout_total:
                print("⚠ Tempo limite excedido. Saída pode estar incompleta.")
                break
            time.sleep(0.5)
        except:
            break

    client.close()
    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()

def conectar_ssh_huawei(ip, usuario, senha, porta=22):
    print(f"Conectando via SSH na OLT Huawei {ip}:{porta}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=usuario, password=senha, port=porta)

    shell = client.invoke_shell()
    shell.settimeout(1)

    def esperar_prompt(timeout=15):
        saida = b""
        inicio = time.time()
        while True:
            if time.time() - inicio > timeout:
                break
            try:
                saida += shell.recv(1024)
                if b"#" in saida:
                    break
            except:
                pass
        return saida



    shell.send("enable\n")
    time.sleep(0.5)

    # Aguardar prompt inicial
    saida_prompt = esperar_prompt()
    print(saida_prompt)
    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", saida_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"HUAWEI"
    print(prompt_name + b"#")
    #################################################################
    shell.send("scroll\n")
    time.sleep(1)
    shell.send("\n")
    time.sleep(2) 
    shell.send("display current-configuration\n")
    time.sleep(1)
    shell.send("\n")
    time.sleep(2) 

    saida = b""
    timeout_total = 90
    inicio = time.time()

    while True:
        try:
            saida += shell.recv(4096)
            if saida.strip().endswith(prompt_name + b"#"):
                print("saida encontrada")
                break
            if time.time() - inicio > timeout_total:
                print("⚠ Tempo limite excedido. Saída pode estar incompleta.")
                break
            time.sleep(0.5)
        except:
            break

    client.close()
    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()

def conectar_telnet_huawei(ip, usuario, senha, porta=23):
    print(f"Conectando via Telnet na OLT Huawei {ip}:{porta}...")
    tn = telnetlib.Telnet(ip, porta, timeout=10)
    
    tn.read_until(b"Username:", timeout=5)
    tn.write(usuario.encode('ascii') + b"\n")
    tn.read_until(b"Password:", timeout=5)
    tn.write(senha.encode('ascii') + b"\n")
    time.sleep(1)
    
    saida_prompt= tn.read_until(b"#", timeout=5)
    tn.write(b"enable\n")
    time.sleep(0.5)
    #CAPTURAR NOME DA OLT
    saida_prompt = tn.read_until(b"#", timeout=5)
    print(saida_prompt)
    linhas_prompt = saida_prompt.strip().split(b"\n")
    print(linhas_prompt)
    if len(linhas_prompt) >= 2:
        linha_prompt = linhas_prompt[-1].strip()
    else:
        linha_prompt = saida_prompt.strip()

    match_prompt = re.search(rb"([A-Za-z0-9_\-]+)#", linha_prompt)
    print(match_prompt)
    prompt_name = match_prompt.group(1) if match_prompt else b"HUAWEI"
    print(prompt_name)

    tn.write(b"scroll\n")
    time.sleep(1)
    tn.write(b"\n")
    time.sleep(2)
    tn.write(b"display current-configuration\n")
    time.sleep(1)
    tn.write(b"\n")
    time.sleep(2)

    saida = b""
    timeout_total = 90
    inicio = time.time()
    
    while True:
        try:
            saida += tn.read_very_eager()
            #print(saida_decodificada)
            if saida.strip().endswith(prompt_name + b"#"):
                print ("saida encontrada")
                break
            time.sleep(0.5)
        except EOFError:
            break

    output = saida.decode('utf-8', errors='ignore').strip()
    with open("saida_startup_config.txt", "w") as f:
        f.write(output)
    return output.splitlines()
    
def menu_olt():
    print("Selecione o modelo de OLT: ")
    print("[1] - Fiberhome")
    print("[2] - ZTE")
    print("[3] - Datacom ")
    print("[4] - Parks ")
    print("[5] - Huawei ")
    while True:
        escolha = input("Escolha: ").strip()
        if escolha in ('1', '2', '3', '4', '5'):
            return escolha
        else:
            print("Inválido")
def menu_protocolo():
    print("Selecione o protocolo SSH ou Telnet: ")
    print("[1] - SSH")
    print("[2] - Telnet")
    while True:
        escolha = input("Escolha: ").strip()
        if escolha in ('1', '2'):
            return int(escolha)
        else:
            print("Inválido")

if __name__ == "__main__":
    tipo_olt = menu_olt()
    protocolo = menu_protocolo()
    
    """
    parser = argparse.ArgumentParser(description="Buscar ONU por serial em OLT")
    parser.add_argument("--zte", action="store_true", help="Modo ZTE")
    parser.add_argument("--datacom", action="store_true", help="Modo Datacom")
    parser.add_argument("--ssh", action="store_true", help="Usar SSH")
    parser.add_argument("--telnet", action="store_true", help="Usar Telnet")
    args = parser.parse_args()
    """
    ip_olt = input("IP da OLT: ")
    porta = int(input("Porta: "))
    usuario = input("Usuário: ")
    senha_login = input("Senha do login: ")
    senha_enable = None
    """
    if not args.zte and not args.datacom:
        senha_enable = input("Senha do enable: ")
        if not senha_enable:
            senha_enable = senha_login
    serial = input("Serial da ONU: ").strip()
    """
    """
    if args.zte:
        if args.ssh:
            linhas_config = conectar_ssh_zte(ip_olt, usuario, senha_login, porta)
        elif args.telnet:
            linhas_config = conectar_telnet_zte(ip_olt, usuario, senha_login, porta)
        else:
            raise Exception("Informe --ssh ou --telnet para OLT ZTE.")
        resultado = buscar_onu_zte(serial, linhas_config)
    elif args.datacom:
        if args.ssh:
            linhas_config = conectar_ssh_datacom(ip_olt, usuario, senha_login, porta)
        elif args.telnet:
            linhas_config = conectar_telnet_datacom(ip_olt, usuario, senha_login, porta)
        else:
            raise Exception("Informe --ssh ou --telnet para OLT Datacom")
        resultado = buscar_onu_datacom(serial, linhas_config)
    else:
        linhas_config = conectar_telnet_fiberhome(ip_olt, usuario, senha_login, senha_enable, porta)
        resultado = buscar_onu_fiberhome(serial, linhas_config)
    """
    if tipo_olt == "1":
        senha_enable = input("Senha do enable: ") or senha_login
        serial = input("Serial da ONU: ").strip()
        linhas_config = conectar_telnet_fiberhome(ip_olt, usuario, senha_login, senha_enable, porta)
        resultado = buscar_onu_fiberhome(serial, linhas_config)
    elif tipo_olt == "2":
        serial = input("Serial da ONU: ").strip()
        if protocolo == 1:
            linhas_config = conectar_ssh_zte(ip_olt, usuario, senha_login, porta)
        else:
            linhas_config = conectar_telnet_zte(ip_olt, usuario, senha_login, porta)
        resultado = buscar_onu_zte(serial, linhas_config)
    elif tipo_olt == "3":
        serial = input("Serial da ONU: ").strip()
        if protocolo == 1:
            linhas_config = conectar_ssh_datacom(ip_olt, usuario, senha_login, porta)
        else:
            linhas_config = conectar_telnet_datacom(ip_olt, usuario, senha_login, porta)
        resultado = buscar_onu_datacom(serial, linhas_config)
    elif tipo_olt == "4":
        serial = input("Serial da ONU: ").strip()
        if protocolo == 1:
            print(protocolo)
            linhas_config = conectar_ssh_parks(ip_olt, usuario, senha_login, porta)
        else:
            linhas_config = conectar_telnet_parks(ip_olt, usuario, senha_login, porta)
        resultado = buscar_onu_parks(serial, linhas_config)
    elif tipo_olt == "5":
        serial = input("Serial da ONU: ").strip()
        if protocolo == 1:
            print(protocolo)
            linhas_config = conectar_ssh_huawei(ip_olt, usuario, senha_login, porta)
        else:
            linhas_config = conectar_telnet_huawei(ip_olt, usuario, senha_login, porta)
        resultado = buscar_onu_huawei(serial, linhas_config)

        
    if resultado:
        print(f"\nComandos da ONU {serial}:\n")
        print("=" * 50)
        for cmd in resultado["commands"]:
            print(cmd)
        print("=" * 50)
        with open(f"comandos_onu_{serial}.txt", "w") as f:
            for cmd in resultado["commands"]:
                f.write(cmd + "\n")
        print(f"Arquivo 'comandos_onu_{serial}.txt' salvo com sucesso.")
    else:
        print("Serial não encontrado no startup-config.")
        print("Verifique manualmente o arquivo 'saida_startup_config.txt'.")