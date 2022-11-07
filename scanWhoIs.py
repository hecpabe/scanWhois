

"""
    Título: Scan Who Is
    Nombre: Héctor Paredes Benavides
    Descripción: Creamos un script que obtenga el whois de un dominio, compruebe filtraciones y realice escaneo de puertos
    Fecha: 3/11/2022
"""

# ========== Inclusión de bibliotecas ==========
import requests
import re
import sys
import subprocess

# ========== Declaraciones Globales ==========
DOMAINS_COLUMNS = ["Hostname", "Type", "TTL", "Priority", "Content"]

# ========== Función Principal Main ==========
"""
    Nombre: Main
    Descripción: Función con la que inicializamos el programa
    Parámetros: Ninguno
    Retorno: Ninguno
    Precondición: Ninguna
"""
def main():

    # Solicitamos un dominio
    domain = input("Introduzca un dominio: ")
    
    # Obtenemos el whois y el DNS Record
    whois = getWhois(domain)
    domainsRecord = getDomains(domain)

    # Mostramos el whois
    showWhois(whois["WhoisRecord"])

    # Mostramos los servidores NS
    showNS(domainsRecord)

    # Mostramos los servidores MX
    showMX(domainsRecord)

    # Obtenemos los dominios de servidores MX
    mxServers = getMX(domainsRecord)

    # Mostramos las filtraciones de los dominios
    for mx in mxServers:
        showDomainBreaches(mx)

    # Realizamos el ping y si conseguimos obtener la ip realizamos el nmap    
    ipAddress = makePing(domain)
    if ipAddress != None:
        makePortScan(ipAddress)

# ========== Codificación de Funciones ==========
"""
    Nombre: Get Domains
    Descripción: Función con la que obtenemos los diferentes servidores de DNS que tiene un dominio
    Parámetros:
        0: [STRING] Dominio del que sacar la información
    Retorno: [LISTA DE DICCIONARIOS] Lista con los diccionarios con la información de los diferentes servidores 
    Precondición: No se asegura una correcta ejecución si el dominio no existe
    Complejidad Temporal: O(n) n->Número de servidores obtenidos
    Complejidad Espacial: O(n) n->Número de servidores obtenidos
"""
def getDomains(domain):

    domains = []

    # Obtenemos el HTML del apartado de DNS Record
    response = requests.get("https://who.is/dns/" + domain).text.split("\n")

    # Obtenemos la tabla HTML con la información que buscamos
    for row in response:
        if "table" in row:
            table = row
            break
    
    # Obtenemos las diferentes filas de la tabla e insertamos los datos en la lista de dominios
    for tableRow in table.split("<tr>"):
        if "<td>" in tableRow:
            tableRowList = list(filter(None, tableRow.split("<td>")))
            counter = 0
            newDomain = {}
            for tableRowListColumn in tableRowList:
                newDomain[DOMAINS_COLUMNS[counter]] = tableRowListColumn.replace("<td>", "").replace("</td>", "") \
                    .replace("</tr>", "").replace("</tbody>", "").replace("</table>", "").replace("</div>", "")
                counter += 1
            domains.append(newDomain)
    
    # Retornamos los dominios obtenidos
    return domains

"""
    Nombre: Get Whois
    Descripción: Función con la que obtenemos la información del Whois de un dominio en formato JSON
    Parámetros: 
        0: [STRING] Dominio del que sacar la información
    Retorno: [DICCIONARIO] JSON con la información del dominio solicitado
    Precondición: La conexión con la API debe funcionar correctamente
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def getWhois(domain):
    
    # Obtenemos el json y lo retornamos
    return requests.get("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_5QU5RrGmgcqUEZEhG3Kv94FdJeqnM&outputFormat=JSON&domainName=" + domain).json()

"""
    Nombre: Show Whois
    Descripción: Función con la que mostramos los datos obtenidos del registro Whois
    Parámetros:
        0: [DICCIONARIO] JSON del registro Whois obtenido de la función Get Whois
    Retorno: Ninguno
    Precondición: El registro Whois debe haberse obtenido correctamente previamente mediante la función Get Whois
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def showWhois(whoisRecord):

    print("\n\n=========== DATOS WHOIS ==========")

    # Mostramos los datos del Registrar
    print("----- Registrar Info -----")
    print("\tName: " + whoisRecord["registrarName"])
    print("\tWhois Server: " + whoisRecord["registryData"]["whoisServer"])
    print("\tStatus: ")
    
    status = whoisRecord["status"]
    for eachStatus in status.split(" "):
        print("\t\t- " + eachStatus)

    # Mostramos las fechas importantes
    print("\n----- Important Dates -----")
    print("\tExpires On: " + whoisRecord["expiresDate"])
    print("\tRegistered On: " + whoisRecord["createdDate"])
    print("\tUpdated On: " + whoisRecord["updatedDate"])

    # Mostramos los Name Servers
    print("\n----- Name Servers -----")
    for nameServer in whoisRecord["nameServers"]["hostNames"]:
        print("DNS: " + nameServer)
    
    # Mostramos los datos del Registrant
    print("\n----- Registrant Contact Information -----")
    print("\tName: " + whoisRecord["registrant"]["name"])
    print("\tOrganization: " + whoisRecord["registrant"]["organization"])

    for address in whoisRecord["registrant"]["street1"].split("\n"):
        print("\tAddress: " + address)
    
    print("\tCity: " + whoisRecord["registrant"]["city"])
    print("\tState / Province: " + whoisRecord["registrant"]["state"])
    print("\tPostal Code: " + whoisRecord["registrant"]["postalCode"])
    print("\tCountry: " + whoisRecord["registrant"]["countryCode"])
    print("\tPhone: " + whoisRecord["registrant"]["telephone"])
    print("\tFax: " + whoisRecord["registrant"]["fax"])

    # Mostramos la información del Administrativo
    print("\n----- Administrative Contact Information -----")
    print("\tName: " + whoisRecord["administrativeContact"]["name"])
    print("\tOrganization: " + whoisRecord["administrativeContact"]["organization"])
    
    for address in whoisRecord["administrativeContact"]["street1"].split("\n"):
        print("\tAddress: " + address)
    
    print("\tCity: " + whoisRecord["administrativeContact"]["city"])
    print("\tState / Province: " + whoisRecord["administrativeContact"]["state"])
    print("\tPostal Code: " + whoisRecord["administrativeContact"]["postalCode"])
    print("\tCountry: " + whoisRecord["administrativeContact"]["countryCode"])
    print("\tPhone: " + whoisRecord["administrativeContact"]["telephone"])
    print("\tFax: " + whoisRecord["administrativeContact"]["fax"])

    # Mostramos la información del Técnico
    print("\n----- Technical Contact Information -----")
    print("\tName: " + whoisRecord["technicalContact"]["name"])
    print("\tOrganization: " + whoisRecord["technicalContact"]["organization"])
    
    for address in whoisRecord["technicalContact"]["street1"].split("\n"):
        print("\tAddress: " + address)
    
    print("\tCity: " + whoisRecord["technicalContact"]["city"])
    print("\tState / Province: " + whoisRecord["technicalContact"]["state"])
    print("\tPostal Code: " + whoisRecord["technicalContact"]["postalCode"])
    print("\tCountry: " + whoisRecord["technicalContact"]["countryCode"])
    print("\tPhone: " + whoisRecord["technicalContact"]["telephone"])
    print("\tFax: " + whoisRecord["technicalContact"]["fax"])

"""
    Nombre: Show NS
    Descripción: Función con la que mostramos la información de los diferentes servidores DNS de tipo NS
    Parámetros: 
        0: [LISTA DE DICCIONARIOS] Lista con la información de los diferentes dominios obtenidos mediante la función Get Domains
    Retorno: Ninguno.
    Precondición: Los dominios tienen que haberse obtenido previamente mediante la función Get Domains
    Complejidad Temporal: O(n) n->Número de servidores del dominio
    Complejidad Espacial: O(1)
"""
def showNS(domains):

    print("\n========== Servidores NS ==========")

    counter = 1

    # Mostramos los datos de los servidores NS
    for domain in domains:
        if domain["Type"] == "NS":
            print("----- Servidor " + str(counter) + " -----")
            for key, value in domain.items():
                print(key + ": " + value)
            print("")
            counter += 1

"""
    Nombre: Show MX
    Descripción: Función con la que mostramos la información de los diferentes servidores DNS de tipo MX
    Parámetros:
        0: [LISTA DE DICCIONARIOS] Lista con la información de los diferentes dominios obtenidos mediante la función Get Domains
    Retorno: Ninguno.
    Precondición: Los dominios tienen que haberse obtenido previamente mediante la función Get Domains
    Complejidad Temporal: O(n) n->Número de servidores del dominio
    Complejidad Espacial: O(1)
"""
def showMX(domains):

    print("\n========== Servidores MX ==========")

    counter = 1

    # Mostramos los datos de los servidores MX
    for domain in domains:
        if domain["Type"] == "MX":
            print("----- Servidor " + str(counter) + " -----")
            for key, value in domain.items():
                print(key + ": " + value)
            print("")
            counter += 1

"""
    Nombre: Get MX
    Descripción: Función con la que obtenemos una lista de los servidores DNS de tipo MX
    Parámetros: 
        0: [LISTA DE DICCIONARIOS] Lista con la información de los diferentes dominios obtenidos mediante la función Get Domains
    Retorno: Ninguno.
    Precondición: Los dominios tienen que haberse obtenido previamente mediante la función Get Domains
    Complejidad Temporal: O(n) n->Número de servidores del dominio
    Complejidad Espacial: O(n) n->Número de servidores DNS de tipo MX del dominio
"""
def getMX(domains):

    mxDomains = []

    for domain in domains:
        if domain["Type"] == "MX":
            mxDomains.append(domain["Hostname"])

    return mxDomains

"""
    Nombre: Show Domain Breaches
    Descripción: Función con la que mostramos las diferentes filtraciones de los correos con el dominio especificado
    Parámetros:
        0: [STRING] Nombre de dominio de tipo MX a comprobar filtraciones
    Retorno: Ninguno
    Precondición: Ninguna.
    Complejidad Temporal: O(n) n->Número de filtraciones para ese dominio
    Complejidad Espacial: O(1)
"""
def showDomainBreaches(mx):

    # Obtenemos los leaks de diferentes páginas
    haveibeenpwnedBreaches = getHaveibeenpwnedBreaches(mx)

    print("========== Leaks para " + mx + " ==========")
    print("===== Leaks de haveibeenpwned =====")

    # Si hay breaches los mostramos, sino mostramos que no los hay
    if len(haveibeenpwnedBreaches) == 0:
        print("No se han encontrado leaks")
    else:
        counter = 1
        for breach in haveibeenpwnedBreaches:
            print("----- Breach " + str(counter) + " -----")
            print("Nombre: " + breach["Name"])
            print("Dominio: " + breach["Domain"])
            print("Fecha de la filtración: " + breach["BreachDate"])
            print("Cuentas filtradas: " + str(breach["PwnCount"]))
            print("Tipo de información filtrada:")
            for dataClass in breach["DataClasses"]:
                print("\t- " + dataClass)
            print("")
            counter += 1

"""
    Nombre: Get Have I Been Pwned Breaches
    Descripción: Función con la que obtenemos las filtraciones de un dominio en haveibeenpwned
    Parámetros:
        0: [STRING] Dominio del que comprobar filtraciones
    Retorno: [DICCIONARIO] JSON con la información de las diferentes filtraciones encontradas en haveibeenpwned
    Precondición: La conexión con la API debe funcionar correctamente
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def getHaveibeenpwnedBreaches(mx):
    
    return requests.get("https://haveibeenpwned.com/api/v3/breaches?domain=" + mx).json()

"""
    Nombre: Make Ping
    Descripción: Función con la que comprobamos si un dominio está vivo o no haciéndole un ping y mostrando la información
    Parámetros:
        0: [STRING] Dominio al que hacer el ping
    Retorno: [STRING] Dirección IP del dominio
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def makePing(domain):

    print("\n========== PING de" + domain + " ==========")

    # Realizamos el ping
    proc = subprocess.Popen(["/usr/bin/ping -c 1 %s" % domain, ""], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    # Si no tenemos éxito mostramos el error, sino, mostramos la información y retornamos la ip del host
    if len(out.split()) == 0:
        print("No se ha alcanzado el destino (el host no está vivo o ha ocurrido un error en la resolución del dominio)")
        return None
    else:
        out = out.decode("utf-8")
        print(out)
        return out.split()[2].replace("(", "").replace(")", "")

"""
    Nombre: Make Port Scan
    Descripción: Función con la que realizamos un NMAP al top 10 puertos TCP de una IP
    Parámetros:
        0: [STRING] IP a la que hacer el NMAP
    Retorno: Ninguno.
    Precondición: Ninguna.
    Complejidad Temporal: O(1)
    Complejidad Espacial: O(1)
"""
def makePortScan(ipAddress):

    print("\n========== NMAP de " + ipAddress + " ==========")

    # Realizamos el nmap de los top 10 puertos TCP sin resolución de dominio, mostramos solo los abiertos, ponemos un min-rate de 
    # 5K para que vaya rápido
    proc = subprocess.Popen(["sudo /usr/bin/nmap -sS -n -Pn --open --min-rate 5000 --top-ports 10 %s" % ipAddress, ""], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    # Mostramos los resultados
    out = out.decode("utf-8")
    print(out)

# ========== Ejecución del Main ==========
main()