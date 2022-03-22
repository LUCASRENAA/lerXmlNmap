import xml.etree.ElementTree as ET
tree = ET.parse("teste2.xml")
root = tree.getroot()


ips = []

class CVE_IPS_2:
    def __init__(self, ip, cve,descricao):
        self.ip = ip
        self.cve = cve
        self.descricao = descricao

class Porta_representar:
    def __init__(self, porta, servico, produto, versao):
        self.porta = porta
        self.servico = servico
        self.produto = produto
        self.versao = versao

class IP_representar:
    def __init__(self, ip, portas):
        self.ip = ip
        self.portas = portas

cve_ips_vetor = []
for child in root.findall("host"):
        for title in child.findall("address"):
            if title.attrib['addrtype'] == 'ipv4':
                ip = title.attrib['addr']
        for port in child.findall("ports"):
            portas = []
            for ports in port.findall("port"):
                porta = ports.attrib['portid']
                for serviços in ports.findall("service"):
                    servico = serviços.attrib['name']
                    try:
                        produto = serviços.attrib['product']
                    except:
                        produto = "Não existe"
                    try:
                        versao = serviços.attrib['version']
                    except:
                        versao = 0
                for teste in ports.findall("script"):
                    for osss in teste.findall("table"):
                        validar = 0
                        try:

                            if str(osss.attrib['key'])[:3] == "CVE":
                                cve_texto = str(title.attrib['addr'])
                                descricao = ""
                                validar = 1

                            for element in osss:

                                if element.attrib['key'] == 'description':
                                    print(element.attrib['key'])

                                    for alou in element.findall("elem"):
                                        print(alou.text)
                                        descricao = alou.text
                            if validar == 1:
                                cve_ips_vetor.append(CVE_IPS_2(cve_texto, osss.attrib['key'],descricao))

                        except:
                            print("não é vulneravel")

                porta_objeto = Porta_representar(porta, servico, produto, versao)
                portas.append(porta_objeto)
            ips.append(IP_representar(ip, portas))

        for os in child.findall("os"):
            contador = 0
            for oss in os.findall("osmatch"):
                contador = contador + 1
                sistema_operacional = str(oss.attrib['name'])

                if contador == 1:
                    print(str(title.attrib['addr']))
                    sistema_operacional_principal = str(oss.attrib['name'])
                    sistema_operacional_principal_probabilidade = str(oss.attrib['accuracy'])

                    print(sistema_operacional_principal)
                    print(sistema_operacional_principal_probabilidade)

        """
        for os in child.findall("hostscript"):
            for oss in os.findall("script"):
                    print("id script")
                    print(oss.attrib['id'])
                    print('\n')
                    for osss in oss.findall("table"):
                        print(str(title.attrib['addr']))
                        print(porta)

                        print(osss.attrib['key'])
                        print("\n\n")
                        for elemm in osss.findall("elem"):
                            print("orx")
                            print(elemm.attrib['key'])
                            print(elemm.text)
                            print("\n\n")
        """
print("Leitor de xml de um arquivo do nmap")
print("---------ips---------")


for ip in ips:
        print("ip: "+ str(ip.ip))
    
        for porta in ip.portas:
            print("porta: " + str(porta.porta))

           

print("---------------------")
print("CVES")
for cve in cve_ips_vetor:
        print(cve.cve)
        print(cve.ip)
        