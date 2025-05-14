Origin (easy)

1. Primeramente abrimos el archivo ftp.pcap
![image](https://github.com/user-attachments/assets/9da65aa7-6e9f-44d1-87d7-240d5f238e5f)

2. Buscamos la IP del atacante 15.206.185.207 usando el filtro de warkshark ftp, analizamos varios intentos de contraseña invalido con la Response: 331 Please specify the password

Aunque en algunos paquetes la IP 15.206.185.207 aparece como destino (cuando recibe respuestas del servidor), los comandos ofensivos como USER, PASS, RETR y STOR fueron iniciados desde esta IP, por lo que se identifica como el origen del ataque.
![image](https://github.com/user-attachments/assets/786ab687-cc74-475e-a1f3-c83a3465cc9e)

3. Analizamos la informacion del atacante, y vemos que es desde Mumbai usando una instancia EC2 de Amazon AWS
```bash

whois 15.206.185.207                                   

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2025, American Registry for Internet Numbers, Ltd.
#



# start

NetRange:       15.205.0.0 - 15.207.255.255
CIDR:           15.206.0.0/15, 15.205.0.0/16
NetName:        AT-88-Z
NetHandle:      NET-15-205-0-0-1
Parent:         NET15 (NET-15-0-0-0-0)
NetType:        Direct Allocation
OriginAS:       
Organization:   Amazon Technologies Inc. (AT-88-Z)
RegDate:        2019-03-26
Updated:        2021-02-10
Ref:            https://rdap.arin.net/registry/ip/15.205.0.0



OrgName:        Amazon Technologies Inc.
OrgId:          AT-88-Z
Address:        410 Terry Ave N.
City:           Seattle
StateProv:      WA
PostalCode:     98109
Country:        US
RegDate:        2011-12-08
Updated:        2024-01-24
Comment:        All abuse reports MUST include:
Comment:        * src IP
Comment:        * dest IP (your IP)
Comment:        * dest port
Comment:        * Accurate date/timestamp and timezone of activity
Comment:        * Intensity/frequency (short log extracts)
Comment:        * Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP address at that point in time.
Ref:            https://rdap.arin.net/registry/entity/AT-88-Z


OrgTechHandle: ANO24-ARIN
OrgTechName:   Amazon EC2 Network Operations
OrgTechPhone:  +1-206-555-0000 
OrgTechEmail:  amzn-noc-contact@amazon.com
OrgTechRef:    https://rdap.arin.net/registry/entity/ANO24-ARIN

OrgRoutingHandle: ARMP-ARIN
OrgRoutingName:   AWS RPKI Management POC
OrgRoutingPhone:  +1-206-555-0000 
OrgRoutingEmail:  aws-rpki-routing-poc@amazon.com
OrgRoutingRef:    https://rdap.arin.net/registry/entity/ARMP-ARIN

OrgNOCHandle: AANO1-ARIN
OrgNOCName:   Amazon AWS Network Operations
OrgNOCPhone:  +1-206-555-0000 
OrgNOCEmail:  amzn-noc-contact@amazon.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/AANO1-ARIN

OrgRoutingHandle: IPROU3-ARIN
OrgRoutingName:   IP Routing
OrgRoutingPhone:  +1-206-555-0000 
OrgRoutingEmail:  aws-routing-poc@amazon.com
OrgRoutingRef:    https://rdap.arin.net/registry/entity/IPROU3-ARIN

OrgAbuseHandle: AEA8-ARIN
OrgAbuseName:   Amazon EC2 Abuse
OrgAbusePhone:  +1-206-555-0000 
OrgAbuseEmail:  trustandsafety@support.aws.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/AEA8-ARIN

# end


# start

NetRange:       15.206.0.0 - 15.207.255.255
CIDR:           15.206.0.0/15
NetName:        AMAZON-BOM
NetHandle:      NET-15-206-0-0-2
Parent:         AT-88-Z (NET-15-205-0-0-1)
NetType:        Reallocated
OriginAS:       AS16509
Organization:   Amazon Data Services India (ADSI-6)
RegDate:        2019-05-08
Updated:        2021-02-10
Ref:            https://rdap.arin.net/registry/ip/15.206.0.0


OrgName:        Amazon Data Services India
OrgId:          ADSI-6
Address:        L&T Business Park, Gate No.5, Tower A
Address:        Ground Floor, Sakivihar Road, Pawai
City:           Mumbai
StateProv:      MAHARASHTRA
PostalCode:     400072
Country:        IN
RegDate:        2016-08-05
Updated:        2019-08-02
Ref:            https://rdap.arin.net/registry/entity/ADSI-6


OrgNOCHandle: AANO1-ARIN
OrgNOCName:   Amazon AWS Network Operations
OrgNOCPhone:  +1-206-555-0000 
OrgNOCEmail:  amzn-noc-contact@amazon.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/AANO1-ARIN

OrgTechHandle: ANO24-ARIN
OrgTechName:   Amazon EC2 Network Operations
OrgTechPhone:  +1-206-555-0000 
OrgTechEmail:  amzn-noc-contact@amazon.com
OrgTechRef:    https://rdap.arin.net/registry/entity/ANO24-ARIN

OrgAbuseHandle: AEA8-ARIN
OrgAbuseName:   Amazon EC2 Abuse
OrgAbusePhone:  +1-206-555-0000 
OrgAbuseEmail:  trustandsafety@support.aws.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/AEA8-ARIN

# end



#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2025, American Registry for Internet Numbers, Ltd.
#


````
4. Buscamos el software FTP que está corriendo el servidor (el backup server) que apareció en el pcap, para esto usamos el filtro ftp.response.code == 220 y vemos que el software es  vsFTPd 3.0.5
![image](https://github.com/user-attachments/assets/d8bfb5e3-bcfe-4b67-a097-4d2b1b3177ac)

```bash
ip.src == 15.206.185.207 and ftp
````
Vemos que el inicio del ataque fue a las 2024-05-03 04:12:54
![image](https://github.com/user-attachments/assets/f60cd46d-e27d-48d1-a619-005dd7efff1a)

6. Buscamos el usuario y clave que fueron usados por el atacante , vemos que fue usado:

```bash
USER:forela-ftp
PASS:ftprocks69$
````
![image](https://github.com/user-attachments/assets/6c4d525b-ca09-45d8-910f-8502aa12a7ac)

7. Vemos que el atacante ha descargado archivos mediante el codigo:

Archivos descargados:
```bash

Request: RETR Maintenance-Notice.pdf
Request: RETR s3_buckets.txt
````

![image](https://github.com/user-attachments/assets/6ae906b5-955a-4ee9-a4ab-3abc847f0e21)

8. Debemos descargar los archivos comprometidos usando Wireshark para esto debemos:
```
a) Seguir el TCP stream de las transferencias RETR.

b) Exportar los objetos FTP en Wireshark:
File → Export Objects → FTP:
````

![image](https://github.com/user-attachments/assets/0fdaa1b1-1ad0-421c-96e8-179df2b8d164)

9. Analizamos los documentos descargados por el atacante y vemos que hay contraseñas comprometidas, del archivo Maintenance-Notice.pdf
```` 
File: Maintenance-Notice.pdf
Password: **B@ckup2024!**
````

10. Analizamos el archivo s3_buckets.txt y vemos que se ha filtrado un email
```bash
File: s3_buckets.txt
archivebackups@forela.co.uk
````

11. Analizamos la URL de un S3 bucket del año 2023 que se encuentra en el archivo s3_buckets.txt
```
https://2023-coldstorage.s3.amazonaws.**com**
````

























