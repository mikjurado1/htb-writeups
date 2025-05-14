#### 🕵️‍♂️ Objetivo

> Determinar el **último tiempo de arranque (boot time)** del dispositivo Android en formato UTC.

#### 🧰 Herramientas utilizadas

- `mount` (para montar la imagen `.dd`)
    
- `find`, `ls`, `date`, `grep`
    
- Permisos de root: `sudo` / `sudo su`
    
- Análisis de nombres de archivo (`epoch`)

#### 📂 Pasos realizados

1. **Montar la imagen .dd**
```bash
sudo mkdir -p /mnt/droidphish
sudo mount -o ro,noload,loop -t ext4 DroidPhish.dd /mnt/droidphish

````
2. Buscar posibles archivos relacionados con boot:
```bash
find /mnt/droidphish -iname "*boot*" -o -iname "*restart*"
````

3. Identificar archivo sospechoso:
```bash
/data/data/com.google.android.gms/files/safeboot_restarts/1732449939860-244433016
````
4. Extraer timestamp del nombre del archivo:
```bash
1732449939860 → en segundos: 1732449939
````

5. Convertir a fecha legible en UTC:
```bash
date -u -d @1732449939
# Resultado: 2024-11-24 07:05:39 UTC
````
6. **Ajustar zona horaria (EST → UTC+5):**
```bash
2024-11-24 07:05:39 + 5h = 2024-11-24 12:05:39
````
### 🧩 Pregunta > _The user was exposed to a phishing attack. Provide the name of the email app used as the attack vector._

### ✅ Resumen de investigación

1. Busqué apps de correo en `/data/data/`:
```bash
ls /mnt/droidphish/android-9.0-r2/data/data/ | grep -Ei 'mail|email|gm'
````
a. Resultado:  
    `ch.protonmail.android`, `com.google.android.gm`, ...
    
b. Inspeccioné `ch.protonmail.android`:
    
    - Contenía la base de datos `db-mail`
        
    - Directorios activos como `files/`, `shared_prefs/`, etc.
        
    - Evidencia de uso reciente
        
c. Deducción:
    
    - ProtonMail fue usada como app de correo en el dispositivo
        
    - Vector de ataque de phishing

🟩 Respuesta final
```bash
Protonmail
````
📧 Email Phishing – Subject

### 🧩 Pregunta > : Provide the title of the phishing email.
```
Ruta analizada:
/data/data/ch.protonmail.android/databases/db-mail
````
### ✅ Resumen de investigación: 

Explorar el contenido de la base de datos SQLite:

```bash
sqlite3 /mnt/droidphish/android-9.0-2/data/data/ch.protonmail.android/databases/db-mail

````
Consulta en SQLite:
````bash
SELECT subject FROM MessageEntity WHERE subject IS NOT NULL;
````

Resultado Encontrado:
```bash
Celebrating 3 Years of Success – Thank You!
````

Obtuve su timestamp:
```bash
SELECT subject, time FROM MessageEntity WHERE subject LIKE '%Success%';
-- Resultado: 1732467882
````

Convertí el timestamp a UTC:
```bash
date -u -d @1732467882
# Resultado: 2024-11-24 17:04:42 UTC
````

🕵️ Análisis forense: URL de descarga maliciosa.

Objetivo: Encontrar la URL desde la cual se descargó la aplicación maliciosa (Booking.apk).

Metodología: Exploración manual del sistema Android montado.

a. Navegué por el sistema de archivos montado (/mnt/droidphish/...) usando la terminal en Kali Linux.

b. Permisos necesarios: Algunas carpetas requerían privilegios de superusuario, así que ejecuté sudo su para tener acceso completo.

c. Ruta relevante identificada Ubicación del historial de descargas de Chrome:
```bash
/data/data/com.android.chrome/app_chrome/Default/History
````
Análisis con DB Browser for SQLite

Abrí el archivo History con DB Browser y exploré la tabla downloads_url_chains.

Resultado

Encontré la siguiente URL maliciosa:
```bash
https://provincial-consecutive-lbs-boots.trycloudflare.com/Booking.apk
````

![image](https://github.com/user-attachments/assets/8eb1ad85-85cd-4eb7-a4e5-6f779b5cb55d)

Encontrar el sha256 hash
```
sha256sum /mnt/droidphish/android-9.0-r2/data/media/0/Download/Booking.apk            
Respuesta:
af081cd26474a6071cde7c6d5bd971e61302fb495abcf317b4a7016bdb98eae2  /mnt/droidphis
````

🐾 Análisis del APK – Nombre del Paquete

Para extraer el nombre del paquete de la aplicación maliciosa (Booking.apk), utilicé la herramienta aapt:
```
aapt dump badging /mnt/droidphish/android-9.0-r2/data/media/0/Download/Booking.apk | grep package

````
Resultado:
```
package: name='com.hostel.mount' versionCode='3573638' versionName='35.73.6.38' platformBuildVersionName='6.0-2438415' platformBuildVersionCode='23' compileSdkVersion='23' compileSdkVersionCodename='6.0-2438415'

Resultado: com.hostel.mount
````

🔐 Análisis de permisos – APK malicioso (Booking.apk)
🧩 Pregunta

¿Cuántos permisos de ejecución (runtime permissions) fueron concedidos a la aplicación maliciosa?
🔍 Procedimiento

1. Descompilé el APK malicioso con apktool para acceder al archivo AndroidManifest.xml:
```bash
apktool d /mnt/droidphish/android-9.0-r2/data/media/0/Download/Booking.apk -o ~/booking_apk
````

2. Busqué todos los permisos definidos en el manifiesto:
```bash
grep 'uses-permission' ~/booking_apk/AndroidManifest.xml
````
3. Identifiqué los permisos que corresponden a la categoría runtime permissions, según la documentación oficial de Android (nivel de protección "dangerous").

4. Conté los siguientes 13 permisos como runtime:
a. SEND_SMS
b. READ_SMS
c. READ_CALL_LOG
d. READ_CONTACTS
e. GET_ACCOUNTS
f. CAMERA
g. RECORD_AUDIO
h. ACCESS_COARSE_LOCATION
i. ACCESS_FINE_LOCATION
j. CALL_PHONE
k. READ_EXTERNAL_STORAGE
l. WRITE_EXTERNAL_STORAGE
m. READ_PHONE_STATE
✅ Respuesta final: 13 permisos de ejecución

🧠 DroidPhish – Identificación del Servidor C2 (Comando y Control)
🧩 Pregunta

Identify the C2 IP address and port that the malicious application was programmed to connect to.
🔍 Análisis

Dado que no logré localizar de forma confiable la dirección IP y puerto dentro del código APK o en el sistema de archivos, recurrí a un método alternativo y muy utilizado en análisis de malware: VirusTotal.

a. Subí el hash256 a VirusTotal.
b. Me dirigí a la pestaña "Behavior".
c. En la sección Network Communication, se muestran todas las conexiones salientes realizadas durante el análisis dinámico.

✅ Respuesta encontrada

La siguiente entrada destaca como C2 por usar un puerto no estándar (10824):
```
3.121.139.82:10824
````
