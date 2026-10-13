
from datetime import datetime

RUTA_LOG = "network_traffic.log"
RUTA_REPORTE = "reporte_diagnostico.txt"

COLUMNAS_ESPERADAS = 7
CANTIDAD_TOP = 5

# Cantidad de registros que se muestran en el reporte con sus 7 columnas
CANTIDAD_MUESTRA = 10
NOMBRES_PUERTOS = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS", 3389: "RDP"}

# Parametros de deteccion: mas de UMBRAL_INTENTOS registros DENY desde una misma
# IP hacia un puerto vigilado dentro de VENTANA_SEGUNDOS se considera un ataque.
PUERTOS_VIGILADOS = {22: "SSH", 3389: "RDP"}
UMBRAL_INTENTOS = 10
VENTANA_SEGUNDOS = 60

PROTOCOLOS_VALIDOS = ("TCP", "UDP", "ICMP")
ACCIONES_VALIDAS = ("ALLOW", "DENY")


def parsear_linea(linea):
    """Convierte una linea del log en un diccionario con los tipos correctos.

    Devuelve None si la linea esta incompleta o tiene datos invalidos, para que
    el programa pueda descartarla y seguir con la siguiente.
    """
    # El formato puede venir separado por espacios o por comas
    campos = linea.replace(",", " ").split()
    if len(campos) != COLUMNAS_ESPERADAS:
        return None

    marca, ip_origen, ip_destino, puerto, protocolo, accion, cantidad_bytes = campos
    try:
        registro = {
            "timestamp": datetime.fromisoformat(marca),
            "ip_origen": ip_origen,
            "ip_destino": ip_destino,
            "puerto": int(puerto),
            "protocolo": protocolo.upper(),
            "accion": accion.upper(),
            "bytes": int(cantidad_bytes),
        }
    except ValueError:
        return None

    if registro["protocolo"] not in PROTOCOLOS_VALIDOS:
        return None
    if registro["accion"] not in ACCIONES_VALIDAS:
        return None
    if registro["bytes"] < 0:
        return None
    return registro


def registrar_intento_denegado(registro, ventanas, sospechosos):
    """Actualiza la ventana deslizante de intentos denegados de una IP.

    Por cada par (IP, puerto) se guardan solo los timestamps de los ultimos
    VENTANA_SEGUNDOS, asi la memoria usada no crece con el tamano del archivo.
    """
    clave = (registro["ip_origen"], registro["puerto"])
    if clave not in ventanas:
        ventanas[clave] = []
        sospechosos[clave] = {
            "total_denegados": 0, "maximo_en_ventana": 0, "primera_alerta": None}
    ventana = ventanas[clave]
    ahora = registro["timestamp"]
    ventana.append(ahora)

    # Se descartan los intentos que ya quedaron fuera de la ventana de tiempo
    while (ahora - ventana[0]).total_seconds() > VENTANA_SEGUNDOS:
        ventana.pop(0)

    datos = sospechosos[clave]
    datos["total_denegados"] += 1
    if len(ventana) > datos["maximo_en_ventana"]:
        datos["maximo_en_ventana"] = len(ventana)
    if len(ventana) > UMBRAL_INTENTOS and datos["primera_alerta"] is None:
        datos["primera_alerta"] = ahora


def procesar_log(ruta_log):
    """Recorre el archivo una sola vez acumulando todas las metricas."""
    bytes_por_ip = {}                        # solo trafico ALLOW
    registros_por_protocolo = {}
    bytes_por_protocolo = {}
    for protocolo in PROTOCOLOS_VALIDOS:
        registros_por_protocolo[protocolo] = 0
        bytes_por_protocolo[protocolo] = 0
    ventanas = {}
    sospechosos = {}

    # Solo se guardan los primeros registros para mostrarlos en el reporte
    primeros_registros = []

    total_validos = 0
    total_descartados = 0

    # "with" cierra el archivo automaticamente; iterar sobre el archivo lee una
    # linea a la vez, sin cargar el contenido completo en memoria.
    with open(ruta_log, "r", encoding="utf-8", errors="replace") as archivo:
        for linea in archivo:
            registro = parsear_linea(linea)
            if registro is None:
                total_descartados += 1
                continue

            total_validos += 1
            if len(primeros_registros) < CANTIDAD_MUESTRA:
                primeros_registros.append(registro)
            registros_por_protocolo[registro["protocolo"]] += 1
            bytes_por_protocolo[registro["protocolo"]] += registro["bytes"]

            if registro["accion"] == "ALLOW":
                ip = registro["ip_origen"]
                bytes_por_ip[ip] = bytes_por_ip.get(ip, 0) + registro["bytes"]
            elif registro["puerto"] in PUERTOS_VIGILADOS:
                registrar_intento_denegado(registro, ventanas, sospechosos)

    return {
        "total_validos": total_validos,
        "total_descartados": total_descartados,
        "primeros_registros": primeros_registros,
        "bytes_por_ip": bytes_por_ip,
        "registros_por_protocolo": registros_por_protocolo,
        "bytes_por_protocolo": bytes_por_protocolo,
        "sospechosos": sospechosos,
    }


def obtener_top_ips(bytes_por_ip, cantidad):
    """Devuelve las IP con mas bytes, ordenadas de mayor a menor."""
    ordenadas = sorted(bytes_por_ip.items(), key=lambda par: par[1], reverse=True)
    return ordenadas[:cantidad]


def obtener_alertas(sospechosos):
    """Filtra los pares (IP, puerto) que superaron el umbral dentro de la ventana."""
    alertas = []
    for (ip, puerto), datos in sospechosos.items():
        if datos["primera_alerta"] is not None:
            alertas.append({
                "ip": ip,
                "puerto": puerto,
                "servicio": PUERTOS_VIGILADOS[puerto],
                "total_denegados": datos["total_denegados"],
                "maximo_en_ventana": datos["maximo_en_ventana"],
                "primera_alerta": datos["primera_alerta"],
            })
    alertas.sort(key=lambda alerta: alerta["total_denegados"], reverse=True)
    return alertas


def calcular_porcentaje(parte, total):
    return parte / total * 100 if total > 0 else 0.0


def formatear_bytes(cantidad):
    """Expresa una cantidad de bytes en la unidad mas legible (B, KB, MB, GB, TB)."""
    valor = float(cantidad)
    for unidad in ("B", "KB", "MB", "GB"):
        if valor < 1024:
            return f"{valor:.2f} {unidad}"
        valor /= 1024
    return f"{valor:.2f} TB"


def describir_puerto(puerto):
    """Agrega el nombre del servicio a los puertos conocidos, por ejemplo 22 (SSH)."""
    if puerto in NOMBRES_PUERTOS:
        return f"{puerto} ({NOMBRES_PUERTOS[puerto]})"
    return str(puerto)


def construir_tabla_registros(registros):
    """Arma una tabla con las 7 columnas del log para los registros recibidos."""
    formato = "{:<19}  {:<15}  {:<10}  {:<14}  {:<9}  {:<6}  {:>18}"
    lineas = [formato.format("Timestamp", "IP_Origen", "IP_Destino", "Puerto_Destino",
                             "Protocolo", "Accion", "Bytes_Transferidos")]
    for registro in registros:
        lineas.append(formato.format(
            registro["timestamp"].isoformat(), registro["ip_origen"], registro["ip_destino"],
            describir_puerto(registro["puerto"]), registro["protocolo"], registro["accion"],
            f"{registro['bytes']:,}"))
    return lineas


def construir_reporte(resultados):
    """Arma el texto del reporte a partir de las metricas calculadas."""
    top_ips = obtener_top_ips(resultados["bytes_por_ip"], CANTIDAD_TOP)
    alertas = obtener_alertas(resultados["sospechosos"])
    total_registros = resultados["total_validos"]
    total_bytes = sum(resultados["bytes_por_protocolo"].values())

    lineas = [
        "=== REPORTE DE DIAGNOSTICO DE RED ===",
        f"Fecha de procesamiento: {datetime.now().date().isoformat()}",
        f"Total de registros procesados: {total_registros:,}",
        f"Lineas descartadas por formato invalido: {resultados['total_descartados']:,}",
        "",
        f"--- ESTRUCTURA DE LOS DATOS (PRIMEROS {len(resultados['primeros_registros'])} REGISTROS) ---",
    ]
    lineas.extend(construir_tabla_registros(resultados["primeros_registros"]))

    lineas.append("")
    lineas.append(f"--- TOP {CANTIDAD_TOP} IP ORIGEN POR VOLUMEN DE DATOS (ALLOW) ---")
    for posicion, (ip, cantidad_bytes) in enumerate(top_ips, start=1):
        lineas.append(f"{posicion}. IP: {ip:<15} | Trafico: {formatear_bytes(cantidad_bytes)}")

    lineas.append("")
    lineas.append("--- ALERTAS DE SEGURIDAD DETECTADAS ---")
    lineas.append(f"Criterio: mas de {UMBRAL_INTENTOS} registros DENY hacia el puerto 22 o 3389 "
                  f"en {VENTANA_SEGUNDOS} segundos")
    if not alertas:
        lineas.append("No se detectaron ataques.")
    for alerta in alertas:
        lineas.append(
            f"[ALERTA] Posible ataque {alerta['servicio']} por fuerza bruta desde la IP: "
            f"{alerta['ip']} ({alerta['total_denegados']:,} intentos denegados al puerto "
            f"{alerta['puerto']}, maximo {alerta['maximo_en_ventana']} en {VENTANA_SEGUNDOS} s, "
            f"primera alerta: {alerta['primera_alerta'].isoformat()})")

    lineas.append("")
    lineas.append("--- RESUMEN POR PROTOCOLO ---")
    lineas.append(f"Trafico total: {formatear_bytes(total_bytes)}")
    for protocolo in PROTOCOLOS_VALIDOS:
        registros = resultados["registros_por_protocolo"][protocolo]
        cantidad_bytes = resultados["bytes_por_protocolo"][protocolo]
        lineas.append(
            f"- {protocolo + ':':<5} {calcular_porcentaje(registros, total_registros):6.2f}% "
            f"de los registros ({registros:,}) | "
            f"{calcular_porcentaje(cantidad_bytes, total_bytes):6.2f}% de los bytes "
            f"({formatear_bytes(cantidad_bytes)})")

    return "\n".join(lineas) + "\n"


def guardar_reporte(texto, ruta_reporte):
    with open(ruta_reporte, "w", encoding="utf-8") as archivo:
        archivo.write(texto)


def main():
    try:
        resultados = procesar_log(RUTA_LOG)
    except FileNotFoundError:
        print(f"No se encontro el archivo de log: {RUTA_LOG}")
        return

    texto = construir_reporte(resultados)
    guardar_reporte(texto, RUTA_REPORTE)
    print(texto)
    print(f"Reporte guardado en: {RUTA_REPORTE}")


if __name__ == "__main__":
    main()
