"""
Ejercicio 2: Monitoreo de calidad de servicio (QoS) en enlaces WAN.

Lee router_metrics.csv linea por linea y genera reporte_qos.txt con, por router:
  1. Latencia promedio
  2. Porcentaje de perdida de paquetes
  3. Violaciones de SLA (latencia promedio > 150 ms o perdida > 5%)
  4. Porcentaje de tiempo con el enlace en estado DOWN

Uso:  python3 monitoreo_qos.py
"""

from datetime import date

RUTA_METRICAS = "router_metrics.csv"
RUTA_REPORTE = "reporte_qos.txt"

COLUMNAS_ESPERADAS = 7
ESTADOS_VALIDOS = ("UP", "DEGRADED", "DOWN")

# Limites del Acuerdo de Nivel de Servicio (SLA)
SLA_LATENCIA_MAXIMA_MS = 150.0
SLA_PERDIDA_MAXIMA_PORCENTAJE = 5.0


def parsear_linea(linea):
    """Convierte una linea del archivo en un diccionario con los tipos correctos.

    Devuelve None si la linea esta incompleta o tiene datos invalidos.
    """
    # El archivo puede venir separado por comas (.csv) o por espacios (.txt)
    campos = linea.replace(",", " ").split()
    if len(campos) != COLUMNAS_ESPERADAS:
        return None

    marca, id_router, ip, latencia, enviados, perdidos, estado = campos
    try:
        muestra = {
            "timestamp": marca,
            "id_router": id_router,
            "ip": ip,
            "latencia_ms": float(latencia),
            "enviados": int(enviados),
            "perdidos": int(perdidos),
            "estado": estado.upper(),
        }
    except ValueError:
        return None

    if muestra["estado"] not in ESTADOS_VALIDOS:
        return None
    if muestra["latencia_ms"] < 0 or muestra["enviados"] <= 0:
        return None
    if not 0 <= muestra["perdidos"] <= muestra["enviados"]:
        return None
    return muestra


def nuevo_acumulado(ip):
    return {
        "ip": ip,
        "muestras": 0,
        "muestras_caido": 0,
        "muestras_degradado": 0,
        "suma_latencia": 0.0,
        "enviados": 0,
        "perdidos": 0,
    }


def procesar_metricas(ruta_metricas):
    """Recorre el archivo una sola vez acumulando los totales de cada router."""
    acumulados = {}  # id_router -> totales
    total_validas = 0
    total_descartadas = 0

    # "with" cierra el archivo automaticamente; iterar sobre el archivo lee una
    # linea a la vez, sin cargar el contenido completo en memoria.
    with open(ruta_metricas, "r", encoding="utf-8", errors="replace") as archivo:
        for numero_linea, linea in enumerate(archivo, start=1):
            # La primera linea puede ser el encabezado con los nombres de columna
            if numero_linea == 1 and linea.lower().startswith("timestamp"):
                continue

            muestra = parsear_linea(linea)
            if muestra is None:
                total_descartadas += 1
                continue

            total_validas += 1
            id_router = muestra["id_router"]
            if id_router not in acumulados:
                acumulados[id_router] = nuevo_acumulado(muestra["ip"])
            totales = acumulados[id_router]

            totales["muestras"] += 1
            totales["suma_latencia"] += muestra["latencia_ms"]
            totales["enviados"] += muestra["enviados"]
            totales["perdidos"] += muestra["perdidos"]

            if muestra["estado"] == "DOWN":
                totales["muestras_caido"] += 1
            elif muestra["estado"] == "DEGRADED":
                totales["muestras_degradado"] += 1

    return acumulados, total_validas, total_descartadas


def calcular_porcentaje(parte, total):
    return parte / total * 100 if total > 0 else 0.0


def calcular_metricas(acumulados):
    """Convierte los totales acumulados en las metricas finales de cada router."""
    metricas = []
    for id_router in sorted(acumulados):
        totales = acumulados[id_router]

        # Promedio global: todas las muestras del router en el periodo evaluado
        latencia_promedio = totales["suma_latencia"] / totales["muestras"]
        perdida = calcular_porcentaje(totales["perdidos"], totales["enviados"])
        tiempo_caido = calcular_porcentaje(totales["muestras_caido"], totales["muestras"])

        motivos = []
        if latencia_promedio > SLA_LATENCIA_MAXIMA_MS:
            motivos.append(f"latencia promedio {latencia_promedio:.2f} ms > "
                           f"{SLA_LATENCIA_MAXIMA_MS:.0f} ms")
        if perdida > SLA_PERDIDA_MAXIMA_PORCENTAJE:
            motivos.append(f"perdida de paquetes {perdida:.2f}% > "
                           f"{SLA_PERDIDA_MAXIMA_PORCENTAJE:.0f}%")

        metricas.append({
            "id_router": id_router,
            "ip": totales["ip"],
            "muestras": totales["muestras"],
            "latencia_promedio": latencia_promedio,
            "enviados": totales["enviados"],
            "perdidos": totales["perdidos"],
            "perdida": perdida,
            "tiempo_caido": tiempo_caido,
            "disponibilidad": 100 - tiempo_caido,
            "motivos_sla": motivos,
        })
    return metricas


def construir_reporte(metricas, total_validas, total_descartadas):
    """Arma el texto del reporte a partir de las metricas de cada router."""
    lineas = [
        "=== REPORTE DE CALIDAD DE SERVICIO (QoS) EN ENLACES WAN ===",
        f"Fecha de procesamiento: {date.today().isoformat()}",
        f"Total de muestras procesadas: {total_validas:,}",
        f"Lineas descartadas por formato invalido: {total_descartadas:,}",
        f"Routers evaluados: {len(metricas)}",
        "",
        "--- LATENCIA PROMEDIO POR ROUTER ---",
    ]
    for router in metricas:
        lineas.append(f"- {router['id_router']:<13} ({router['ip']:<11}) | "
                      f"Latencia promedio: {router['latencia_promedio']:7.2f} ms")

    lineas.append("")
    lineas.append("--- PERDIDA DE PAQUETES POR ROUTER ---")
    for router in metricas:
        lineas.append(f"- {router['id_router']:<13} | Perdidos: {router['perdidos']:>7,} de "
                      f"{router['enviados']:>7,} | Perdida: {router['perdida']:5.2f}%")

    lineas.append("")
    lineas.append("--- ALERTAS DE VIOLACION DE SLA ---")
    lineas.append(f"Limites: latencia promedio > {SLA_LATENCIA_MAXIMA_MS:.0f} ms "
                  f"o perdida de paquetes > {SLA_PERDIDA_MAXIMA_PORCENTAJE:.0f}%")
    routers_en_falta = [router for router in metricas if router["motivos_sla"]]
    if not routers_en_falta:
        lineas.append("Ningun router viola el SLA.")
    for router in routers_en_falta:
        lineas.append(f"[ALERTA] {router['id_router']}: " + "; ".join(router["motivos_sla"]))

    lineas.append("")
    lineas.append("--- DISPONIBILIDAD DEL ENLACE (UPTIME) ---")
    for router in metricas:
        lineas.append(f"- {router['id_router']:<13} | Tiempo en DOWN: {router['tiempo_caido']:5.2f}% "
                      f"| Disponibilidad: {router['disponibilidad']:6.2f}%")

    return "\n".join(lineas) + "\n"


def guardar_reporte(texto, ruta_reporte):
    with open(ruta_reporte, "w", encoding="utf-8") as archivo:
        archivo.write(texto)


def main():
    try:
        acumulados, total_validas, total_descartadas = procesar_metricas(RUTA_METRICAS)
    except FileNotFoundError:
        print(f"No se encontro el archivo de metricas: {RUTA_METRICAS}")
        return

    metricas = calcular_metricas(acumulados)
    texto = construir_reporte(metricas, total_validas, total_descartadas)
    guardar_reporte(texto, RUTA_REPORTE)
    print(texto)
    print(f"Reporte guardado en: {RUTA_REPORTE}")


if __name__ == "__main__":
    main()
