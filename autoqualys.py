#!/usr/bin/env python
# ------------------------------------------------------------------------------
import linecache

version = '1.0'

import os
import shutil
import subprocess
import zipfile
import time
import optparse
import socket
import sys
import datetime
import urllib3
from lxml import objectify
import qualysapi
import pandas

import utileria as tool

#logger = logging.getLogger('error.log')
# Configure logger to write to a file...

#def my_handler(type, value, tb):
#    logger.exception("Uncaught exception: {0}".format(str(value)))

## Install exception handler
#sys.excepthook = my_handler

global_scanner = 1
work_dir = "./"
Out_Sumario = "sumario.html"
Out_Estadistica = "estadisticas.csv"
cliente = 'C.G.S.I., C.A.'
dB_CGSI = {}
scansINT = []
scansEXT = []
was_list = []
maps = []
riesgoso = []


struct_db = ['IP', 'NAME', 'OS', 'vulBaj', 'vulBajMed', 'vulMed', 'vulMedAlt', 'vulAlt', 'vulConf', 'vulPot',
             'vulInf','RiesgoPromedio','RUTA', 'AvgCvssTemp', 'Riesgo']
struct_db_maps = ['NAME', 'Dominio', 'CantEquipos', 'RUTA']
struct_db_was = ['NAME', 'RUTA']
struct_stadistic = ['IP', 'NAME', 'OS',  'vulBaj', 'vulBajMed', 'vulMed', 'vulMedAlt', 'vulAlt', 'vulConf', 'vulPot',
             'vulInf','RiesgoPromedio', 'AvgCvssTemp', 'Riesgo']
os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(os.path.dirname(__file__), 'cacert.pem')
db_scanners = {1: {"NAME": "VSCAN_CGSI", "REPORT_TEMPLATE": "1795353"},
               2: {"NAME": "VSCAN_CGSI_2", "REPORT_TEMPLATE": "1810372"},
               3: {"NAME": "CGSI-VSCANNER2", "REPORT_TEMPLATE": "1810425"}}
db_profiles = {1: {"NAME": "FULL SCAN PROFILE","ABREVIADO":"FULL"},
               2: {"NAME": "FULL SCAN PROFILE / Firewall", "ABREVIADO":"CUSTOM"},
               3: {"NAME": "Reporte por Vulnerabilidad", "ABREVIADO":"CUSTOM"},
               4: {"NAME": "OTRO","ABREVIADO":"CUSTOM"}}
qgc = None
scan_refIDs = []
scan_refIDs_fail = []
dB_SCAN = {}  # Key is ref_id
struct_db_SCAN = ["Scan_refID", "Scan_Name", "Type", "Date", "State", "IP"]
reports_ID = []
dB_Reports = {}  # Key is Report_ID
# struct_db_Reports = ["Scan_refID","Report_ID", "Date", "Status",]
struct_db_Reports = ["Report_ID", "Nombre", "Tipo", "Usuario", "Fecha", "Formato", "Tamano", "Estado"]
lista_de_ips = './direcciones_ip.txt'
db_targets = {}  # key is IP
struct_db_targets = ["IP", "Scan_Name", "Tipo", "Appliance", ]
# Dic of Dic que contiene todos los Scans que se han lanzado
db_state = {}  # Key es la IP
struct_db_state = ["ID", "IP", "SCAN_NAME", "SCAN_REF", "TRY"]
db_configs = {}  # key son los mismos de la estructura
os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(os.path.dirname(__file__), 'cacert.pem')
struct_db_configs = ["CLIENTE",
                     "CONSULTOR",
                     "SCANNER",
                     "EXT-INT",
                     "PROFILE",
                     "DELAY",
                     "TARGET_FILE",
                     "SIMULTANEO",
                     "HoraPermitida_LV-start",
                     "HoraPermitida_LV-end",
                     "HoraPermitida_SD-start",
                     "HoraPermitida_SD-end"]


def clean_local_db():
    global dB_SCAN
    global scan_refIDs
    dB_SCAN = {}
    scan_refIDs = []


def get_duplicados(seq):
    seen = set()
    seen_add = seen.add
    # adds all elements it doesn't know yet to seen and all other to seen_twice
    seen_twice = set(x for x in seq if x in seen or seen_add(x))
    #  turn the set into a list (as requested)
    return list(seen_twice)


def get_duplicated_ips():
    global dB_SCAN
    list_duplicados = []
    ip_list = []
    for key in dB_SCAN.keys():
        ip_list.append(dB_SCAN[key]["IP"])
    ips_duplicadas = get_duplicados(ip_list)
    for key in dB_SCAN.keys():
        if dB_SCAN[key]["IP"] in ips_duplicadas:
            list_duplicados.append(key)
    return list_duplicados


def get_abreviado(profile):
    global db_profiles
    for key in sorted(db_profiles.keys()):
        if db_profiles[key]["NAME"] == profile:
            return db_profiles[key]["ABREVIADO"]
    return "CUSTOM"


def print_scan_list():
    global dB_SCAN
    global scan_refIDs
    global scan_refIDs_fail
    if dB_SCAN.keys() > 0:
        exitosos = len(scan_refIDs)
        fallidos = len(scan_refIDs_fail)
        if len(scan_refIDs) > 0:
            print ('[+] Lista de Scans:')
            tool.print_dict(dB_SCAN, sort='Date', headers=struct_db_SCAN)
            print ('[+] Existen un total de ' + str(exitosos) + ' Scans')
        #else:
            #print "[-] No existen Scans"
        if len(scan_refIDs_fail) > 0:
            print ('[-] Existen ' + str(fallidos) + ' Scans Fallidos')
        duplicados = get_duplicated_ips()
        if len(duplicados) > 0:
            print ("[-] Existen " + str(len(duplicados)) + " Scans Duplicados")
            tool.print_dict(dB_SCAN, keys=duplicados, sort='IP', headers=struct_db_SCAN)
    else:
        print ("[-] No existen Scans")


def get_dns(ip):
    global qcc
    call = '/api/2.0/fo/asset/host/'
    parameters = {'action': 'list', 'ips': ip}
    xml_output = qcc.request(call, parameters)
    root = objectify.fromstring(xml_output)
    for host in root.RESPONSE.HOST_LIST.HOST:
        print (host.IP.text, host.DNS.text)


def get_time_from_qualys(String):
    global year
    global month
    my_list = String.split('T')[0].split('-')
    my_list.extend((String.split('T')[1].strip('Z')).split(':'))
    my_list = map(int, my_list)
    year = my_list[0]
    month = my_list[1]
    day = my_list[2]
    hour = my_list[3]
    min = my_list[4]
    seg = my_list[5]
    return datetime.datetime(year, month, day, hour, min, seg)


def download_scan_list(days_ago=30,delay=1):
    global qgc
    global dB_SCAN
    global scan_refIDs
    global scan_refIDs_fail
    after_date = tool.get_date_ago(days_ago)
    scan_refIDs = []
    scan_refIDs_fail = []
    call = '/api/2.0/fo/scan/'
    parameters = dict(action='list',
                      show_ags='1',
                      show_op='1',
                      show_status='1',
                      echo_request='0',
                      launched_after_datetime=after_date)
    try:
        xml_output = qgc.request(call, parameters)
        #print xml_output
        root = objectify.fromstring(xml_output)
        for scan in root.RESPONSE.SCAN_LIST.SCAN:
            try:
                ref_ID = scan.REF.text
                Scan_Name = scan.TITLE.text
                Scan_Name = Scan_Name.encode('ascii', 'ignore')
                Tipo = scan.TYPE.text
                Qualys_Tiempo = scan.LAUNCH_DATETIME.text
                Fecha = get_time_from_qualys(Qualys_Tiempo).strftime("%Y-%m-%d %H:%M")
                Estado = scan.STATUS.STATE.text
                if '-' in Scan_Name:
                    IP = Scan_Name.split("-")[6]
                else:
                    print "No se ha podido descargar el scan "+Scan_Name

                dB_SCAN[ref_ID] = dict(Scan_refID=ref_ID,
                                       Scan_Name=Scan_Name,
                                       Type=Tipo,
                                       Date=Fecha,
                                       State=Estado,
                                       IP=IP)
                if Estado == "Finished":
                    scan_refIDs.append(ref_ID)
                elif Estado == 'Canceled':
                    print "Hay un reporte cancelado"
                else:
                    scan_refIDs_fail.append(ref_ID)
            except ValueError as e:
                print '\nSe genero un Error al procesar ' + scan
                print e
    except AttributeError:
        print "[-] No existen scans en la base de datos de Qualys"
    time.sleep(delay)


def generaReporte_HTML(scan_ref, delay=10):
    global qgc
    global dB_SCAN
    global struct_db_SCAN
    global dB_Reports
    global struct_db_Reports
    call = '/api/2.0/fo/report/'
    parameters = dict(action='launch',
                      template_id=db_scanners[global_scanner]["REPORT_TEMPLATE"],
                      report_title=dB_SCAN[scan_ref]["Scan_Name"],
                      ip_restriction=dB_SCAN[scan_ref]["IP"],
                      report_type='Scan',
                      echo_request='0',
                      output_format='html',
                      report_refs=scan_ref)
    try:
        xml_output = qgc.request(call, parameters)
        #print xml_output
        root = objectify.fromstring(xml_output)
        report_id = root.RESPONSE.ITEM_LIST.ITEM.VALUE.text
        qualys_tiempo = root.RESPONSE.DATETIME.text
        fecha = get_time_from_qualys(qualys_tiempo).strftime("%Y-%m-%d %H:%M")
        name = dB_SCAN[scan_ref]["Scan_Name"]
        dB_Reports[report_id] = dict(Report_ID=report_id,
                                     Nombre=name,
                                     Tipo="Scan",
                                     Usuario="API",
                                     Fecha=fecha,
                                     Formato="html",
                                     Tamano="0",
                                     Estado="Launched")
        print ("[+] Generando reporte " + report_id + " para scan " + name)
    except ValueError as e:
        print ('[-]Se genero un Error al procesar ')
        print (e)
        return False
    except AttributeError as e:
        print ('[-]Se genero un Error al procesar ')
        print ("[-]", e, scan_ref)
        return False
        #tool.progress_delay(delay)
        return True


def download_report_list():
    global qgc
    global dB_Reports
    call = '/api/2.0/fo/report/'
    parameters = dict(action='list',
                      echo_request='0')
    count = 0
    try:
        xml_output = qgc.request(call, parameters)
        #print xml_output
        root = objectify.fromstring(xml_output)
        for report in root.RESPONSE.REPORT_LIST.REPORT:
            report_id = report.ID.text
            nombre = report.TITLE.text
            tipo = report.TYPE.text
            usuario = report.USER_LOGIN.text
            qualys_tiempo = report.LAUNCH_DATETIME.text
            fecha = get_time_from_qualys(qualys_tiempo).strftime("%Y-%m-%d %H:%M")
            formato = report.OUTPUT_FORMAT.text
            size = report.SIZE.text
            estado = report.STATUS.STATE.text
            dB_Reports[report_id] = dict(Report_ID=report_id,
                                         Nombre=nombre,
                                         Tipo=tipo,
                                         Usuario=usuario,
                                         Fecha=fecha,
                                         Formato=formato,
                                         Tamano=size,
                                         Estado=estado)
            count += 1

    except ValueError as e:
        print ('[-] Se genero un Error al procesar ')
        print (e)
    except AttributeError:
        print ('[-] No existen reportes creados en la base de datos de Qualys')
        #print e
    except Exception as e:
        print ("[-] Qualys Api Limit Reached..")
        print (e)
        sys.exit(0)
        #tool.progress_delay(300)
    if len(dB_Reports.keys()) > 0:
        print ("[+] Existen " + str(count) + " reportes en Qualys")
    #print_report_list()
    time.sleep(1)


def print_report_list():
    global dB_Reports
    global struct_db_Reports
    if len(dB_Reports.keys()) > 0:
        print ("[+] Imprimiendo lista de Reportes en Base de Datos Local")
        tool.print_dict(dB_Reports, headers=struct_db_Reports, sort='Report_ID', align=["Nombre"])


def download_report(report_id,delay=10):
    global qgc
    global dB_Reports
    folder = work_dir + "SCANS/"
    name = dB_Reports[report_id]["Nombre"]
    out_file = folder + name + ".zip"
    call = '/api/2.0/fo/report/'
    parameters = dict(action='fetch',
                      echo_request='0',
                      id=report_id)
    try:
        if not os.path.exists(folder):
            os.makedirs(folder)
        if not os.path.exists(folder + name) and 'SQ-' in name and 'FULL' in name and 'I' in name or 'E':
            response = qgc.request(call, parameters)
            with open(out_file, "wb") as report:
                report.write(response)
            with zipfile.ZipFile(out_file, "r") as zip:
                zip.extractall(folder + name)
            new_folder = folder + name + "/"
            old_folder = new_folder + os.listdir(new_folder)[0] + "/"
            command = "move " + old_folder + "* " + new_folder
            command = command.replace('/', '\\')
            with open(os.devnull, "w") as f:
                subprocess.call(command, shell=True, stdout=f)
            #print ("[+] Reporte guardado en: " + out_file.strip(".zip"))
            os.remove(out_file)
            shutil.rmtree(old_folder)
        else:
            print ("[-] Ya el scan " + name + " esta descargado o el nombre del archivo es incorrecto")
            return False
    except ValueError as e:
        print ("[-] Hubo un error al guardar el archivo " + out_file)
        print (e)
    except WindowsError as e:
        print ("[-] Hubo un error al borrar un archivo")
        print (e)
    except zipfile.BadZipfile as e:
        print ("[-] Hubo un error al descomprimir el archivo" + out_file)
        print (e)
    #tool.progress_delay(delay)
    return True




def genera_reportes():
    global dB_Reports
    global struct_db_Reports
    global dB_SCAN
    reportes_generados = []
    download_report_list()
    if len(dB_SCAN.keys()) < 1:
        print "[+] La base de datos local de Scans esta vacia"
        print "[+] Se va a descargar la lista de Scans desde Qualys"
        try:
            days_ago = int(raw_input("Indique de hace cuantos dias desea los scans [30] > "))
        except ValueError as e:
            days_ago = 30
            pass
        download_scan_list(days_ago)
    total_scans = len(dB_SCAN.keys())
    generados = 0
    no_generados = 0
    errores = 0
    if total_scans > 0:
        #print_scan_list()
        print "[+] Existen " + str(total_scans) + " scans en la DB Local"
        print "[+] Generando Reportes"
        for report_id in sorted(dB_Reports.keys()):
            reportes_generados.append(dB_Reports[report_id]["Nombre"])
        for ref_id in sorted(dB_SCAN.keys()):
            name = dB_SCAN[ref_id]["Scan_Name"]
            if name not in reportes_generados:
                if generaReporte_HTML(ref_id) is True:
                    generados += 1
                else:
                    errores += 1
            else:
                print "[-] Reporte ya generado para " + name
                no_generados += 1
            print "[+] Se han generado " + str(generados) + " y faltan " + str(
                total_scans - generados - no_generados - errores)
        print "[+] Lista de Reportes Generados:"
        tool.print_dict(dB_Reports, headers=struct_db_Reports)
        print "[+] Se generaron un total de " + str(generados) + " reportes y ya estaban generados " + str(no_generados)
        if errores > 0:
            print "[-] " + str(errores) + " reportes dieron error"
    else:
        print "[-] No existen Scans para generar Reportes"


def download_reports():
    global dB_Reports
    global cant_total_reportes
    carpetaScans = 'SCANS'
    print "[+] Descargando Lista de Reportes"
    download_report_list()
    if os.path.exists(work_dir+carpetaScans):
       shutil.rmtree(work_dir+carpetaScans)
       os.mkdir(work_dir+carpetaScans)

    cant_total_reportes = len(dB_Reports.keys())
    if cant_total_reportes > 0:
        print "[+] Descargando reportes..."
        descargados = 0
        no_descargado = 0
        for report_id in sorted(dB_Reports.keys()):
            if download_report(report_id) is True:
                descargados += 1
                print "[+] Reporte "+str(descargados) +" de " + str(cant_total_reportes)
            else:
                no_descargado += 1
        print '[+] Se descargaron en total ' + str(descargados) + ' reportes y ya estaban descargados ' + str(
            no_descargado)
    else:
        print "[-] No existen reportes para descargar"


def preguntar_datos(tmp_file=".autoqualys_state.tmp"):
    global db_configs
    global db_scanners
    global global_scanner
    global struct_db_configs
    global db_profiles
    lv_start = "0"
    lv_end = "0"
    sd_end = "0"
    sd_start = "0"
    delay = 20
    targets = "targets.txt"
    simultaneo = 1
    ext_int = "I"
    profile = "FULL SCAN PROFILE"
    print '+-----------------------------------------------------------------------------+'
    id_consultor = raw_input("Indique el Nombre del Consultor > ")
    id_cliente = raw_input("Indique el Nombre del Cliente > ")
    #    while True:
    #        for key in sorted(db_scanners.keys()):
    #            print str(key) + ".- " + db_scanners[key]["NAME"]
    #        tmp_scanner = raw_input("Seleccione el Scanner a utilizar > ")
    #        if not tool.is_number(tmp_scanner):
    #            print "[-] Debe ingresar un numero valido"
    #        elif int(tmp_scanner) <= 0 or int(tmp_scanner) > len(db_scanners.keys()):
    #            print "[-] El numero seleccionado es incorrecto"
    #        else:
    #            scanner = db_scanners[int(tmp_scanner)]["NAME"]
    #            print "[+] Scanner Seleccionado: " + scanner
    #            inicia_qualys(qgc, scanner)
    #            break
    scanner = db_scanners[global_scanner]["NAME"]
    while True:
        targets_file = raw_input("Indique el Nombre del archivo con lista de direcciones IP [targets.txt] > ")
        if targets_file is "":
            print "[+] No se indico ningun archivo, se intentara utilizar el archivo " + targets
            if not os.path.exists(targets):
                print "[-] El archivo " + targets + " no existe"
            else:
                break
        else:
            if os.path.exists(targets_file):
                targets = targets_file
                break
            else:
                print "[-] El archivo indicado, no existe.. vuelva a indicar un archivo"
    while True:
        tmp_ext_int = raw_input("Indique si los scans seran (E)xternos o (I)nternos [I] > ")
        if tmp_ext_int is "":
            print ("[+] No se indico tipo de scan, se utilizara el valor por defecto Interno")
            break
        else:
            if tmp_ext_int.upper() == "I" or tmp_ext_int == "E":
                ext_int = tmp_ext_int
                break
            else:
                print ("[-] Debe seleccionar una opcion valida, E para Externo o I para Interno")
    while True:
        for key in sorted(db_profiles.keys()):
            print (str(key) + ".- " + db_profiles[key]["NAME"])
        tmp_profile = raw_input("Seleccione el profile a utilizar > ")
        if not tool.is_number(tmp_profile) or (int(tmp_profile) <= 0 or int(tmp_profile) > len(db_profiles.keys())):
            print ("[-] Debe ingresar un numero valido")
        else:
            profile = db_profiles[int(tmp_profile)]["NAME"]
            if profile == "OTRO":
                profile = raw_input("Coloque el nombre del profile exactamente igual al nombre del profile en Qualys: ")
                print ("ALERTA: Si el nombre colocado no existe dentro de Qualys, se generara un error al ejecutarse")
                time.sleep(5)
            break
    while True:
        tmp_delay = raw_input("Indique intervalos entre Scans, en minutos [20] > ")
        if tmp_delay is "":
            print ("[+] No indico ningun numero, el valor por defecto es " + str(delay) + " minutos")
            break
        elif not tool.is_number(tmp_delay):
            print ("Debe ingresar un numero valido")
        elif int(tmp_delay) <= 0 or int(tmp_delay) > 86400:
            print ("El numero ingresado esta fuera de rango, debe ingresar un numero entre 1-86400 seg")
        else:
            delay = int(tmp_delay)
            break
    while True:
        tmp_simultaneo = raw_input("Indique cuantos Scans Simultaneos desea lanzar  > ")
        if tmp_simultaneo is "":
            print ("[+] No indico ningun numero, el valor por defecto es " + str(simultaneo))
            break
        elif not tool.is_number(tmp_simultaneo):
            print ("Debe ingresar un numero valido")
        elif int(tmp_simultaneo) <= 0 or int(tmp_simultaneo) > 8:
            print ("El numero ingresado esta fuera de rango, debe ingresar un numero entre 1 y 8")
        else:
            simultaneo  = int(tmp_simultaneo)
            break
    print ("Configuracion de Rango de Horarios Permitidos:")
    while True:
        tmp_lv_start = raw_input("Indique la hora inicial, de lunes a viernes. Utilizar formato 24horas [0] > ")
        if tmp_lv_start is "":
            print ("[+] No indico ningun numero, el valor por defecto es " + lv_start)
            break
        elif not tool.is_number(tmp_lv_start):
            print ("Debe ingresar un numero valido")
        elif int(tmp_lv_start) < 0 or int(tmp_lv_start) >= 24:
            print ("El numero ingresado esta fuera de rango, debe ingresar un numero entre 0 y 23")
        else:
            lv_start = int(tmp_lv_start)
            break
    while True:
        tmp_lv_end = raw_input("Indique la hora final, de lunes a viernes. Utilizar formato 24horas [0] > ")
        if tmp_lv_end is "":
            print ("[+] No indico ningun numero, el valor por defecto es " + lv_end)
            break
        elif not tool.is_number(tmp_lv_end):
            print ("Debe ingresar un numero valido")
        elif int(tmp_lv_end) < 0 or int(tmp_lv_end) >= 24:
            print ("El numero ingresado esta fuera de rango, debe ingresar un numero entre 0 y 23")
        else:
            lv_end = int(tmp_lv_end)
            break
    while True:
        tmp_sd_start = raw_input("Indique la hora inicial, de sabado a domingo. Utilizar formato 24horas [0] > ")
        if tmp_sd_start is "":
            print ("[+] No indico ningun numero, el valor por defecto es " + sd_start)
            break
        elif not tool.is_number(tmp_sd_start):
            print ("Debe ingresar un numero valido")
        elif int(tmp_sd_start) < 0 or int(tmp_sd_start) >= 24:
            print ("El numero ingresado esta fuera de rango, debe ingresar un numero entre 0 y 23")
        else:
            sd_start = int(tmp_sd_start)
            break
    while True:
        tmp_sd_end = raw_input("Indique la hora final, de sabado a domingo. Utilizar formato 24horas [0] > ")
        if tmp_sd_end is "":
            print ("[+] No indico ningun numero, el valor por defecto es " + sd_end)
            break
        elif not tool.is_number(tmp_sd_end):
            print ("Debe ingresar un numero valido")
        elif int(tmp_sd_end) < 0 or int(tmp_sd_end) >= 24:
            print ("El numero ingresado esta fuera de rango, debe ingresar un numero entre 0 y 23")
        else:
            sd_end = int(tmp_sd_end)
            break
    print ('+-----------------------------------------------------------------------------+')
    if id_consultor is "":
        id_consultor = "Auto Qualys"
    if id_cliente is "":
        id_cliente = None
    db_configs["CONSULTOR"] = id_consultor
    db_configs["CLIENTE"] = id_cliente.upper()
    db_configs["SCANNER"] = scanner
    db_configs["DELAY"] = delay
    db_configs["PROFILE"] = profile
    db_configs["EXT-INT"] = ext_int
    db_configs["TARGET_FILE"] = targets
    db_configs["SIMULTANEO"] = simultaneo
    db_configs["HoraPermitida_LV-start"] = lv_start
    db_configs["HoraPermitida_LV-end"] = lv_end
    db_configs["HoraPermitida_SD-start"] = sd_start
    db_configs["HoraPermitida_SD-end"] = sd_end
    for item in struct_db_configs:
        print ("[+] "+item+" = "+str(db_configs[item]))
    if config_is_ok() is False:
        print ("[-] No se indico suficiente informacion para continuar...")
        sys.exit(0)
    salvar_configs()

def menu():
    global lista_de_ips
    global db_targets
    global work_dir
    global version
    global qgc
    global cliente
    global cant_total_reportes

    s_menu = {#1: "Verificar lista de Objetivos",
              #2: "Agregar Assets",
              3: "Lanzar Scans.",
              4: "Procesar y descargar scans.",
              5: "Listar Scans existentes en Qualys.",
              6: "Listar Reportes creados en Qualys.",
              7: "Cambiar nombre de Cliente.",
              8: "Formatear Reportes",
              9: " Proceso manual - Generar reportes" ,
              10: "Proceso manual - Descargar reportes" ,
              11: "Proceso manual - Renombrar directorios de reportes" ,
              12: "Proceso manual - Generar sumario y estadisticas" ,
              13: "Cambiar template de scan" ,
              99: "Salir."}
    while True:

        print ('+-----------------------------------------------------------------------------+')
        print ('  Qualys Automation Script')
        print ('  Ver. ' + version)
        print ('+-----------------------------------------------------------------------------+')
        print ('[+] Usando Nombre de cliente: ' + cliente)
        options = sorted(s_menu.keys())
        for entry in options:
            print ('[' + str(entry) + '] ' + s_menu[entry])
        print ('+-----------------------------------------------------------------------------+')
        selection = raw_input("Indique una opcion > ")
        if selection == '3':
            lanzar_scans(qgc = qgc)

        elif selection == '4': #Procesar y descargar  Scans
            genera_reportes()
            download_reports()
            rename_qualys_dirs(work_dir)
            if obtener_datos() is True:
                generaSumario()
                generaEstadisticas()
        elif selection == '5':
            print ("[+] Descargando lista de Scans de Qualys")
            download_scan_list()
            print_scan_list()
        elif selection == '6':
            print ("[+] Descargando lista de reportes de Qualys")
            download_report_list()
            print_report_list()
        elif selection == '7':
            cliente = raw_input("Introduzca el nombre del cliente: ")
        elif selection == '8':
            print ("Formateando reportes...")
            FormateoAEspanol(file)
        elif selection == '9':
            genera_reportes()
        elif selection == '10':
            download_reports()
        elif selection == '11':
            rename_qualys_dirs(work_dir)
        elif selection == '12':
            if obtener_datos() is True:
                generaSumario()
                generaEstadisticas()
        elif selection == '13':
            if num12 == 1:
                print "Templates para el scanner 1 -->"
                print "[1] Si desea usar el template comparativo ID  1898429"
                print "[2] Si desea usar el id Scan Results ID 1795353"
                seltemplate =int (input ("Indique el id del template, si no se indica un id valido el programa dara error.[Scan Results[1795353]]: "))
                if seltemplate == 1:
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1898429"
                    print 'Se usara el template "Corporativo [1898429]" '
                elif selection == 2:
                    print 'Se usara el template "Scan Results [1795353]" '
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1795353"
                else:
                    print "Usted indico una opcion no valida. Se usara el template por defecto."
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1795353"
                print "El template que se usara es: "  + db_scanners[global_scanner]["REPORT_TEMPLATE"]
            elif num12 == 2:
                print "Templates para el scanner 2 -->"
                print "[1] Si desea usar el template comparativo ID  1981626"
                print "[2] Si desea usar el id Scan Results ID 1810372"
                seltemplate =int (input ("Indique el id del template, si no se indica un id valido el programa dara error.[Scan Results[1810372]]: "))
                if seltemplate == 1:
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1981626"
                    print 'Se usara el template "Corporativo [1981626]" '
                elif selection == 2:
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1810372"
                    print 'Se usara el template "Scan Results [1810372]" '
                else:
                    print "Usted indico una opcion no valida. Se usara el template por defecto."
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1810372"
            elif num12 == 3:
                print "Templates para el scanner 3 -->"
                print "[1] Si desea usar el template comparativo ID  2026435"
                print "[2] Si desea usar el id Scan Results ID 1810425 "
                seltemplate =int (input ("Indique el id del template, si no se indica un id valido el programa dara error.[Scan Results[1810425]]: "))
                if seltemplate == 1:
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "2026435"
                    print 'Se usara el template "Corporativo [2026435]" '
                elif selection == 2:
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1810425"
                    print 'Se usara el template "Scan Results [1810425]" '
                else:
                    print "Usted indico una opcion no valida. Se usara el template por defecto."
                    db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1810425"
                print "El template que se usara es: "  + db_scanners[global_scanner]["REPORT_TEMPLATE"]
        elif selection == '99':
            print ("Hasta luego...")
            break
        else:
            print ("Opcion Incorrecta!")
        #raw_input("Presione Enter para continuar...")


# # Out Name Example  SQ-JP-BODCORP-I-FULL-20141014-10.6.112.33-001
def genera_nombre (ip, id_consultor, id_cliente, profile_in, try_num):
    global db_configs
    if len(id_cliente) > 5:
        # print "[-] El ID de Cliente no debe superar los 6 caracteres"
        id_cliente = id_cliente[:6]
    profile = get_abreviado(profile_in)
    var_ie = db_configs["EXT-INT"]
    #if tool.is_private(ip):
    #    var_ie = "I"
    #else:
    #    var_ie = "E"
    try_number = str(try_num).zfill(3)
    right_now = datetime.datetime.now()
    date = right_now.strftime("%Y%m%d")
    output = "SQ-" + tool.get_iniciales(
        id_consultor) + "-" + id_cliente.upper() + "-" + var_ie + "-" + profile + "-" + date + "-" + ip + "-" + try_number
    return output


def verifica_scan(nombre):
    # descarga la lista de Scans actuales, de los ultimos 30 dias.
    # carga los scans actuales en la base de datos local
    #compara la lista de targets actuales con la lista de scans ya existentes.
    '''
    :param nombre:
    :return: Verifica si en Qualys existe un scan con un nombre Xs y si el mismo ya fue positivo
    '''


def lanza_scan(qgc, dir_ip, scanner, scan_name, profile, cuando=None):
    '''
    :param
    :return: Ejecuta un Scan contra Qualys, arroja 1 si el escan fue positivo. Si hubo algun error retorna 0.
    '''
    xml_output = ""
    option_title = profile
    if cuando is not None:
        print ("[+] Esperando un momento para lanzar Scan")
        #tool.progress_delay(cuando)
    print ('+-----------------------------------------------------------------------------+')
    print "[+] Lanzando Scan para la direccion IP=" + str(dir_ip) + " usando nombre " + str(scan_name)
    try:
        call = '/api/2.0/fo/scan/'
        if db_configs["EXT-INT"] == "I":
            parameters = dict(action='launch',
                              echo_request='0',
                              scan_title=scan_name,
                              target_from="assets",
                              iscanner_name=scanner,
                              option_title=option_title,
                              ip=dir_ip, )
        elif db_configs["EXT-INT"] == "E":
            if tool.is_private(dir_ip):
                print ("[-] No se puede ejecutar un Scan Externo sobre una direccion IP interna")
                print ("    Vuelva a configurar AutoQualys correctamente")
                sys.exit(0)
            parameters = dict(action='launch',
                              echo_request='0',
                              scan_title=scan_name,
                              target_from="assets",
                              option_title=option_title,
                              ip=dir_ip, )
        else:
            print ("[-] Error al lanzar el Scan, No se pudo determinar si era Externo o Interno")
            sys.exit(0)
        xml_output = qgc.request(call, parameters)
        #print xml_output
        xml_dict = {}
        root = objectify.fromstring(xml_output)
        for ITEM in root.RESPONSE.ITEM_LIST.ITEM:
            try:
                xml_dict[ITEM.KEY.text] = ITEM.VALUE.text
            except ValueError as e:
                print ('\nSe genero un Error al procesar ' + ITEM)
                print (e)
        scan_id = xml_dict["REFERENCE"]
        print ("[+] Scan Lanzado exitosamente | Scan_id = " + scan_id + " | Time = " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        time.sleep(0.5)
        return scan_id
    except AttributeError as E:
        print ("[-] Se ha generado un error al lanzar el Scan")
        print (E)
        print (xml_output)
        time.sleep(3)
        scan_id = None
        return None
    except ValueError as E:
        print ("[-] Se ha generado un error al lanzar el Scan")
        print (E)
        print (xml_output)
        time.sleep(3)
        scan_id = None
        return None
    except:
        print ("[-] Se ha generado un error inesperado al lanzar el Scan")
        print (xml_output)
        time.sleep(3)
        scan_id = None
        return None

def salvar_configs(tmp_file=".autoqualys_state.tmp"):
    '''
    Esta funcion permite salvar la configuracion actual, borrando cualquier archivo anterior
    '''
    global db_configs
    global struct_db_configs
    try:
        with open(tmp_file, "w") as state:
            for key in struct_db_configs:
                state.write("#" + key + "=" + str(db_configs[key]) + "\n")
    except ValueError as e:
        print ("[-] Hubo un error al procesar el archivo " + tmp_file)
        print (e)
        sys.exit(0)


def config_is_ok():
    global db_configs
    if db_configs["CLIENTE"] is None or db_configs["CONSULTOR"] is None or db_configs["SCANNER"] is None:
        return False
    else:
        return True


def lanzar_scans(qgc, id_consultor=None, id_cliente=None, scanner=None, delay=10, simultaneo=1, input_file="targets.txt",
                 tmp_file=".autoqualys_state.tmp"):
    global db_state
    global db_configs
    target_list = []
    invalid_ip = []
    old_target_list = []
    failure = []
    success = []
    db_configs["CLIENTE"] = id_cliente
    db_configs["CONSULTOR"] = id_consultor
    db_configs["SCANNER"] = scanner
    db_configs["DELAY"] = delay
    db_configs["TARGET_FILE"] = input_file
    db_configs["SIMULTANEO"] = simultaneo
    if config_is_ok() is False:
        if recuperar_estado() is True:
            for ip in sorted(db_state.keys()):  # Carga todas las IP ya escaneadas en la lista old_target_list
                old_target_list.append(ip)
            success.extend(old_target_list)
        else:
            preguntar_datos()
    else:
        salvar_configs()
    try:
        with open(input_file, "r") as targets:
            for line in targets:
                line = line.strip("\n")
                line = line.strip("\r")
                if tool.is_ip(line):
                    if line not in old_target_list:
                        target_list.append(line)
                        # print "[+] Extraida direccion IP " + line
                        # else:
                        # #print "[-] La direccion IP " + line + " ya fue escaneada"
                else:
                    print ("[-] " + line + " no es una direccion IP valida")
                    invalid_ip.append(line)
            print ("[+] Se lograron extraer un total de " + str(
                len(target_list)) + " direcciones IP nuevas del archivo " + input_file)
            if len(old_target_list) > 0:
                print ("[+] Ya fueron escaneadas "+str(len(old_target_list))+" direcciones IP")
            if len(invalid_ip) > 0:
                print ("[-] Se encontraron " + str(len(invalid_ip)) + " direcciones IP invalidas")
        print ('+-----------------------------------------------------------------------------+')
        print ("[+] Lanzando Scans..")
        print ("[+] Puede presionar [Ctrl + C] para detener la aplicacion..")
        print ("[+] Se lanzaran un total de " + str(len(target_list)) + " Scans")
        #print "[+] Fecha estimada de finalizacion " + calc_tiempo_de_finalizacion(db_configs["DELAY"],
        #                                                                          db_configs["SIMULTANEO"],
        #                                                                         str(len(target_list)))
        activa_delay = 0
        simultaneo = int(db_configs["SIMULTANEO"])
        delay = int(db_configs["DELAY"])*60
        try_num = 1
        profile = db_configs["PROFILE"]
        for dir_ip in target_list:
            tool.check_time_loop(db_configs["HoraPermitida_LV-start"],
                                 db_configs["HoraPermitida_LV-end"],
                                 db_configs["HoraPermitida_SD-start"],
                                 db_configs["HoraPermitida_SD-end"])
            status = None
            counter = 0
            while status is None and counter < 3:
                status = None
                # print "[+] Lanzando scan hacia IP " + dir_ip
                scan_name = genera_nombre(dir_ip, db_configs["CONSULTOR"], db_configs["CLIENTE"], profile, try_num)
                status = lanza_scan(qgc, dir_ip, db_configs["SCANNER"], scan_name, profile)
                if status is None:
                    print ("[+] Reintentando lanzar Scan a IP: " + dir_ip)
                    failure.append(dir_ip)
                    counter += 1
                    time.sleep(3)
                else:
                    success.append(dir_ip)
                    tmp_list = [str(len(success)), dir_ip, scan_name, status, str(try_num)]
                    #struct_db_state = ["ID", "IP", "SCAN_NAME", "SCAN_REF", "TRY"]
                    try:
                        with open(tmp_file, "a+") as state_file:
                            csv_tmp = ",".join(str(tmp_list))
                            state_file.write(csv_tmp + "\n")
                    except ValueError as E:
                        print ("[-] Error al agregar un scan exitoso al archivo " + tmp_file)
                        print (E)
            activa_delay += 1
            if activa_delay >= simultaneo:
                #tool.progress_delay(delay)
                activa_delay = 0
        print ("[+] Se terminaron de lanzar los Scans")
    # except IOError:
    # print "[-] No existe el archivo " + input_file
    except ValueError as E:
        print ("[-] Se produjo un error durante la ejecucion")
        print (E)
    except KeyboardInterrupt:
        print ("[-] Programa detenido, por el usuario")
    if len(success) > 0:
        print ("[+] Scans Exitosos = " + str(len(success)))
    if len(failure) > 0:
        print ("[+] Scans Fallidos = " + str(len(failure)))


def recuperar_estado(tmp_file=".autoqualys_state.tmp"):
    global db_state
    global db_configs
    global struct_db_configs
    global global_scanner
    tmp_db_configs = {}
    for key in struct_db_configs:
        tmp_db_configs[key] = None
    if not os.path.exists(tmp_file):
        print ("[-] No existe archivo de estado anterior")
        return False
    else:
        ask = raw_input("Existe un archivo de estado anterior, desea recuperarlo? (y/n): ")
        if "Y" in ask.upper():
            print ("[+] Cargando archivo de estado anterior")
            match1 = False
            try:
                with open(tmp_file, "r") as temp:
                    for line in temp:
                        for key in struct_db_configs:
                            if line.startswith("#"+key):
                                tmp_db_configs[key] = line.split("=")[1].strip("\n")
                                match1 = True
                        if match1 is True:
                            match1 = False
                            continue
                        elif line.startswith(' ') or line is '' or line is "\n" or line is "\r":
                            continue
                        else:
                            try:
                                data = line.split(',')
                                db_state[data[1]] = {'ID': int(data[0]),
                                                     'IP': data[1],
                                                     'SCAN_NAME': data[2],
                                                     'SCAN_REF': data[3],
                                                     'TRY': data[4]}
                            except ValueError as E:
                                print ("[-] Linea no procesada " + line.strip('\n'))
                if tmp_db_configs["CLIENTE"] is None or tmp_db_configs["CONSULTOR"] is None or tmp_db_configs[
                    "SCANNER"] is None:
                    # Si no se logra obtener ninguna informacion del archivo de estado puede que el mismo este corrupto
                    print ("[-] El archivo de estado esta corrupto..")
                    tool.elimina_archivo(tmp_file)
                    return False
                else:
                    # Copia los valores temporales en los valores globales
                    for key in struct_db_configs:
                        db_configs[key] = tmp_db_configs[key]
                # ["CLIENTE", "CONSULTOR", "SCANNER", "DELAY", "TARGET_FILE", "SIMULTANEO"]
                print ("[+] Se cargo el ultimo estado satisfactoriamente")
                if len(db_state.keys()) > 0:
                    tool.print_dict(db_state, struct_db_state, align='IP', sort='ID')
                else:
                    print ("[-] No existen Scans ejecutados en el archivo de estado guardado..")
                for item in struct_db_configs:
                    print ("[+] "+item+" = "+str(db_configs[item]))
                if db_configs["SCANNER"] != db_scanners[global_scanner]["NAME"]:
                    print ("[-] Este Archivo de Estado pertenece al Scanner "+db_configs["SCANNER"])
                    print ("    y usted esta utilizando el Scanner "+db_scanners[global_scanner]["NAME"])
                    sys.exit(0)
                print ('+-----------------------------------------------------------------------------+')
                return True
            except ValueError as E:
                print ("[-] Hubo un error al procesar el archivo " + tmp_file)
                print (E)
                return False
        else:
            respuesta = raw_input("Desea eliminar el archivo de estado anterior? (y/n): ")
            if respuesta.upper() == "Y":
                tool.elimina_archivo(tmp_file)
                print ("[+] Archivo de estado anterior ignorado y eliminado")
            else:
                print ("[-] Respalde el estado anterior en otro directorio")
                sys.exit(0)



def inicia_qualys(qgc, tmp_scanner=None):
    print ("[+] Configurando Qualys")
    for attempt in range(3):
        try:
            if tmp_scanner == "VSCAN_CGSI":
                scanner = 1
            elif tmp_scanner == "VSCAN_CGSI_2":
                scanner = 2
            elif tmp_scanner == "CGSI-VSCANNER2":
                scanner = 3
            elif tmp_scanner == None:
                scanner = int(raw_input("Introduzca el Escanner a Utilizar:"))
            else:
                scanner = int(tmp_scanner)
            if scanner == 1:
                with open(".config.txt", "w") as configuration_file:
                    configuration_file.write("""
[info]
hostname = xxxx
username = xxxx
password = xxxx
max_retries = 10
""")
            elif scanner == 2:
                with open(".config.txt", "w") as configuration_file:
                        configuration_file.write("""
[info]
hostname = xxxx
username = xxxx
password = xxxx
max_retries = 10
""")
            elif scanner == 3:
                with open(".config.txt", "w") as configuration_file:
                        configuration_file.write("""
[info]
hostname = xxxx
username = xxxx
password = xxxx
max_retries = 10
""")
            else:
                print ("[-] Seleccionado un numero Invalido")
                sys.exit(0)
            banner(scanner)
            qgc = qualysapi.connect('.config.txt')
            tool.elimina_archivo(".config.txt")
            return qgc
        except ValueError as E:
            print ("[-] Hubo un error configurando Qualys, reintentando..")
            print (E)
        except WindowsError as E:
            time.sleep(2)
            print ("[-] Hubo un error al tratar de iniciar la conexion con Qualys, reintentando..")
        else:
            break


def banner(num):
    global num12
    num12 = num
    if num == 3:
        print ("""
 .d8888b.   .d8888b.        d8888 888b    888 8888888888 8888888b.        .d8888b.
d88P  Y88b d88P  Y88b      d88888 8888b   888 888        888   Y88b      d88P  Y88b
Y88b.      888    888     d88P888 88888b  888 888        888    888           .d88P
 "Y888b.   888           d88P 888 888Y88b 888 8888888    888   d88P          8888"
    "Y88b. 888          d88P  888 888 Y88b888 888        8888888P"            "Y8b.
      "888 888    888  d88P   888 888  Y88888 888        888 T88b        888    888
Y88b  d88P Y88b  d88P d8888888888 888   Y8888 888        888  T88b       Y88b  d88P
 "Y8888P"   "Y8888P" d88P     888 888    Y888 8888888888 888   T88b       "Y8888P"
""")
        db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1810425"
        print "Se esta usando el template " + db_scanners[global_scanner]["REPORT_TEMPLATE"]


    elif num == 2:
        print ("""
 .d8888b.   .d8888b.        d8888 888b    888 8888888888 8888888b.        .d8888b.
d88P  Y88b d88P  Y88b      d88888 8888b   888 888        888   Y88b      d88P  Y88b
Y88b.      888    888     d88P888 88888b  888 888        888    888             888
 "Y888b.   888           d88P 888 888Y88b 888 8888888    888   d88P           .d88P
    "Y88b. 888          d88P  888 888 Y88b888 888        8888888P"        .od888P"
      "888 888    888  d88P   888 888  Y88888 888        888 T88b        d88P"
Y88b  d88P Y88b  d88P d8888888888 888   Y8888 888        888  T88b       888"
 "Y8888P"   "Y8888P" d88P     888 888    Y888 8888888888 888   T88b      888888888
""")
        db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1810372"
        print "Se esta usando el template " + db_scanners[global_scanner]["REPORT_TEMPLATE"]
    elif num == 1:
        print ("""
 .d8888b.   .d8888b.        d8888 888b    888 8888888888 8888888b.        d888
d88P  Y88b d88P  Y88b      d88888 8888b   888 888        888   Y88b      d8888
Y88b.      888    888     d88P888 88888b  888 888        888    888        888
 "Y888b.   888           d88P 888 888Y88b 888 8888888    888   d88P        888
    "Y88b. 888          d88P  888 888 Y88b888 888        8888888P"         888
      "888 888    888  d88P   888 888  Y88888 888        888 T88b          888
Y88b  d88P Y88b  d88P d8888888888 888   Y8888 888        888  T88b         888
 "Y8888P"   "Y8888P" d88P     888 888    Y888 8888888888 888   T88b      8888888
""")
        db_scanners[global_scanner]["REPORT_TEMPLATE"] = "1795353"
        print "Se esta usando el template " + db_scanners[global_scanner]["REPORT_TEMPLATE"]
    else:
        print ("[-] Bad Options por Banner")


def calc_tiempo_de_finalizacion(delay, simultaneo, total):
    now = datetime.datetime.now()
    multiplier = int(total) / int(simultaneo)
    total_time = datetime.timedelta(seconds=multiplier * int(delay))
    end_date = now + total_time
    return end_date.strftime("%Y-%m-%d %H:%M")



# generar el sumario de los informes CGSI de forma automatizada                         #

def rename_qualys_dirs(root_dir='./'):
    print '[+] Renombrando directorios de Qualys'
    for root, dirs, files in os.walk(root_dir+'SCANS'):
        for directory in dirs:
            if "Q-" in directory :
                full_dir = os.path.join(root, directory)
                new_dir = full_dir.replace('Q-', 'C-')
                os.rename(full_dir, new_dir)

def limpia_cabecera(file):
    print ('[+] Limpiando Cabecera de Archivo '+file)
    if "MAP" in file:
        tool.erase_line_with('<div id="creat_sum">', file, 6)
    elif "SCAN" in file:
        tool.erase_line_with('<div id="creat_sum">', file, 8)
        tool.erase_line_with('<b>References:</b>', file, 11)
        tool.erase_line_with('Hosts were scanned but no open port was found', file)
    else:
        print ("[-] Archivo no reconocido")
        return False
    tool.erase_line_with('<div id="report_date">', file)
    tool.erase_line_with('<div id="user_sum">', file)
    tool.erase_line_with('<div id="addr_sum">', file)

def buscar_index():
    try:
        output = tool.pyfind('index.html')
        output.extend(tool.pyfind('report.html'))
        return output
    except ValueError as e:
        print ("[-] Ha ocurrido un error al intentar buscar los Index")



def procesaINDEX_HTML(file): #busca5
    # print '[+] procesando archivo '+file
    # #       FILE =  IP    NAME   OS   RISK   vulBaj   vulMed  vulMedAlt  vulMed/Alt  vulAlt vulConf  vulPot vulInf RUTA
    #prueba74378
    global scansINT
    global scansEXT
    global maps
    global was_list
    global hola

    if '\\' in file:
        key = file.replace('\\', '/').split('/')[-2]
    else:
        key = file.split('/')[-2]

    RUTA = file
    ## Para un SCAN
    if 'SC-' in key: #Comprueba que ya se haya cambiado de nombre los scans
        if '-I-' in key or '-E-' in key:
            raiz = tool.busca_linea(file, '<tr class="total">') #Busca esta parte en el archivo index
            try:
                vulConf = tool.get_linea(file, raiz + 5).split('<')[1].split('>')[1]
                vulConf = tool.set_default(vulConf, '0')
            except:
                vulConf = '0'
            try:
                vulPot = tool.get_linea(file, raiz + 8).split('<')[1].split('>')[1]
                vulPot = tool.set_default(vulPot, '0')
                int (vulPot)
            except:
                vulPot = '0'
            try:
                vulInf = tool.get_linea(file, raiz + 11).split('<')[1].split('>')[1]
                vulInf = tool.set_default(vulInf, '0')
            except:
                vulInf = '0'
            raiz = tool.busca_linea(file, '<td colspan="2" headers="th')
            try:
                vulAlt = tool.get_linea(file, raiz + 10).strip('\n')
                vulAlt = tool.set_default(vulAlt, '0')
            except:
                vulAlt = '0'
            try:
                vulMedAlt = tool.get_linea(file, raiz + 26).strip('\n')
                vulMedAlt = tool.set_default(vulMedAlt, '0')
            except:
                vulMedAlt = '0'
            try:
                vulMed = tool.get_linea(file, raiz + 42).strip('\n')
                vulMed = tool.set_default(vulMed, '0')
            except:
                vulMed = '0'
            try:
                vulBajMed = tool.get_linea(file, raiz + 58).strip('\n')
                vulBajMed = tool.set_default(vulBajMed, '0')
            except:
                vulBajMed = '0'
            try:
                vulBaj = tool.get_linea(file, raiz + 74).strip('\n')
                vulBaj = tool.set_default(vulBaj, '0')
            except:
                vulBaj = '0'

            n1 = int (vulPot) + int (vulConf)
            n2 = 0
            ValorReferenciaConstant = 'Temporal:</dt><dd>'
            avgCvssTemp = 0 #Acumulador que ayudar a realizar el calculo
            try: #Funcion para agregar el AvgCvssTemp

                while n2 < n1:

                    AvgCvssTemp = tool.get_linea(file, raiz)
                    raiz += 1
                    if ValorReferenciaConstant in AvgCvssTemp:
                        ValidarExsTemp= AvgCvssTemp.find (ValorReferenciaConstant)
                        TamanioValidarExsTemp = len(ValorReferenciaConstant)
                        ValidarExsTemp += TamanioValidarExsTemp
                        ValidarExsPosFin = AvgCvssTemp.find ('</dd></dl><dl class="vulnDetails">')
                        ValorCvssTemp = AvgCvssTemp[ValidarExsTemp:ValidarExsPosFin]
                        FloatValorCvssTemp = float (ValorCvssTemp) #Convierte el valor String en float
                        avgCvssTemp += FloatValorCvssTemp #Realiza calculo del avg cuando
                        n2 += 1
                avgCvssTemp = avgCvssTemp / n1 #Pasar cuando termine el ciclo
                RedondeaAvgCvssTemp = round(avgCvssTemp,2)
                AvgCvssTemp = tool.set_default( str(RedondeaAvgCvssTemp), '0') #Convierte z1 (float) a string y lo plasma en el csv

            except:
                AvgCvssTemp = '0'
            try: #Escribe en el archivo el riesgo promedio
                raiz = tool.busca_linea(file, ' scope="row">&nbsp;&nbsp;&nbsp;&nbsp;5</th>')
                BuscarVulProm = tool.get_linea(file, raiz + 2).strip('\n')
                BuscaVul5 = tool.get_linea(file, raiz + 2)
                BuscaVul51 = tool.get_linea(file, raiz + 5)
                BuscaVul4 = tool.get_linea(file, raiz + 18)
                BuscaVul41 = tool.get_linea(file, raiz + 21)
                BuscaVul3 = tool.get_linea(file, raiz + 34)
                BuscaVul31 = tool.get_linea(file, raiz + 37)
                BuscaVul2 = tool.get_linea(file, raiz + 50)
                BuscaVul21 = tool.get_linea(file, raiz + 53)
                BuscaVul1 = tool.get_linea(file, raiz + 66)
                BuscaVul11 = tool.get_linea(file, raiz + 69)
                Suma =( 5*(float (BuscaVul5) +float (BuscaVul51)) + 4*(float (BuscaVul4) + float (BuscaVul41)) +3*( float (BuscaVul3) + float (BuscaVul31)) + 2*(float (BuscaVul2)+ float (BuscaVul21)) + (float(BuscaVul1) + float (BuscaVul11)) )/ n1
                SumaDecimales = round(Suma,2) #Redondea a 2 decimales
                RiesgoPromedio = tool.set_default(str(SumaDecimales), '0')

            except:

                RiesgoPromedio = '0'

            try: #Calculo de riesgo
                if Suma > 0 and Suma <= 0.54:
                    Suma = 1
                elif Suma >= 0.55 and Suma <= 1.30:
                    Suma = 2
                elif Suma >= 1.31 and Suma <= 1.60:
                    Suma = 3
                elif Suma >= 1.61 and Suma <= 2.30:
                    Suma = 4
                elif Suma >= 2.31 and Suma <= 2.60:
                    Suma = 5
                elif Suma >= 2.61 and Suma <= 3.30:
                    Suma = 6
                elif Suma >= 3.31 and Suma <= 3.6:
                    Suma = 7
                elif Suma >= 3.61 and Suma <= 4.30:
                    Suma = 8
                elif Suma >= 4.31 and Suma <= 4.60:
                    Suma = 9
                elif Suma >= 4.61 and Suma <= 5:
                    Suma = 10

                Riesgo = (Suma + avgCvssTemp ) / 2
                RiesgoRedon = round (Riesgo,2)

                Riesgo = tool.set_default(str(RiesgoRedon), '0')

                riesgoso.append(RiesgoRedon)

            except:
                Riesgo = '0'


            IP = key.split('-')[-2]
            temp = tool.get_linea_texto(file, '<span class=\"host_id\">').replace('>', ',').replace('<', ',').replace('(', ',')
            try:
                NAME = temp.split(',')[3]
                if NAME == '' :
                    NAME = '-'
            except:
                NAME = '-'
            try:
                OS = temp.split(',')[10]
                if OS == '':
                    OS = '-'
            except:
                OS = '-'

            dB_CGSI[key] = {'IP': IP, 'NAME': NAME, 'OS': OS,  'vulBaj': vulBaj, 'vulBajMed': vulBajMed,
                            'vulMed': vulMed, 'vulMedAlt': vulMedAlt, 'vulAlt': vulAlt, 'vulConf': vulConf,
                            'vulPot': vulPot, 'vulInf': vulInf,'RiesgoPromedio':RiesgoPromedio,'RUTA': RUTA,'AvgCvssTemp': AvgCvssTemp, 'Riesgo':Riesgo}
            if '-I-' in key:
                scansINT.append(key)
            else:
                scansEXT.append(key)
                ## Para un WAS
        elif '-W-' in key:
            try:
                NAME = key.split('-')[6]
                if NAME == '':
                    NAME = 'WAS'
            except:
                NAME = 'WAS'
            dB_CGSI[key] = {'NAME': NAME, 'RUTA': RUTA}
            print ("[-] Se detecto un WAS: " + key)
            was_list.append(key)
    ## Para un MAP
    elif 'MC-' in key:
        if '-E-' in key:
            NAME = 'Map Externo'
        else:
            NAME = 'Map Interno'
        raiz = tool.busca_linea(file, 'Hosts Encontrados:')
        try:
            CantEquipos = tool.get_linea(file, raiz + 1).split('<')[1].split('>')[1]
        except:
            CantEquipos = '-'
        raiz = tool.busca_linea(file, 'Dominio:')
        try:
            Dominio = tool.get_linea(file, raiz + 1).split('<')[1].split('>')[1]
        except:
            Dominio = '-'
        dB_CGSI[key] = {'NAME': NAME, 'Dominio': Dominio, 'CantEquipos': CantEquipos, 'RUTA': RUTA}
        maps.append(key)
    else:
        print ("[-] Se detecto un Archivo que no fue procesado: " + key)


def FormateoAEspanol(file): #busca4
    ruta = os.getcwd()
    prueba = os.listdir(".\\SCANS")
    x = len (prueba)
    origen = ".\\CGSI.jpg"
    destino = ".\\SCANS\\CGSI.jpg"
    if os.path.exists(origen):
        with open(origen, 'rb') as forigen:
            with open(destino, 'wb') as fdestino:
                shutil.copyfileobj(forigen, fdestino)

    os.system(".\\formateo.bat")

def generaCuerpo(ID, RUTA, IP, NAME, OS):
    global Out_Sumario
    global work_dir

    buscar = "\i"
    reemplazar_por = "/i"
    RUTA = RUTA.replace(buscar, reemplazar_por)
    buscar2 = "\S"
    reemplazar_por2 = "/S"
    RUTA = RUTA.replace(buscar2, reemplazar_por2)

#prueba7439

    try:

        with open(work_dir + Out_Sumario, 'a') as cfgFile:

            nivel = riesgoso[positivo]
            nivel1 = str(nivel)
            nivel2 = nivel1.split(".")
            nivel3 = nivel2[0]

            cfgFile.write(('\n'
                           '<tr>\n'
                           '<td>{ID}</td>\n'
                           '<td><a href="{RUTA}" target="_blank">{IP}</a></td>\n'
                           '<td wrap>{NAME}</td>\n'
                           '<td width = 1 align "justify">{OS} </td>\n'
                           '<td><img src="./Resources/images/vuln_{RISK}.gif"/ >  {RISK}.0</td>\n'
                           '</tr>\n'
                           '\n'
                           ).format(ID=ID, IP=IP, RUTA=RUTA, NAME=NAME,  OS=OS, RISK=nivel3))


    except ValueError as e:
        print ('[-] Hubo un error al intentar abrir el Archivo ' + work_dir + Out_Sumario)
        print (e)
        sys.exit(0)


def generaCuerpoMaps(ID, NAME, Dominio, CantEquipos, RUTA):
    global Out_Sumario
    global work_dir
    try:
        with open(work_dir + Out_Sumario, 'a') as cfgFile:
            cfgFile.write(('\n'
                           '<tr>\n'
                           '<td>{ID}</td>\n'
                           '<td><a href="{RUTA}" target="_blank">{NAME}</a></td>\n'
                           '<td>{Dominio}</td>\n'
                           '<td>{CantEquipos}</td>\n'
                           '</tr>\n'
                           '\n').format(ID=ID, RUTA=RUTA, NAME=NAME, Dominio=Dominio, CantEquipos=CantEquipos))
    except ValueError as e:
        print ('[-] Hubo un error al intentar abrir el Archivo ' + work_dir + Out_Sumario)
        print (e)
        sys.exit(0)


def generaCuerpoWas(ID, NAME, RUTA):
    global Out_Sumario
    global work_dir
    try:
        with open(work_dir + Out_Sumario, 'a') as cfgFile:
            cfgFile.write(('\n'
                           '<tr>\n'
                           '<td>{ID}</td>\n'
                           '<td><a href="{RUTA}" target="_blank">{NAME}</a></td>\n'
                           '</tr>\n'
                           '\n').format(ID=ID, RUTA=RUTA, NAME=NAME))
    except ValueError as e:
        print ('[-] Hubo un error al intentar abrir el Archivo ' + work_dir + Out_Sumario)
        print (e)
        sys.exit(0)


def generaCabecera(tipo):
    global Out_Sumario
    global scansEXT
    global scansINT
    global maps
    global cliente
    global work_dir

    try:
        with open(work_dir + Out_Sumario, 'a') as Sumario:

            if tipo is 'sumario':

                Sumario.write(('\n'
                               '<html xmlns:fn="http://www.w3.org/2005/02/xpath-functions">\n'
                               '<head>\n'
                               '<title>Sumario de reportes - {cliente} </title>\n'
                               '<link rel="stylesheet" type="text/css" href="./Resources/css/css_scan.css"/>\n'
                               '</head>\n'
                               '<body id="report" class="scan_type">\n'
                               '<div id="window_pane">\n'
                               '<div>\n'
                               '<img src="./Resources/images/cgsi.jpg" class="logo_img" />\n'
                               '<h2><br />Sumario de reportes - {cliente}</h2>\n'
                               '</div>\n'
                               '\n').format(cliente=cliente))
            if tipo is 'maps':
                Sumario.write(('\n'
                               '<div>\n'
                               '<h5 class="sum_title">Descubrimiento de Dispositivos ({nn} maps)</h5>\n'
                               '<table class="vulnSum" cellspacing="0" cellpadding="0" border="0">\n'
                               '<tr class="by_severity">\n'
                               '<td width="40px">\n'
                               '<b>&Iacute;tem</b>\n'
                               '</td>\n'
                               '<td width="150px">\n'
                               '<b>Nombre</b>\n'
                               '</td>\n'
                               '<td width="250px">\n'
                               '<b>Dominio</b>\n'
                               '</td>\n'
                               '<td>\n'
                               '<b>Dispositivos descubiertos</b>\n'
                               '</td>\n'
                               '</tr>\n'
                               '\n').format(nn=str(len(maps))))
            if tipo is 'was':
                Sumario.write(('\n'
                               '<div>\n'
                               '<h5 class="sum_title">Escaneos de Aplicativos Web ({nn} escaneos)</h5>\n'
                               '<table class="vulnSum" cellspacing="0" cellpadding="0" border="0">\n'
                               '<tr class="by_severity">\n'
                               '<td width="40px">\n'
                               '<b>&Iacute;tem</b>\n'
                               '</td>\n'
                               '<td width="150px">\n'
                               '<b>Nombre</b>\n'
                               '</td>\n'
                               '<td width="250px">\n'
                               '<b></b>\n'
                               '</td>\n'
                               '<td>\n'
                               '<b></b>\n'
                               '</td>\n'
                               '</tr>\n'
                               '\n').format(nn=str(len(was_list))))
            if tipo is 'ext':
                Sumario.write(('\n'
                               '<div>\n'
                               '<h5 class="sum_title">Resumen de los Escaneos Externos ({nn} escaneos)</h5>\n'
                               '<table class="vulnSum" cellspacing="0" cellpadding="0" border="0">\n'
                               '<tr class="by_severity">\n'
                               '<td width="40px">\n'
                               '<b>&Iacute;tem</b>\n'
                               '</td>\n'
                               '<td width="150px">\n'
                               '<b>Direcci&oacute;n IP</b>\n'
                               '</td>\n'
                               '<td width="250px">\n'
                               '<b>Nombre del dispositivo</b>\n'
                               '</td>\n'
                               '<td>\n'
                               '<b>Sistema operativo</b>\n'
                               '</td>\n'
                               '<td width="150px">\n'
                               '<b>Riesgo de seguridad</b>\n'
                               '</td>\n'
                               '</tr>\n'
                               '\n').format(nn=str(len(scansEXT))))
            if tipo is 'int':
                Sumario.write(('\n'
                               '<h5 class="sum_title">Resumen de los Escaneos Internos ({nn} escaneos)</h5>\n'
                               '<table class="vulnSum" cellspacing="0" cellpadding="0" border="0">\n'
                               '<tr class="by_severity">\n'
                               '<td width="40px">\n'
                               '<b>&Iacute;tem</b>\n'
                               '</td>\n'
                               '<td width="150px">\n'
                               '<b>Direcci&oacute;n IP</b>\n'
                               '</td>\n'
                               '<td width="250px">\n'
                               '<b>Nombre del dispositivo</b>\n'
                               '</td>\n'
                               '<td>\n'
                               '<b>Sistema operativo</b>\n'
                               '</td>\n'
                               '<td width="150px">\n'
                               '<b>Riesgo de seguridad</b>\n'
                               '</td>\n'
                               '\n').format(nn=str(len(scansINT))))
            if tipo is 'cierre':
                Sumario.write(('\n'
                               '</br>\n'
                               '<p id="disclaimer">INFORMACI&Oacute;N CONFIDENCIAL Y PROPIETARIA. Copyright &copy;2017  , C.G.S.I., C.A.</p>\n'
                               '</div>\n'
                               '</div>\n'
                               '</body>\n'
                               '</html>\n'))
            if tipo is 'cola':
                Sumario.write(('\n'
                               '</table>\n'
                               '</br>\n'))
    except ValueError as e:
        print ('[-] Hubo un error al intentar abrir el Archivo ' + work_dir + Out_Sumario)
        print (e)
        sys.exit(0)


def ordena_SCANS():
    global scansEXT
    global scansINT
    scansEXT = ordena_Lista_por_IP(scansEXT)
    scansINT = ordena_Lista_por_IP(scansINT)


def ordena_Lista_por_IP(lista):
    global dB_CGSI
    dB_IP = {}
    output = []
    for key in lista:
        dB_IP[key] = dB_CGSI[key]['IP']
    list = sorted(dB_IP.items(), key=lambda item: socket.inet_aton(item[1]))
    for linea in list:
        output.append(linea[0])
    return output


def generaCuerpo_Scans(scan):
    global scansEXT
    global scansINT
    global positivo
    if scan == 'ext':
        print ('  > Generando Cuerpo Scans Externo')
        list = scansEXT
    else:
        print ('  > Generando Cuerpo Scans Interno')
        list = scansINT
    x = 1
    positivo = 0
    for File in list:
        ID = str(x).zfill(2)
        RUTA = dB_CGSI[File]['RUTA']
        IP = dB_CGSI[File]['IP']
        NAME = dB_CGSI[File]['NAME']
        OS = dB_CGSI[File]['OS']
        #RISK = dB_CGSI[File]['riesgoso']
        generaCuerpo(ID, RUTA, IP, NAME, OS)
        positivo += 1
        x += 1



def generaCuerpo_Maps():
    global maps
    print ('  > Generando Cuerpo Maps')
    x = 1
    for File in maps:
        ID = str(x).zfill(2)
        NAME = dB_CGSI[File]['NAME']
        Dominio = dB_CGSI[File]['Dominio']
        CantEquipos = dB_CGSI[File]['CantEquipos']
        RUTA = dB_CGSI[File]['RUTA']
        generaCuerpoMaps(ID, NAME, Dominio, CantEquipos, RUTA)
        x += 1


def generaCuerpo_Was():
    global dB_CGSI
    global was_list
    print ('  > Generando Cuerpo Was')
    x = 1
    for File in was_list:
        ID = str(x).zfill(2)
        NAME = dB_CGSI[File]['NAME']
        RUTA = dB_CGSI[File]['RUTA']
        generaCuerpoWas(ID, NAME, RUTA)
        x += 1


def obtener_datos():

    print ('[+] Obteniendo datos')
    # index = buscaINDEX()
    index = buscar_index()
    if len(index) < 1:
        print ('[-] No se pudieron recopilar los datos')
        return False
    else:
        for file in index:
            procesaINDEX_HTML(file)


        if (len(scansINT) + len(scansEXT)) < 1:
            print ('[-] No se pudo procesar ni un solo Scan')
            return False
        else:
            ordena_SCANS()
            print ('[+] Datos recopilados y ordenados')
            return True


def cuerpoCompletoMaps():
    generaCabecera('maps')
    generaCuerpo_Maps()
    generaCabecera('cola')


def cuerpoCompletoWAS():
    generaCabecera('was')
    generaCuerpo_Was()
    generaCabecera('cola')


def cuerpoCompletoScanExt():
    generaCabecera('ext')
    generaCuerpo_Scans('ext')
    generaCabecera('cola')


def cuerpoCompletoScanInt():
    generaCabecera('int')
    generaCuerpo_Scans('int')
    generaCabecera('cola')


def generaSumario():
    global work_dir
    global maps
    global was_list
    global scansEXT
    global scansINT
    print ('[+] Generando Sumario..')
    try:
        tool.limpia_archivo(work_dir + Out_Sumario)
        generaCabecera('sumario')
        if len(maps) > 0:
            cuerpoCompletoMaps()
            if len(was_list) > 0:
                cuerpoCompletoWAS()
        if len(scansEXT) > 0:
            cuerpoCompletoScanExt()
        if len(scansINT) > 0:
            cuerpoCompletoScanInt()
        generaCabecera('cierre')
        print ('[+] Sumario Generado ' + work_dir + Out_Sumario)
    except ValueError as E:
        print ("[-] Se genero un error intentando generar el Sumario")
        print( E )



def querydB_CGSI(key, struct):
    list = []
    for item in struct:
        list.append(dB_CGSI[key][item])
    return list


def generaEstadisticas():
    global Out_Estadistica
    global scansINT
    global scansEXT
    global struct_stadistic
    global work_dir
    print ('[+] Generando Estadisticas..')
    tool.limpia_archivo(work_dir + Out_Estadistica)
    try:
        with open(work_dir + Out_Estadistica, 'a') as file:
            file.write(','.join(struct_stadistic) + '\n')
            for key in scansEXT:
                line = querydB_CGSI(key, struct_stadistic)
                file.write(','.join(line) + '\n')
            for key in scansINT:
                line = scansINT
                line = querydB_CGSI(key, struct_stadistic)
                file.write(','.join(line) + '\n')
    except ValueError as e:
        print ('[-] Hubo un error al intentar abrir el Archivo ' + work_dir + Out_Estadistica)

        #sys.exit(0)
    print ('[+] Estadisticas Generadas..' + work_dir + Out_Estadistica)


def formateaArchivos():
    print ('[+] Formateando Archivos')
    global scansEXT
    global scansINT
    global dB_CGSI
    antes = "2013, C.G.S.I., C.A."
    despues = "2017, C.G.S.I., C.A."


    for file in scansINT:
        modificaTexto(dB_CGSI[file]['RUTA'], antes, despues)
    for file in scansEXT:
        modificaTexto(dB_CGSI[file]['RUTA'], antes, despues)
    for file in maps:
        modificaTexto(dB_CGSI[file]['RUTA'], antes, despues)
    print ('[+] Archivos formateados')


def modificaTexto(file, antes, despues):
    try:
        os.system('sed -i "s/' + antes + '/' + despues + '/" ' + file)
    except ValueError as e:
        print (e)
        sys.exit(0)


def main():
    global cliente
    global work_dir
    global lista_de_ips
    parser = optparse.OptionParser("%prog -c <Cliente> -d <Directorio> -in <Lista de IPs>")
    parser.add_option('-d', dest='Directorio', type='string', help='Ruta de Trabajo (Opcional)')
    parser.add_option('-c', dest='Cliente', type='string', help='Nombre del cliente (Opcional)')
    (options, args) = parser.parse_args()
    if options.Cliente is not None:
        cliente = options.Cliente
        cliente = cliente
    if options.Directorio is not None:
        if os.path.isdir(options.Directorio):
            work_dir = options.Directorio
            work_dir = work_dir
        else:
            print ("[-] El directorio " + options.Directorio + " no existe")
            sys.exit(0)
    menu()


if __name__ == '__main__':
    try:
        qgc = inicia_qualys(qgc, None)
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Se ha Precionado Ctrl+[C]\n"
              "    Hasta Luego..")
