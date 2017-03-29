#!/usr/bin/env python
# ------------------------------------------------------------------------------
import linecache
import os

from IPy import IP
import platform
import socket
from prettytable import PrettyTable
from progressbar import *
import datetime


def erase_line_with(string, file, elines=1):
    output_file = ""
    if elines is 0:  # Evita un mal argumento
        elines = 1
    erase = elines
    try:
        with open(file,'r') as input_file:
            for line in input_file:
                if erase < elines:
                    #print "[-] Line Erased"      # BORRA por Conteo
                    #print line
                    erase += 1
                elif string not in line:         # NO BORRA
                    output_file += line
                else:
                    #print "[-] Line Erased"      # BORRADO NORMAL
                    #print line
                    erase = 1
    except ValueError as E:
        print "[-] Hubo un error al leer o procesar el archivo "+E
    try:
        with open(file,'w') as output:
            output.write(output_file)
    except ValueError as E:
        print "[-] Hubo un error al escribir el archivo "+E


def cleanScreen():
    CurrentOS = platform.system()
    if CurrentOS is "Windows":
        os.system('cls')
    elif CurrentOS is "Linux":
        os.system('clear')


#def progress_delay(time_count):
    #tmp_time = int(time_count)
    #progress = ProgressBar()
    #print "[+] En espera por "+str(datetime.timedelta(seconds=tmp_time))
    #for i in progress(range(tmp_time)):
        #time.sleep(1)


def querydb(db, key, struct):
    '''
    Esta funcion genera una lista del contenido de una llave dentro de un diccionario de diccionarios
    :param db:
    :param key:
    :param struct:
    :return:
    '''
    tmp_list = []
    for item in struct:
        tmp_list.append(db[key][item])
    return tmp_list


def print_dict(db, headers, align=None, keys=None, sort=None):
    '''
    Esta funcion hace un print visualmente atractivo, del contenido de un diccionario
    :param db:
    :param headers:
    :param align:
    :param keys:
    :param sort:
    :return:
    '''
    tabla = PrettyTable(headers)
    tabla.padding_width = 1
    if align is None:
        align = ["Scan_Name", "IP"]
    for x in align:
        tabla.align[x] = "l"
    if keys is None:
        for key in db.keys():
            tmp_list = querydb(db, key, headers)
            tabla.add_row(tmp_list)
    else:
        for key in keys:
            tmp_list = querydb(db, key, headers)
            tabla.add_row(tmp_list)
    if sort is None:
        print tabla
    else:
        print tabla.get_string(sortby=sort)


def is_number(var):
    try:
        out = int(var)
        return True
    except ValueError:
        return False


def get_date_ago(num_of_days):
    out_date = datetime.datetime.now() + datetime.timedelta(-num_of_days)
    return out_date.strftime("%Y-%m-%dT00:00:00Z")


def busca_linea(file, word):
    count = 1
    try:
        with open(file, 'r') as index:
            for line in index:
                if word in line:
                    break
                else:
                 count += 1

    except ValueError as e:
        print '[-] No se pudo abrir el archivo ' + file
        print e
        sys.exit(0)
        # print '[+]The word '+word+' is located in line '+str(count)+' of file '+file
    return count


def get_linea(file, ubicacion):
    return linecache.getline(file, ubicacion)

def get_linea_texto(file, word):
    posicion = busca_linea(file, word)
    return get_linea(file, posicion)


def set_default(val, default):
    if val == '':
        val = default
    return val


def pyfind(pattern='*', directory='./'):
    list_out = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(pattern):
                list_out.append(os.path.join(root, file))
    return list_out


def find_dirs(pattern='*', root_dir='./'):
    full_dir_list = []
    for root, dirs, files in os.walk(root_dir):
        for directory in dirs:
            if directory.startswith(pattern):
                full_dir_list.append(os.path.join(root, directory))
    return full_dir_list


def limpia_archivo(arch):
    if os.path.isfile(arch):
        try:
            open(arch, "w").close()
            print '[-] Se elimino el archivo ' + arch + ' anterior'
        except ValueError as e:
            print e


def elimina_archivo(arch):
    if os.path.isfile(arch):
        try:
            os.remove(arch)
            #print '[-] Se elimino el archivo ' + arch
        except ValueError as e:
            print e

def is_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def get_iniciales(nombre):
    return nombre.split(" ")[0][0].upper() + nombre.split(" ")[1][0].upper()


def is_private(input_ip):
    try:
        ip = IP(input_ip)
        if ip.iptype() is "PRIVATE":
            return True
        else:
            return False
    except ValueError as E:
        print E
        return False


def hora_permitida(tmp_start_time, tmp_end_time, tmp_now="", tmp_min=""):
    if tmp_now is "":
        hora_actual = int(datetime.datetime.now().strftime('%H'))
        min_actual = int(datetime.datetime.now().strftime('%M'))
    else:
        hora_actual = int(tmp_now)
        min_actual = int(tmp_min)
    start_time = int(tmp_start_time)
    end_time = int(tmp_end_time)
    if start_time == end_time == 0:
        #print "[+] Horario permitido"
        return True
    if start_time > end_time:
        if hora_actual >= start_time:
            if (end_time is 0 and hora_actual is 23) and (min_actual > 45):
                #print "[-] Quedan 15 minutos para finalizar la ventana de tiempo"
                return False
            else:
                #print "[+] Horario permitido"
                return True
        elif hora_actual < end_time:
            if (hora_actual is end_time-1) and (min_actual > 45):
                #print "[-] Quedan 15 minutos para finalizar la ventana de tiempo"
                return False
            else:
                #print "[+] Horario permitido"
                return True
        else:
            #print "[-] Horario no permitido"
            return False
    else:
        if (hora_actual >= start_time) and (hora_actual < end_time):
            if (hora_actual is end_time-1) and (min_actual > 45):
                #print "[-] Quedan 15 minutos para finalizar la ventana de tiempo"
                return False
            else:
                #print "[+] Horario permitido"
                return True
        else:
            #print "[-] Horario no permitido"
            return False


def check_time(lv_start, lv_end, sd_start, sd_end):
    today = datetime.datetime.today().weekday()
    if today >= 5:
        #print "[+] Aplicando horario de Fin de Semana"
        return hora_permitida(sd_start, sd_end)
    else:
        #print "[+] Aplicando horario de Semana"
        return hora_permitida(lv_start, lv_end)


def check_time_loop(lv_start, lv_end, sd_start, sd_end):
    if not check_time(lv_start, lv_end, sd_start, sd_end):
        print("[-] Esperando por horario permitido")
        while not check_time(lv_start, lv_end, sd_start, sd_end):
            time.sleep(60)