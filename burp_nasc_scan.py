# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_date(date_str):
    # Verifica se a data está no formato DD/MM/AAAA e se é uma data válida
    day, month, year = map(int, date_str.split('/'))
    
    # Regras básicas de validação de data
    if 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2100:
        # Verifica fevereiro e anos bissextos
        if month == 2:
            if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                return day <= 29
            else:
                return day <= 28
        # Meses com 30 dias
        elif month in [4, 6, 9, 11]:
            return day <= 30
        # Meses com 31 dias
        else:
            return True
    return False

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Birthdate Finder") # Nome da extensão
        callbacks.registerHttpListener(self)
        print("Birthdate Finder, Installation OK!!!") # Mensagem de confirmação

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processar a resposta HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extrair o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Procurar por datas de nascimento no formato DD/MM/AAAA
            date_pattern = re.compile(r'\b\d{2}/\d{2}/\d{4}\b')
            possible_dates = date_pattern.findall(body)
            possible_dates = list(set(possible_dates)) # Remover duplicados
            
            # Validar as datas encontradas
            valid_dates = [date for date in possible_dates if validate_date(date)]
            
            if valid_dates: # Se encontrar datas válidas, cria uma questão
                print("Found Valid Birthdate(s): %s" % ', '.join(valid_dates))
