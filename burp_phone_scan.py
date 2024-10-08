# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_phone(phone):
    # Lista de DDDs válidos no Brasil
    valid_ddds = {
        '11', '12', '13', '14', '15', '16', '17', '18', '19', # São Paulo
        '21', '22', '24', # Rio de Janeiro
        '27', '28', # Espírito Santo
        '31', '32', '33', '34', '35', '37', '38', # Minas Gerais
        '41', '42', '43', '44', '45', '46', # Paraná
        '47', '48', '49', # Santa Catarina
        '51', '53', '54', '55', # Rio Grande do Sul
        '61', # Distrito Federal
        '62', '64', # Goiás
        '63', # Tocantins
        '65', '66', # Mato Grosso
        '67', # Mato Grosso do Sul
        '68', # Acre
        '69', # Rondônia
        '71', '73', '74', '75', '77', # Bahia
        '79', # Sergipe
        '81', '87', # Pernambuco
        '82', # Alagoas
        '83', # Paraíba
        '84', # Rio Grande do Norte
        '85', '88', # Ceará
        '86', '89', # Piauí
        '91', '93', '94', # Pará
        '92', '97', # Amazonas
        '95', # Roraima
        '96', # Amapá
        '98', '99' # Maranhão
    }
    
    ddd = phone[:2]
    return ddd in valid_ddds

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Phone Number Finder") # Nome da extensão
        callbacks.registerHttpListener(self)
        print("Phone Number Finder, Installation OK!!!") # Mensagem de confirmação

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processar a resposta HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extrair o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Procurar por números de telefone no formato DDD + Número
            phone_pattern = re.compile(r'\b\d{2}\s\d{9}\b')
            possible_phones = phone_pattern.findall(body)
            possible_phones = list(set(possible_phones)) # Remover duplicados
            
            # Validar os números de telefone encontrados
            valid_phones = [phone for phone in possible_phones if validate_phone(phone)]
            
            if valid_phones: # Se encontrar números de telefone válidos, cria uma questão
                print("Found Valid Phone Number(s): %s" % ', '.join(valid_phones))
