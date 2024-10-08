# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number.replace(' ', ''))
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))
    return checksum % 10 == 0

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Credit Card Finder") # Nome da extensão
        callbacks.registerHttpListener(self)
        print("Credit Card Finder, Installation OK!!!") # Mensagem de confirmação

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processar a resposta HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extrair o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Procurar por números de cartão de crédito no formato 5454 8796 2154 1412
            cc_pattern = re.compile(r'\b(?:\d{4} ){3}\d{4}\b')
            possible_ccs = cc_pattern.findall(body)
            possible_ccs = list(set(possible_ccs)) # Remover duplicados
            
            # Validar os números de cartão de crédito usando o algoritmo de Luhn
            valid_ccs = [cc for cc in possible_ccs if luhn_checksum(cc)]
            
            if valid_ccs: # Se encontrar cartões de crédito válidos, cria uma questão
                print("Found Valid Credit Card(s): %s" % ', '.join(valid_ccs))
