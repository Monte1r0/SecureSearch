# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_cpf(cpf):
    # Remove pontos e traços
    cpf = cpf.replace(".", "").replace("-", "")
    
    # Verifica se o CPF tem 11 dígitos
    if len(cpf) != 11:
        return False
    
    # Verifica se todos os dígitos são iguais
    if cpf == cpf[0] * 11:
        return False
    
    # Cálculo dos dígitos verificadores
    for i in range(9, 11):
        value = sum(int(cpf[num]) * ((i + 1) - num) for num in range(0, i))
        digit = (value * 10) % 11
        if digit == 10:
            digit = 0
        if digit != int(cpf[i]):
            return False

    return True

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CPF Finder") # Nome da extensão
        callbacks.registerHttpListener(self)
        print("CPF Finder, Installation OK!!!") # Mensagem de confirmação

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processar a resposta HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extrair o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Procurar CPFs e validar
            cpf_pattern = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')
            possible_cpfs = cpf_pattern.findall(body)
            possible_cpfs = list(set(possible_cpfs)) # Remover duplicados
            valid_cpfs = [cpf for cpf in possible_cpfs if validate_cpf(cpf)]

            if valid_cpfs: # Se encontrar CPFs válidos, cria uma questão
                print("Found Valid CPF(s): %s" % ', '.join(valid_cpfs))

