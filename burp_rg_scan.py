# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_rg(rg):
    # Remove possíveis caracteres especiais e valida comprimento
    rg = re.sub(r'\D', '', rg)  # Remove tudo que não for número
    return 7 <= len(rg) <= 9  # RG geralmente tem entre 7 e 9 dígitos

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RG Finder")  # Nome da extensão
        callbacks.registerHttpListener(self)
        print("RG Finder, Installation OK!!!")  # Mensagem de confirmação

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processar a resposta HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extrair corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Procurar possíveis RGs no corpo da resposta
            rg_pattern = re.compile(r'\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9X]\b')
            possible_rgs = rg_pattern.findall(body)
            possible_rgs = list(set(possible_rgs))  # Remover duplicatas
            valid_rgs = [rg for rg in possible_rgs if validate_rg(rg)]  # Validar os RGs

            if valid_rgs:  # Se encontrar RGs válidos, exibir
                print("Found Valid RG(s): %s" % ', '.join(valid_rgs))
