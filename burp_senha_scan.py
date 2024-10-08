# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_password(password):
    # Simples validação de senha: ao menos 8 caracteres, contendo letras e números
    if len(password) < 8:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configurações iniciais
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Password Finder") # Nome da extensão
        callbacks.registerHttpListener(self)
        print("Password Finder, Installation OK!!!") # Mensagem de confirmação

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processar a resposta HTTP
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extrair o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # Procurar padrões que possam ser senhas
            # A regex a seguir é básica e procura por strings que tenham ao menos 8 caracteres alfanuméricos
            password_pattern = re.compile(r'\b[A-Za-z0-9@#$%^&+=]{8,}\b')
            possible_passwords = password_pattern.findall(body)
            possible_passwords = list(set(possible_passwords)) # Remover duplicados
            valid_passwords = [password for password in possible_passwords if validate_password(password)]

            if valid_passwords: # Se encontrar senhas válidas, cria uma questão
                print("Found Valid Password(s): %s" % ', '.join(valid_passwords))
