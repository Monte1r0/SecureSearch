# -*- coding: utf-8 -*-  # Declara a codificação do arquivo como UTF-8 para garantir que caracteres especiais sejam tratados corretamente.

import re  # Importa o módulo de expressões regulares, utilizado para encontrar padrões em textos.
from burp import IBurpExtender, IHttpListener  # Importa interfaces do Burp Suite para criar extensões e ouvir mensagens HTTP.

# Função para calcular o checksum de Luhn, utilizado para validar números de cartão de crédito.
def luhn_checksum(card_number):
    # Função interna para converter um número em uma lista de dígitos.
    def digits_of(n):
        return [int(d) for d in str(n)]  # Converte um número em uma lista de seus dígitos individuais.

    digits = digits_of(card_number.replace(' ', ''))  # Remove espaços e converte o número do cartão em uma lista de dígitos.
    odd_digits = digits[-1::-2]  # Obtém os dígitos das posições ímpares (do final para o início).
    even_digits = digits[-2::-2]  # Obtém os dígitos das posições pares.

    checksum = sum(odd_digits)  # Soma os dígitos das posições ímpares.
    for d in even_digits:
        checksum += sum(digits_of(d * 2))  # Soma os dígitos dos valores multiplicados por 2 (validação Luhn).

    return checksum % 10 == 0  # Retorna True se o checksum for válido (divisível por 10).

# Função para validar um número de CPF.
def validate_cpf(cpf):
    cpf = cpf.replace(".", "").replace("-", "")  # Remove pontos e hífens do CPF.
    if len(cpf) != 11:  # Verifica se o CPF tem exatamente 11 dígitos.
        return False
    if cpf == cpf[0] * 11:  # Verifica se o CPF é uma sequência repetida (por exemplo, "11111111111").
        return False
    for i in range(9, 11):
        # Calcula o dígito verificador.
        value = sum(int(cpf[num]) * ((i + 1) - num) for num in range(0, i))
        digit = (value * 10) % 11
        if digit == 10:
            digit = 0
        if digit != int(cpf[i]):
            return False  # Retorna False se o dígito verificador não corresponder.
    return True  # Retorna True se o CPF for válido.

# Função para validar datas no formato dd/mm/aaaa.
def validate_date(date_str):
    day, month, year = map(int, date_str.split('/'))  # Divide a string da data em dia, mês e ano.
    if 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2100:
        if month == 2:  # Verifica se o mês é fevereiro.
            if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):  # Verifica se o ano é bissexto.
                return day <= 29
            else:
                return day <= 28
        elif month in [4, 6, 9, 11]:  # Meses com 30 dias.
            return day <= 30
        else:  # Meses com 31 dias.
            return True
    return False  # Retorna False se a data não for válida.

# Função para validar números de telefone.
def validate_phone(phone):
    valid_ddds = {  # Conjunto de DDDs válidos para São Paulo e outras regiões.
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
    ddd = phone[:2]  # Obtém o DDD do telefone.
    return ddd in valid_ddds  # Retorna True se o DDD for válido.

# Função para validar endereços de e-mail.
def validate_email(email):
    email_pattern = re.compile(r'^[-\w.]+@([-\w]+\.)+[a-zA-Z]{2,7}$')  # Define o padrão para e-mail.
    return email_pattern.match(email) is not None  # Retorna True se o e-mail corresponder ao padrão.

# Função para validar RG.
def validate_rg(rg):
    rg = re.sub(r'\D', '', rg)  # Remove caracteres não numéricos do RG.
    return len(rg) == 9 and re.match(r'\d{8}-\d\b', rg)  # Verifica se o RG tem 9 dígitos e corresponde ao padrão.

# Classe BurpExtender implementa IBurpExtender e IHttpListener para a extensão do Burp Suite.
class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks  # Armazena o objeto de callbacks.
        self._helpers = callbacks.getHelpers()  # Obtém o helper do Burp Suite.
        callbacks.setExtensionName("Sensitive Information Finder")  # Define o nome da extensão.
        callbacks.registerHttpListener(self)  # Registra a extensão como ouvinte de HTTP.
        print("Sensitive Information Finder, Installation OK!!!")  # Mensagem de instalação bem-sucedida.

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:  # Apenas processa respostas HTTP, não solicitações.
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())  # Analisa a resposta HTTP.
            body_offset = response_info.getBodyOffset()  # Obtém o deslocamento do corpo da resposta.
            body_bytes = messageInfo.getResponse()[body_offset:]  # Extrai o corpo da resposta.
            body = self._helpers.bytesToString(body_bytes)  # Converte bytes em string.

            # Encontrar e validar números de cartão de crédito.
            cc_pattern = re.compile(r'\b(?:\d{4} ){3}\d{4}\b')  # Padrão para números de cartão de crédito.
            possible_ccs = cc_pattern.findall(body)  # Encontra possíveis números de cartão de crédito.
            possible_ccs = list(set(possible_ccs))  # Remove duplicatas.
            valid_ccs = [cc for cc in possible_ccs if luhn_checksum(cc)]  # Valida números com o checksum de Luhn.
            if valid_ccs:
                print("Found Valid Credit Card(s): %s" % ', '.join(valid_ccs))  # Imprime números válidos.

            # Encontrar e validar CPFs.
            cpf_pattern = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')  # Padrão para CPF.
            possible_cpfs = cpf_pattern.findall(body)  # Encontra possíveis CPFs.
            possible_cpfs = list(set(possible_cpfs))  # Remove duplicatas.
            valid_cpfs = [cpf for cpf in possible_cpfs if validate_cpf(cpf)]  # Valida CPFs.
            if valid_cpfs:
                print("Found Valid CPF(s): %s" % ', '.join(valid_cpfs))  # Imprime CPFs válidos.

            # Encontrar e validar datas de nascimento.
            date_pattern = re.compile(r'\b\d{2}/\d{2}/\d{4}\b')  # Padrão para datas.
            possible_dates = date_pattern.findall(body)  # Encontra possíveis datas.
            possible_dates = list(set(possible_dates))  # Remove duplicatas.
            valid_dates = [date for date in possible_dates if validate_date(date)]  # Valida datas.
            if valid_dates:
                print("Found Valid Birthdate(s): %s" % ', '.join(valid_dates))  # Imprime datas válidas.

            # Encontrar e validar números de telefone.
            phone_pattern = re.compile(r'\b\d{2}\s\d{9}\b')  # Padrão para números de telefone.
            possible_phones = phone_pattern.findall(body)  # Encontra possíveis números de telefone.
            possible_phones = list(set(possible_phones))  # Remove duplicatas.
            valid_phones = [phone for phone in possible_phones if validate_phone(phone)]  # Valida telefones.
            if valid_phones:
                print("Found Valid Phone(s): %s" % ', '.join(valid_phones))  # Imprime números de telefone válidos.

            # Encontrar e validar endereços de e-mail.
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')  # Padrão para e-mail.
            possible_emails = email_pattern.findall(body)  # Encontra possíveis e-mails.
            possible_emails = list(set(possible_emails))  # Remove duplicatas.
            valid_emails = [email for email in possible_emails if validate_email(email)]  # Valida e-mails.
            if valid_emails:
                print("Found Valid Email(s): %s" % ', '.join(valid_emails))  # Imprime e-mails válidos.

            # Encontrar e validar RGs.
            rg_pattern = re.compile(r'\b\d{8}-\d\b')  # Padrão para RG.
            possible_rgs = rg_pattern.findall(body)  # Encontra possíveis RGs.
            possible_rgs = list(set(possible_rgs))  # Remove duplicatas.
            valid_rgs = [rg for rg in possible_rgs if validate_rg(rg)]  # Valida RGs.
            if valid_rgs:
                print("Found Valid RG(s): %s" % ', '.join(valid_rgs))  # Imprime RGs válidos.
