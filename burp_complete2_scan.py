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

def validate_cpf(cpf):
    cpf = cpf.replace(".", "").replace("-", "")
    if len(cpf) != 11:
        return False
    if cpf == cpf[0] * 11:
        return False
    for i in range(9, 11):
        value = sum(int(cpf[num]) * ((i + 1) - num) for num in range(0, i))
        digit = (value * 10) % 11
        if digit == 10:
            digit = 0
        if digit != int(cpf[i]):
            return False
    return True

def validate_date(date_str):
    day, month, year = map(int, date_str.split('/'))
    if 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2100:
        if month == 2:
            if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                return day <= 29
            else:
                return day <= 28
        elif month in [4, 6, 9, 11]:
            return day <= 30
        else:
            return True
    return False

def validate_phone(phone):
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

def validate_email(email):
    email_pattern = re.compile(r'^[-\w.]+@([-\w]+\.)+[a-zA-Z]{2,7}$')
    return email_pattern.match(email) is not None

def validate_rg(rg):
    rg = re.sub(r'\D', '', rg)
    return len(rg) == 9 and re.match(r'\d{8}-\d', rg)

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sensitive Information Finder")
        callbacks.registerHttpListener(self)
        print("Sensitive Information Finder, Installation OK!!!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)

            # Encontrar e validar números de cartão de crédito
            cc_pattern = re.compile(r'\b(?:\d{4} ){3}\d{4}\b')
            possible_ccs = cc_pattern.findall(body)
            possible_ccs = list(set(possible_ccs))
            valid_ccs = [cc for cc in possible_ccs if luhn_checksum(cc)]
            if valid_ccs:
                print("Found Valid Credit Card(s): %s" % ', '.join(valid_ccs))

            # Encontrar e validar CPFs
            cpf_pattern = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')
            possible_cpfs = cpf_pattern.findall(body)
            possible_cpfs = list(set(possible_cpfs))
            valid_cpfs = [cpf for cpf in possible_cpfs if validate_cpf(cpf)]
            if valid_cpfs:
                print("Found Valid CPF(s): %s" % ', '.join(valid_cpfs))

            # Encontrar e validar datas de nascimento
            date_pattern = re.compile(r'\b\d{2}/\d{2}/\d{4}\b')
            possible_dates = date_pattern.findall(body)
            possible_dates = list(set(possible_dates))
            valid_dates = [date for date in possible_dates if validate_date(date)]
            if valid_dates:
                print("Found Valid Birthdate(s): %s" % ', '.join(valid_dates))

            # Encontrar e validar números de telefone
            phone_pattern = re.compile(r'\b\d{2}\s\d{9}\b')
            possible_phones = phone_pattern.findall(body)
            possible_phones = list(set(possible_phones))
            valid_phones = [phone for phone in possible_phones if validate_phone(phone)]
            if valid_phones:
                print("Found Valid Phone Number(s): %s" % ', '.join(valid_phones))

            # Encontrar e validar e-mails
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
            possible_emails = email_pattern.findall(body)
            possible_emails = list(set(possible_emails))
            valid_emails = [email for email in possible_emails if validate_email(email)]
            if valid_emails:
                print("Found Valid Email(s): %s" % ', '.join(valid_emails))

            # Encontrar e validar RGs
            rg_pattern = re.compile(r'\b\d{8}-\d\b')
            possible_rgs = rg_pattern.findall(body)
            possible_rgs = list(set(possible_rgs))
            valid_rgs = [rg for rg in possible_rgs if validate_rg(rg)]
            if valid_rgs:
                print("Found Valid RG(s): %s" % ', '.join(valid_rgs))
