# -*- coding: utf-8 -*-
import re
from burp import IBurpExtender, IHttpListener

def validate_email(email):
    # Simple regex pattern for validating email addresses
    email_pattern = re.compile(r'^[-\w.]+@([-\w]+\.)+[a-zA-Z]{2,7}$')
    return email_pattern.match(email) is not None

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # initial configs
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Email Finder") # Name of the extension
        callbacks.registerHttpListener(self)
        print("Email Finder, Installation OK!!!") # Confirmation message

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # process http response
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # extract body response
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            
            # looking for emails and validate
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
            possible_emails = email_pattern.findall(body)
            possible_emails = list(set(possible_emails)) # remove duplicates
            valid_emails = [email for email in possible_emails if validate_email(email)]

            if valid_emails: # if found valid emails, create issue
                print("Found Valid Email(s): %s" % ', '.join(valid_emails))
