import shutil

from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from pp_role_mining.privacyPreserving import privacyPreserving
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper

from .anonymizationOperations import *


def anonymization_main(request):
    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)

    if request.method == 'POST':
        reqValues = extractHttpRequestValues(request)
        result = {'State' : 'Empty'}

        if 'testButton' in request.POST:
            result['OP'] = reqValues['OP_Operation'].Process(event_log, reqValues)

            if(settings.DEBUG):
                result['Log'] = event_log

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': result})


    else:
        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':'', 'outputs':'Main Else Case'})


def extractHttpRequestValues(request):
    values = {}

    if 'DDMB_anon_operation_DATA' in request.POST:
        values['OP_Operation'] = getAnonymizer(request.POST['DDMB_anon_operation_DATA'])

    if 'DDMB_anon_applLevel_DATA' in request.POST:
        values['OP_Level'] = request.POST['DDMB_anon_applLevel_DATA']

    if 'DDMB_anon_target_DATA' in request.POST:
        values['OP_Target'] = request.POST['DDMB_anon_target_DATA']

    return values

def getAnonymizer(name):
    if(name == 'Addition'):
        return Addition_AO()
    elif(name == 'Condensation'):
        return Condensation_AO()
    elif(name == 'Cryptography'):
        return Cryptography_AO()
    elif(name == 'Generalization'):
        return Generalization_AO()
    elif(name == 'Substitution'):
        return Substitution_AO()
    elif(name == 'Supression'):
        return Supression_AO()
    elif(name == 'Swapping'):
        return Swapping_AO()
    else:
        raise NotImplementedError
    pass