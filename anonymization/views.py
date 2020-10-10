import shutil

from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from pp_role_mining.privacyPreserving import privacyPreserving
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper


def anonymization_main(request):
    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

    if request.method == 'POST':
        reqValues = extractHttpRequestValues(request)

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': ''})


    else:
        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':'', 'outputs':''})


def extractHttpRequestValues(request):
    values = {}
    values['OP_Operation'] = request.POST['DDMB_anon_operation']
    values['OP_Level'] = request.POST['DDMB_anon_applLevel']
    values['OP_Target'] = request.POST['DDMB_anon_target']

    return values
