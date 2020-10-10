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
    if request.method == 'POST':

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': ''})


    else:
        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':'', 'outputs':''})

