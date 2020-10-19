import shutil

from django.shortcuts import render
from django.conf import settings
import os
from os import path
from datetime import datetime
from pp_role_mining.privacyPreserving import privacyPreserving
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper
import json
from .anonymizationOperations import *

from pm4py.objects.log.exporter.xes import factory as xes_exporter


def anonymization_main(request):
    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)

    if request.method == 'POST':
        reqValues = extractHttpRequestValues(request)
        result = {'State' : 'Empty'}

        if request.is_ajax():
            xes_log = xes_importer_factory.apply(event_log)
            case_attribs = []
            for case_index, case in enumerate(xes_log):
                for key in case.attributes.keys():
                    if key not in case_attribs:
                        case_attribs.append(key)
            event_attribs = []
            for case_index, case in enumerate(xes_log):
                for event_index, event in enumerate(case):
                    for key in event.keys():
                        if key not in event_attribs:
                            event_attribs.append(key)

            json_respone = {'case_attributes': case_attribs, 'event_attributes': event_attribs}
            return HttpResponse(json.dumps(json_respone),content_type='application/json')

        elif 'testButton' in request.POST:
            result['OP'] = reqValues['OP_Operation'].Process(event_log, reqValues)

            if(settings.DEBUG):
                result['Log'] = event_log

        elif 'applyButton' in request.POST:
            result['OP'] = reqValues['OP_Operation'].Process(event_log, reqValues)

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': result})


    else:
        if request.is_ajax():
            attributes = []
            action = getRequestParameter(request.GET, 'action')

            if 'getLogCaseAttributes' == action:
                attributes = getLogCaseAttributes(event_log)
            elif 'getLogEventAttributes' == action:
                attributes = getLogEventAttributes(event_log)

            json_respone = {'attributes': attributes}
            return HttpResponse(json.dumps(json_respone),content_type='application/json')
        else:
            return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values':'', 'outputs':'Main Else Case'})


def extractHttpRequestValues(request):
    values = {}

    values['OP_Operation'] = getAnonymizer(getRequestParameter(request.POST,'DDMB_anon_operation_DATA'))
    values['OP_Level'] = getRequestParameter(request.POST,'DDMB_anon_applLevel_DATA')
    values['OP_Target'] = getRequestParameter(request.POST,'DDMB_anon_target_DATA')

    return values

def getRequestParameter(requestData, parameter):
    if parameter in requestData:
        return requestData[parameter]
    else:
        return None

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

def getLogCaseAttributes(event_log):
    xes_log = xes_importer_factory.apply(event_log)
    case_attribs = []
    for case_index, case in enumerate(xes_log):
        for key in case.attributes.keys():
            if key not in case_attribs:
                case_attribs.append(key)
    return case_attribs
    pass

def getLogEventAttributes(event_log):
    xes_log = xes_importer_factory.apply(event_log)
    event_attribs = []
    for case_index, case in enumerate(xes_log):
        for event_index, event in enumerate(case):
            for key in event.keys():
                if key not in event_attribs:
                    event_attribs.append(key)
    return event_attribs
    pass