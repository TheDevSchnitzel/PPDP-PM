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
from ppdp_anonops import *

from pm4py.objects.log.importer.xes import factory as xes_importer
from pm4py.objects.log.exporter.xes import factory as xes_exporter


def anonymization_main(request):
    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)

    appState = extractStateFromHttpRequestValues(request)

    if request.method == 'POST':
        reqValues = extractHttpRequestValues(request)
        result = {'State': 'Empty'}

        if request.is_ajax():
            xes_log = xes_importer.apply(event_log)
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
            return HttpResponse(json.dumps(json_respone), content_type='application/json')

        # Handling of output buttons
        elif 'downloadButton' in request.POST:
            return handleXesLogDownloadButtonClick(request)
        elif 'addButton' in request.POST:
            return handleXesLogAddButtonClick(request)
        elif "deleteButton" in request.POST:
            return handleXesLogDeleteButtonClick(request)

        elif 'testButton' in request.POST:
            result['OP'] = Supression(event_log).Process(event_log, {'OP_Level': 'Case', 'OP_Target': 'Case'})

            # Apparently needed so pm4py export won't crash
            result['OP']['extensions'] = {'value': None, 'children': []}

            xes_exporter.export_log(result['OP'], os.path.join(event_logs_path, "exportedLog.xes"))
            #xes_exporter.export_log(xes_log, os.path.join(event_logs_path, "exportedLog.xes"))
            #result['OP'] = reqValues['OP_Operation'].Process(event_log, reqValues)

            if(settings.DEBUG):
                result['Log'] = event_log

        elif 'applyButton' in request.POST:
            result['OP'] = reqValues['OP_Operation'].Process(event_log, reqValues)

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': getOutputFileList("anonymization"), 'result': result, 'appState': json.dumps(appState)})

    else:
        if request.is_ajax():
            attributes = []
            action = getRequestParameter(request.GET, 'action')

            if 'getLogCaseAttributes' == action:
                attributes = getLogCaseAttributes(event_log)
            elif 'getLogEventAttributes' == action:
                attributes = getLogEventAttributes(event_log)

            json_respone = {'attributes': attributes}
            return HttpResponse(json.dumps(json_respone), content_type='application/json')
        else:
            return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': getOutputFileList("anonymization"), 'appState': json.dumps(appState, ensure_ascii=True)})


def extractStateFromHttpRequestValues(request):
    appState = {}

    appState["Operations"] = getRequestParameter(request.POST, 'Operations')
    if(appState["Operations"] is None):
        appState["Operations"] = []

    return appState


def extractHttpRequestValues(request):
    values = {}

    values['OP_Operation'] = getAnonymizer(getRequestParameter(request.POST, 'DDMB_anon_operation_DATA'))
    values['OP_Level'] = getRequestParameter(request.POST, 'DDMB_anon_applLevel_DATA')
    values['OP_Target'] = getRequestParameter(request.POST, 'DDMB_anon_target_DATA')

    return values


def getRequestParameter(requestData, parameter):
    if parameter in requestData:
        return requestData[parameter]
    else:
        return None


def getAnonymizer(name):
    if(name == 'Addition'):
        return Addition()
    elif(name == 'Condensation'):
        return Condensation()
    elif(name == 'Cryptography'):
        return Cryptography()
    elif(name == 'Generalization'):
        return Generalization()
    elif(name == 'Substitution'):
        return Substitution()
    elif(name == 'Supression'):
        return Supression()
    elif(name == 'Swapping'):
        return Swapping()
    # else:
        #raise NotImplementedError
    pass


def getLogCaseAttributes(event_log):
    xes_log = xes_importer.apply(event_log)
    case_attribs = []
    for case_index, case in enumerate(xes_log):
        for key in case.attributes.keys():
            if key not in case_attribs:
                case_attribs.append(key)
    return case_attribs
    pass


def getLogEventAttributes(event_log):
    xes_log = xes_importer.apply(event_log)
    event_attribs = []
    for case_index, case in enumerate(xes_log):
        for event_index, event in enumerate(case):
            for key in event.keys():
                if key not in event_attribs:
                    event_attribs.append(key)
    return event_attribs
    pass


def getOutputFileList(directory):
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    output_path = os.path.join(temp_path, directory)

    if(not os.path.exists(output_path)):
        os.mkdir(output_path)

    return [f for f in os.listdir(output_path) if os.path.isfile(os.path.join(output_path, f))]
    pass


def handleXesLogDownloadButtonClick(request):
    if "output_list" not in request.POST:
        return HttpResponseRedirect(request.path_info)

    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")
    filename = request.POST["output_list"]
    file_dir = os.path.join(temp_path, "anonymization", filename)

    try:
        wrapper = FileWrapper(open(file_dir, 'rb'))
        response = HttpResponse(wrapper, content_type='application/force-download')
        response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_dir)
        return response
    except Exception as e:
        return None


def handleXesLogAddButtonClick(request):
    if "output_list" not in request.POST:
        return HttpResponseRedirect(request.path_info)

    filename = request.POST["output_list"]

    temp_path = os.path.join(settings.MEDIA_ROOT, "temp", "anonymization", filename)
    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs", filename)
    shutil.move(temp_path, event_logs_path)

    if temp_path == settings.ROLE_FILE:
        settings.ROLE_FILE = ""
        settings.ROLE_APPLIED = False

    outputs = getOutputFileList("anonymization")

    values = {}  # setValues(request)
    return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})


def handleXesLogDeleteButtonClick(request):
    if "output_list" not in request.POST:
        return HttpResponseRedirect(request.path_info)

    filename = request.POST["output_list"]
    temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

    file_dir = os.path.join(temp_path, "anonymization", filename)
    os.remove(file_dir)

    if file_dir == settings.ROLE_FILE:
        settings.ROLE_FILE = ""
        settings.ROLE_APPLIED = False

    outputs = getOutputFileList("anonymization")
    values = {}  # setValues(request)

    return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': values, 'outputs': outputs})
