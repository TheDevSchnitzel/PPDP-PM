import shutil
import sys
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
    event_log = getXesLogPath()

    appState = extractStateFromHttpRequestValues(request)
    print(appState)

    if request.method == 'POST':
        #reqValues = extractHttpRequestValues(request)
        result = {'State': 'Empty'}

        if request.is_ajax():
            # Do something here
            if(len(appState['Operations']) > 0 and appState['Action'] == "Process"):
                handleAnonOps(appState)

            # Handle button calls incoming via ajax
            elif getRequestParameter(request.POST, 'outputHandleButton', None) == "addButton":
                return handleXesLogAddButtonClick(request)
            elif getRequestParameter(request.POST, 'outputHandleButton', None) == "deleteButton":
                return handleXesLogDeleteButtonClick(request)

            # Handling of output buttons
        elif 'downloadButton' in request.POST:
            return handleXesLogDownloadButtonClick(request)

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
            return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': getOutputFileList("anonymization"), 'appState': appState})


def getXesLogPath():
    if(settings.EVENT_LOG_NAME == ':notset:'):
        return settings.EVENT_LOG_NAME

    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    event_log = os.path.join(event_logs_path, settings.EVENT_LOG_NAME)
    return event_log


def extractStateFromHttpRequestValues(request):
    appState = json.loads(getRequestParameter(request.POST, 'appState', '{}'))

    if("Operations" not in appState.keys() or appState["Operations"] is None):
        appState["Operations"] = []

    if("AdditionEvents" not in appState.keys() or appState["AdditionEvents"] is None):
        appState["AdditionEvents"] = []

    if("Action" not in appState.keys() or appState["Action"] is None):
        appState["Action"] = "Nothing"

    if(("LogAttributes" not in appState.keys() or appState["LogAttributes"] is None) and getXesLogPath() != ':notset:'):
        xes_log = xes_importer.apply(getXesLogPath())

        appState["LogAttributes"] = {
            "Log": settings.EVENT_LOG_NAME,
            "CaseAttributes": getLogCaseAttributes(xes_log),
            "FirstEventUniqueAttributes": getLogFirstEventUniqueAttributes(xes_log),
            "EventAttributes": getLogEventAttributes(xes_log)
        }

    return appState


def getRequestParameter(requestData, parameter, default=None):
    if parameter in requestData:
        return requestData[parameter]
    else:
        return default


def handleAnonOps(appState):
    operations = appState["Operations"]
    log = xes_importer.apply(getXesLogPath())

    for op in operations:
        name = op["Operation"]
        level = op['Level']

        print(name + " - " + level)

        if(name == 'Addition'):
            a = Addition()
            additionEvents = appState['AdditionEvents']
            log = a.AddEvent(log)

        elif(name == 'Condensation'):
            c = Condensation()
            condenseOp = op['Condensation-Operation']
            condenseTarget = op['Condensation-Target']
            k = int(op['Condensation-kMeans-k'])

            if(condenseOp == 'kMeans'):
                log = c.CondenseEventAttributeBykMeanClusterMode(log, condenseTarget, k)

        elif(name == 'Cryptography'):
            c = Cryptography()
            cryptoOp = op['Cryptography-Operation']
            cryptTarget = op['Cryptography-Target']
            cryptMatchAttr = op['Cryptography-MatchAttr']
            cryptMatchVal = op['Cryptography-MatchVal']

            if(cryptoOp == "Hash"):
                if(level == "Case"):
                    log = c.HashCaseAttribute(log, cryptTarget, cryptMatchAttr, cryptMatchVal)
                elif(level == "Event"):
                    log = c.HashEventAttribute(log, cryptTarget, cryptMatchAttr, cryptMatchVal)
            elif(cryptoOp == "Encrypt"):
                if(level == "Case"):
                    log = c.EncryptCaseAttribute(log, cryptTarget, cryptMatchAttr, cryptMatchVal)
                elif(level == "Event"):
                    log = c.EncryptEventAttribute(log, cryptTarget, cryptMatchAttr, cryptMatchVal)

        elif(name == 'Generalization'):
            return Generalization()
        elif(name == 'Substitution'):
            s = Substitution()
            subTarget = op['Substitution-Target']
            subSensitiveVal = op['Substitution-SensitiveVal']
            log = s.SubstituteEventAttributeValue(log, subTarget, subSensitiveVal)

        elif(name == 'Supression'):
            return Supression()
        elif(name == 'Swapping'):
            s = Swapping()
            swapOp = op['Swapping-Operation']
            swapTarget = op['Swapping-Target']
            k = int(op['Swapping-kMeans-k'])

            if(swapOp == "kMeans"):
                if(level == "Case"):
                    log = s.SwapCaseAttributeValuesBykMeanCluster(log, swapTarget, k)
                elif(level == "Event"):
                    log = s.SwapEventAttributeValuesBykMeanCluster(log, swapTarget, k)

        # else:
            #raise NotImplementedError
        pass

    now = datetime.now()
    dateTime = now.strftime(" %m-%d-%y %H-%M-%S ")
    newName = "anon" + dateTime + settings.EVENT_LOG_NAME[:-3] + "xes"
    tmpPath = os.path.join(settings.MEDIA_ROOT, "temp")
    newFile = os.path.join(tmpPath, "anonymization", newName)
    xes_exporter.export_log(log, newFile)


def getLogCaseAttributes(xesLog):
    case_attribs = []
    for case_index, case in enumerate(xesLog):
        for key in case.attributes.keys():
            if key not in case_attribs:
                case_attribs.append(key)
    return sorted(case_attribs)
    pass


def getLogFirstEventUniqueAttributes(xesLog):
    uniqueAttr = []
    for cIndex, case in enumerate(xesLog):
        for eIndex, event in enumerate(case):
            if(eIndex == 0 and cIndex == 0):
                uniqueAttr = list(event.keys())
            elif(eIndex > 0):
                for key in event.keys():
                    if(key in uniqueAttr):
                        uniqueAttr.remove(key)

    return sorted(uniqueAttr)
    pass


def getLogEventAttributes(xesLog):
    event_attribs = []
    for case_index, case in enumerate(xesLog):
        for event_index, event in enumerate(case):
            for key in event.keys():
                if key not in event_attribs:
                    event_attribs.append(key)
    return sorted(event_attribs)
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
    filename = getRequestParameter(request.POST, 'selectedFile', None)
    if filename is not None:
        temp_path = os.path.join(settings.MEDIA_ROOT, "temp", "anonymization", filename)
        event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs", filename)
        shutil.move(temp_path, event_logs_path)

        if temp_path == settings.ROLE_FILE:
            settings.ROLE_FILE = ""
            settings.ROLE_APPLIED = False

    return HttpResponse(status=204)


def handleXesLogDeleteButtonClick(request):
    filename = getRequestParameter(request.POST, 'selectedFile', None)
    if filename is not None:
        temp_path = os.path.join(settings.MEDIA_ROOT, "temp")

        file_dir = os.path.join(temp_path, "anonymization", filename)
        os.remove(file_dir)

        if file_dir == settings.ROLE_FILE:
            settings.ROLE_FILE = ""
            settings.ROLE_APPLIED = False

    return HttpResponse(status=204)
