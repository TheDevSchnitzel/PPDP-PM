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
import time
import traceback

from ppdp_anonops import *
from ppdp_anonops.utils import *


from pm4py.objects.log.importer.xes import factory as xes_importer
from pm4py.objects.log.exporter.xes import factory as xes_exporter


def anonymization_main(request):
    event_log = getXesLogPath()

    appState = extractStateFromHttpRequestValues(request)
    print(appState)

    if request.method == 'POST':
        # reqValues = extractHttpRequestValues(request)
        result = {'State': 'Empty'}

        if request.is_ajax():
            # Do something here
            if(len(appState['Operations']) > 0 and appState['Action'] == "Process"):
                try:
                    return handleAnonOps(appState)
                except:
                    return HttpResponse(json.dumps({'error': str(traceback.format_exc())}), content_type='application/json', status=500)

            # Handle button calls incoming via ajax
            elif getRequestParameter(request.POST, 'outputHandleButton', None) == "addButton":
                return handleXesLogAddButtonClick(request)
            elif getRequestParameter(request.POST, 'outputHandleButton', None) == "deleteButton":
                return handleXesLogDeleteButtonClick(request)

            # Handle further ajax posts
            elif 'SaveTaxonomyTree' == getRequestParameter(request.POST, 'action', None):
                treeName = getRequestParameter(request.POST, 'treeName', None)
                treeID = getRequestParameter(request.POST, 'treeID', None)
                treeData = getRequestParameter(request.POST, 'treeData', None)
                return saveTaxonomyTree(treeID, treeName, treeData)
            elif 'DeleteTaxonomyTree' == getRequestParameter(request.POST, 'action', None):
                treeName = getRequestParameter(request.POST, 'treeName', None)
                treeID = getRequestParameter(request.POST, 'treeID', None)
                return deleteTaxonomyTree(treeID, treeName)

            # Handling of output buttons
        elif 'downloadButton' in request.POST:
            return handleXesLogDownloadButtonClick(request)

        return render(request, 'anonymization_main.html', {'log_name': settings.EVENT_LOG_NAME, 'values': '', 'outputs': getOutputFileList("anonymization"), 'result': result, 'appState': json.dumps(appState)})

    else:
        if request.is_ajax():
            action = getRequestParameter(request.GET, 'action')

            if 'GetTaxonomyTreeList' == action:
                json_respone = {'taxTrees': getTaxonomyTrees("anonymization")}
                return HttpResponse(json.dumps(json_respone), content_type='application/json')
            elif 'GetTaxonomyTree' == action:
                id = getRequestParameter(request.GET, 'treeID')
                json_respone = {'taxTree': getTaxonomyTree("anonymization", id)}
                return HttpResponse(json.dumps(json_respone), content_type='application/json')

            return HttpResponse(status=204)
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

    start_time = time.time()
    log = xes_importer.apply(getXesLogPath())
    print("IMPORTING TOOK: --- %s seconds ---" % (time.time() - start_time))

    # Statistic data
    origNoTraces = len(log)
    origNoEvents = sum([len(trace) for trace in log])

    for op in operations:
        start_time = time.time()
        name = op["Operation"]
        level = op['Level']

        if(name == 'Addition'):
            a = Addition()
            additionEvents = {e['Id']: e for e in appState['AdditionEvents']}

            additionOp = op['Addition-Operation']
            isConditionalActive = op['Addition-ConditionalActive']
            additionConditionalAttr = op['Addition-ConditionalAttr'] if isConditionalActive else None
            additionConditionalVal = op['Addition-ConditionalVal'] if isConditionalActive else None
            additionMatchOp = op['Addition-MatchOp'] if isConditionalActive else None

            # Select Match Mode (Trace, Attribute, Value => MATCH-PATTERN)
            if(additionMatchOp == "matchCase"):
                additionMatchOp = (lambda t, a, v: a in t.attributes.keys() and t.attributes[a] == v)
            elif(additionMatchOp == "matchFirstEvent"):
                additionMatchOp = (lambda t, a, v: len(t) > 0 and a in t[0].keys() and t[0][a] == v)
            elif(additionMatchOp == "matchLastEvent"):
                additionMatchOp = (lambda t, a, v: len(t) > 0 and a in t[-1].keys() and t[-1][a] == v)
            elif(additionMatchOp == "matchAnyEvent"):
                additionMatchOp = (lambda t, a, v: len(t) > 0 and len([x for x in t if a in x.keys() and x[a] == v]) > 0)
            elif(additionMatchOp == "matchAllEvent"):
                additionMatchOp = (lambda t, a, v: len(t) > 0 and len([x for x in t if a in x.keys() and x[a] == v]) == len(t))
            else:
                additionMatchOp = None

            for event in additionEvents:
                eventTemplate = additionEvents[event]['Attributes']

                if(additionOp == 'Add new event as first in trace'):
                    log = a.AddEventFirstInTrace(log, eventTemplate, additionConditionalAttr, additionConditionalVal, additionMatchOp)
                elif(additionOp == 'Add new event as last in trace'):
                    log = a.AddEventLastInTrace(log, eventTemplate, additionConditionalAttr, additionConditionalVal, additionMatchOp)
                elif(additionOp == 'Add new event at random position'):
                    log = a.AddEventAtRandomPlaceInTrace(log, eventTemplate, additionConditionalAttr, additionConditionalVal, additionMatchOp)

        elif(name == 'Condensation'):
            c = Condensation()
            condenseOp = op['Condensation-Operation']
            condenseTarget = op['Condensation-Target']
            descriptiveAttributes = op['Condensation-DescriptiveAttributes']
            weights = op['Condensation-AttributeWeights']
            k = int(op['Condensation-kClusters'])

            if(level == "Event"):
                if(condenseOp == 'kMeans'):
                    log = c.CondenseEventAttributeBykMeanClusterMode(log, condenseTarget, k)
                elif(condenseOp == 'kModes'):
                    log = c.CondenseEventAttributeBykModeCluster(log, condenseTarget, descriptiveAttributes, k)
                elif(condenseOp == 'Euclidian Distance'):
                    log = c.CondenseEventAttributeByEuclidianDistance(log, condenseTarget, descriptiveAttributes, weights, k)
            elif(level == "Case"):
                if(condenseOp == 'kMeans'):
                    log = c.CondenseCaseAttributeBykMeanClusterMode(log, condenseTarget, k)
                elif(condenseOp == 'kModes'):
                    log = c.CondenseCaseAttributeBykModeCluster(log, condenseTarget, descriptiveAttributes, k)
                elif(condenseOp == 'Euclidian Distance'):
                    log = c.CondenseCaseAttributeByEuclidianDistance(log, condenseTarget, descriptiveAttributes, weights, k)

        elif(name == 'Cryptography'):
            c = Cryptography()
            cryptoOp = op['Cryptography-Operation']
            cryptTarget = op['Cryptography-Target']
            cryptConditionalAttr = op['Cryptography-ConditionalAttr']
            cryptConditionalVal = op['Cryptography-ConditionalVal']

            if(cryptoOp == "Hash"):
                if(level == "Case"):
                    log = c.HashCaseAttribute(log, cryptTarget, cryptConditionalAttr, cryptConditionalVal)
                elif(level == "Event"):
                    log = c.HashEventAttribute(log, cryptTarget, cryptConditionalAttr, cryptConditionalVal)
            elif(cryptoOp == "Encrypt"):
                if(level == "Case"):
                    log = c.EncryptCaseAttribute(log, cryptTarget, cryptConditionalAttr, cryptConditionalVal)
                elif(level == "Event"):
                    log = c.EncryptEventAttribute(log, cryptTarget, cryptConditionalAttr, cryptConditionalVal)

        elif(name == 'Generalization'):
            g = Generalization()

            tree = TaxonomyTree.CreateFromJSON(getTaxonomyTree("anonymization", op['Generalization-TaxTreeSelectionId']), "text", "children")
            generalizationTarget = op['Generalization-Target']
            generalizationDepth = op['Generalization-Depth']

            generalizationOperation = op['Generalization-Operation']
            generalizationTimeDepth = op['Generalization-TimeDepth']

            if(generalizationOperation == "GenTaxonomyTree"):
                if(level == "Case"):
                    log = g.GeneralizeCaseAttributeByTaxonomyTreeDepth(log, generalizationTarget, tree, generalizationDepth)
                elif(level == "Event"):
                    log = g.GeneralizeEventAttributeByTaxonomyTreeDepth(log, generalizationTarget, tree, generalizationDepth)
            elif(generalizationOperation == "GenTimestamp"):
                if(level == "Case"):
                    log = g.GeneralizeCaseTimeAttribute(log, "time:timestamp", generalizationTimeDepth)
                elif(level == "Event"):
                    log = g.GeneralizeEventTimeAttribute(log, "time:timestamp", generalizationTimeDepth)

        elif(name == 'Substitution'):
            s = Substitution()
            subTarget = op['Substitution-Target']
            subSensitiveVal = op['Substitution-SensitiveVal']
            log = s.SubstituteEventAttributeValue(log, subTarget, subSensitiveVal)

        elif(name == 'Suppression'):
            s = Suppression()
            suppressionOP = op['Suppression-Operation']
            isConditionalActive = op['Suppression-ConditionalActive']
            suppressionConditionalAttr = op['Suppression-ConditionalAttr'] if isConditionalActive else None
            suppressionConditionalVal = op['Suppression-ConditionalVal'] if isConditionalActive else None
            suppressionTarget = op['Suppression-Target']
            suppressionTraceLength = int((op['Suppression-TraceLength'] if op['Suppression-TraceLength'] not in ['', None, ' '] else 0))

            if(suppressionOP == "SuppressCaseByTraceLength"):
                log = s.SuppressCaseByTraceLength(log, suppressionTraceLength)
            else:
                if(level == "Event"):
                    if(suppressionOP == "Suppress"):
                        log = s.SuppressEvent(log, suppressionConditionalAttr, suppressionConditionalVal)
                    elif(suppressionOP == "SuppressAttribute"):
                        log = s.SuppressEventAttribute(log, suppressionTarget, suppressionConditionalAttr, suppressionConditionalVal)
                elif(level == "Case"):
                    if(suppressionOP == "Suppress"):
                        log = s.SuppressCase(log, suppressionConditionalAttr, suppressionConditionalVal)
                    elif(suppressionOP == "SuppressAttribute"):
                        log = s.SuppressCaseAttribute(log, suppressionTarget, suppressionConditionalAttr, suppressionConditionalVal)

        elif(name == 'Swapping'):
            s = Swapping()
            swapOp = op['Swapping-Operation']
            swapTarget = op['Swapping-Target']
            k = int(op['Swapping-kClusters'])

            if(swapOp == "kMeans"):
                if(level == "Case"):
                    log = s.SwapCaseAttributeValuesBykMeanCluster(log, swapTarget, k)
                elif(level == "Event"):
                    log = s.SwapEventAttributeValuesBykMeanCluster(log, swapTarget, k)

        # else:
            # raise NotImplementedError

        print(name[0:3].upper() + " - " + level[0:1].upper() + " TOOK: --- %s seconds ---" % (time.time() - start_time))

    # Statistics
    print("Diff. No. of traces %0f" % (len(log) - origNoTraces))
    print("Diff. No. of events %0f" % (sum([len(trace) for trace in log]) - origNoEvents))

    newName = exportLog(log)

    return HttpResponse(json.dumps({'log': newName}), content_type='application/json')


def getLogCaseAttributes(xesLog):
    case_attribs = []
    for case_index, case in enumerate(xesLog):
        for key in case.attributes.keys():
            if key not in case_attribs and not key.startswith("@"):
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
                if key not in event_attribs and not key.startswith("@"):
                    event_attribs.append(key)
    return sorted(event_attribs)
    pass


def getOutputFileList(directory):
    return getFileList(os.path.join(settings.MEDIA_ROOT, "temp"), directory)


def getTaxonomyTrees(directory):
    return getFileList(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), directory)


def getTaxonomyTree(directory, id):
    files = getFileList(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), directory)
    for name in files:
        if name.startswith(id):
            filePath = os.path.join(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), directory, name)
            f = open(filePath, "r")
            data = f.read()
            f.close()
            return data
    return None


def getFileList(path, directory):
    output_path = os.path.join(path, directory)

    if(not os.path.exists(output_path)):
        os.mkdir(output_path)

    return [f for f in os.listdir(output_path) if os.path.isfile(os.path.join(output_path, f))]


def saveTaxonomyTree(treeID, treeName, treeData):
    filePath = os.path.join(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), "anonymization", treeID + " - " + treeName + ".json")

    os.makedirs(os.path.dirname(filePath), exist_ok=True)

    f = open(filePath, "w")
    f.write(treeData)
    f.close()
    return HttpResponse(status=204)


def deleteTaxonomyTree(treeID, treeName):
    filePath = os.path.join(os.path.join(settings.MEDIA_ROOT, "none_event_logs", "taxonomyTrees"), "anonymization", treeID + " - " + treeName + ".json")
    os.remove(filePath)
    return HttpResponse(status=204)


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


def exportLog(log):
    now = datetime.now()
    dateTime = now.strftime(" %m-%d-%y %H-%M-%S ")
    newName = "anon" + dateTime + settings.EVENT_LOG_NAME[:-3] + "xes"
    tmpPath = os.path.join(settings.MEDIA_ROOT, "temp")
    newFile = os.path.join(tmpPath, "anonymization", newName)

    start_time = time.time()
    xes_exporter.export_log(log, newFile)
    print("EXPORTING TOOK: --- %s seconds ---" % (time.time() - start_time))
    return newName
