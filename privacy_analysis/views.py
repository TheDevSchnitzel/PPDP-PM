import shutil
import sys
from django.shortcuts import render
from django.conf import settings
import os
from os import listdir, path
from os.path import isfile, join
from datetime import datetime
from django.http import HttpResponseRedirect, HttpResponse
from wsgiref.util import FileWrapper
import json
import time
import traceback
from django.core.files.storage import FileSystemStorage

from pm4py.objects.log.importer.xes import factory as xes_importer
from pm4py.objects.log.exporter.xes import factory as xes_exporter
from p_privacy_qt.SMS import SMS
from p_privacy_qt.EMD import EMD


def privacy_analysis_main(request):
    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")

    event_log = getXesLogPath(settings.EVENT_LOG_NAME)
    event_log_backup = getXesLogPath(settings.BACKUP_EVENT_LOG_NAME)

    eventlogs = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]

    returnObject = {'eventlog_list': eventlogs, 'disclosureRiskActive': "active"}

    if request.method == 'POST':
        if("actionDataUtility" in request.POST):
            returnObject['dataUtilityActive'] = "active"
            returnObject['disclosureRiskActive'] = ""

        if request.is_ajax():
            return render(request, 'privacy_analysis.html', returnObject)
        else:
            if "uploadButton" in request.POST:
                if "event_log" not in request.FILES:
                    return HttpResponseRedirect(request.path_info)

                log = request.FILES["event_log"]
                fs = FileSystemStorage(event_logs_path)
                filename = fs.save(log.name, log)
                uploaded_file_url = fs.url(filename)

                returnObject['eventlog_list'] = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]

                return render(request, 'privacy_analysis.html', returnObject)

            elif "deleteButton" in request.POST:  # for event logs
                if "log_list" not in request.POST:
                    return HttpResponseRedirect(request.path_info)

                filename = request.POST["log_list"]
                if settings.EVENT_LOG_NAME == filename:
                    settings.EVENT_LOG_NAME = ":notset:"

                eventlogs = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]

                eventlogs.remove(filename)
                file_dir = os.path.join(event_logs_path, filename)
                os.remove(file_dir)

                returnObject['eventlog_list'] = eventlogs

                return render(request, 'privacy_analysis.html', returnObject)

            elif "setButton" in request.POST or "setButtonBackup" in request.POST:
                if "log_list" not in request.POST:
                    return HttpResponseRedirect(request.path_info)

                filename = request.POST["log_list"]

                if "setButton" in request.POST:
                    settings.EVENT_LOG_NAME = filename
                elif "setButtonBackup" in request.POST:
                    settings.BACKUP_EVENT_LOG_NAME = filename

                returnObject['eventlog_list'] = [f for f in listdir(event_logs_path) if isfile(join(event_logs_path, f))]
                returnObject['log_name'] = settings.EVENT_LOG_NAME
                returnObject['log_name_backup'] = settings.BACKUP_EVENT_LOG_NAME
                return render(request, 'privacy_analysis.html', returnObject)

            elif "downloadButton" in request.POST:  # for event logs
                if "log_list" not in request.POST:
                    return HttpResponseRedirect(request.path_info)

                filename = request.POST["log_list"]
                file_dir = os.path.join(event_logs_path, filename)

                try:
                    wrapper = FileWrapper(open(file_dir, 'rb'))
                    response = HttpResponse(wrapper, content_type='application/force-download')
                    response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_dir)
                    return response
                except Exception as e:
                    return None
            else:
                return render(request, 'privacy_analysis.html', returnObject)
    else:
        if request.is_ajax():
            if(request.GET['analysis'] == 'dataUtility'):
                # Total data utility
                utility = getDataUtilityValue(xes_importer.apply(event_log), xes_importer.apply(event_log_backup))
                return HttpResponse(json.dumps({"Utility": utility}), content_type='application/json')

            elif(request.GET['analysis'] == 'disclosureRisk'):
                rv_bkLength, rv_cd, rv_td = getRiskValue(xes_importer.apply(event_log))
                return HttpResponse(json.dumps({"Risk": {"bkLength": rv_bkLength, "cd": rv_cd, "td": rv_td}}), content_type='application/json')

        return render(request, 'privacy_analysis.html', returnObject)


def getXesLogPath(logName):
    if(logName == ':notset:'):
        return None

    event_logs_path = os.path.join(settings.MEDIA_ROOT, "event_logs")
    event_log = os.path.join(event_logs_path, logName)
    return event_log


def getDataUtilityValue(original_log, privacy_log):
    sys.stdout = open(os.devnull, 'w')

    sensitive = []
    time_accuracy = "minutes"
    time_info = False
    trace_attributes = ['concept:name', 'org:resource', 'time:timestamp']
    # these life cycles are applied only when all_lif_cycle = False
    life_cycle = ['complete', '', 'COMPLETE']
    # when life cycle is in trace attributes then all_life_cycle has to be True
    all_life_cycle = True  # True will ignore the transitions specified in life_cycle

    sms = SMS()
    logsimple, traces, sensitives = sms.create_simple_log_adv(original_log, trace_attributes, life_cycle, all_life_cycle, sensitive, time_info, time_accuracy)
    logsimple_2, traces_2, sensitives_2 = sms.create_simple_log_adv(privacy_log, trace_attributes, life_cycle, all_life_cycle, sensitive, time_info, time_accuracy)

    # log 1 convert to char
    map_dict_act_chr, map_dict_chr_act = sms.map_act_char(traces)
    simple_log_char_1 = sms.convert_simple_log_act_to_char(traces, map_dict_act_chr)

    # log 2 convert to char
    # map_dict_act_chr_2,map_dict_chr_act_2 = sms.map_act_char(traces_2)
    simple_log_char_2 = sms.convert_simple_log_act_to_char(traces_2, map_dict_act_chr)

    start_time = time.time()

    my_emd = EMD()
    # log_freq_1, log_only_freq_1 = my_emd.log_freq(traces)
    # log_freq_2 , log_only_freq_2 = my_emd.log_freq(traces_2)

    log_freq_1, log_only_freq_1 = my_emd.log_freq(simple_log_char_1)
    log_freq_2, log_only_freq_2 = my_emd.log_freq(simple_log_char_2)

    cost_lp = my_emd.emd_distance_pyemd(log_only_freq_1, log_only_freq_2, log_freq_1, log_freq_2)
    # cost_lp = my_emd.emd_distance(log_freq_1,log_freq_2)

    data_utility = 1 - cost_lp

    sys.stdout = sys.__stdout__
    return data_utility


def getRiskValue(log):
    existence_based = True  # it is faster when there is no super long traces in the event log
    measurement_type = "average"  # average or worst_case
    sensitive = []
    time_accuracy = "minutes"
    time_info = False
    trace_attributes = ['concept:name']
    # these life cycles are applied only when all_lif_cycle = False
    life_cycle = ['complete', '', 'COMPLETE']
    # when life cycle is in trace attributes then all_life_cycle has to be True
    all_life_cycle = True

    bk_type = 'set'  # set,mult,seq
    bk_length = 2  # int

    sms = SMS()
    # simple_log = sms.create_simple_log(log,["concept:name", "lifecycle:transition"])
    logsimple, traces, sensitives = sms.create_simple_log_adv(log, trace_attributes, life_cycle, all_life_cycle, sensitive, time_info, time_accuracy)

    map_dict_act_chr, map_dict_chr_act = sms.map_act_char(traces)
    simple_log_char_1 = sms.convert_simple_log_act_to_char(traces, map_dict_act_chr)

    sms.set_simple_log(simple_log_char_1)

    multiset_log = sms.get_multiset_log_n(simple_log_char_1)

    # multiset_log1 = sms.get_multiset_log(simple_log)

    uniq_act = sms.get_unique_elem(simple_log_char_1)

    start_time = time.time()
    results_file_name = "testName.csv"

    # min_len = min(len(uniq_act),3)

    cd, td = sms.disclosure_calc(bk_type, uniq_act, measurement_type, results_file_name, bk_length, existence_based, simple_log_char_1, multiset_log)

    return bk_length, cd, td
