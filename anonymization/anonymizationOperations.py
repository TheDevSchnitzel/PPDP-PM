import abc
from pm4py.objects.log.importer.xes import factory as xes_importer_factory
from django.conf import settings

import hashlib

class AnonymizationOperationInterface(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'Process') and callable(subclass.Process))

    @abc.abstractmethod
    def Process(self, path: str, parameter):
        """Perform the anonymization operation on th xes log"""
        raise NotImplementedError

class Substitution_AO(AnonymizationOperationInterface):
    def __init__(self):
        #self.name = name
        pass

    def Process(self, xes_path: str, parameter) -> str:
        result = None
        return {'Operation': 'Substitution', 'Result': result}
        pass


class Condensation_AO(AnonymizationOperationInterface):
    def __init__(self):
        #self.name = name
        pass

    def Process(self, xes_path: str, parameter) -> str:
        result = None
        return {'Operation': 'Condensation', 'Result': result}
        pass


class Swapping_AO(AnonymizationOperationInterface):
    def __init__(self):
        #self.name = name
        pass

    def Process(self, xes_path: str, parameter) -> str:
        result = None
        return {'Operation': 'Swapping', 'Result': result}
        pass


class Generalization_AO(AnonymizationOperationInterface):
    def __init__(self):
        #self.name = name
        pass

    def Process(self, xes_path: str, parameter) -> str:
        result = None
        return {'Operation': 'Generalization', 'Result': result}
        pass

class Supression_AO(AnonymizationOperationInterface):
    """Replace a """

    def __init__(self):
        #self.name = name
        pass

    def Process(self, xes_path: str, parameter) -> str:
        xes_log = xes_importer_factory.apply(xes_path)
        no_traces = len(xes_log)
        no_events = sum([len(trace) for trace in xes_log])
        result = None

        if (parameter['OP_Level'] == 'event' and parameter['OP_Target'] == 'event'):
            #Event based supression: If an event has a certain activity value it is removed from the trace
            for case_index, case in enumerate(xes_log):
                for event_index, event in enumerate(case):
                    result = {'Event': event}
                    #for key in event.keys():
                    #    if key not in event_attribs:
                    #        event_attribs.append(key)

        elif (parameter['OP_Level'] == 'case' and parameter['OP_Target'] == 'case'):
            result = None
        elif (parameter['OP_Level'] == 'event' and parameter['OP_Target'] == 'resource'):
            result = None
        else:
            raise NotImplementedError
        return {'Operation': 'Supression', 'Result': result}
        pass


class Addition_AO(AnonymizationOperationInterface):
    """Extract text from a PDF."""

    def __init__(self):
        #self.name = name
        pass

    def Process(self, xes_path: str, parameter) -> str:
        xes_log = xes_importer_factory.apply(xes_path)
        no_traces = len(xes_log)
        no_events = sum([len(trace) for trace in xes_log])

        result = self.get_attributes(xes_log)



#    log[0] refers to the first trace in the log
#        log[0][0] refers to the first event of the first trace in the log
#            log[0][1] refers to the second event of the first trace in the log
#    log[1] refers to the second trace in the log
#        log[1][0] refers to the first event of the second case in the log
#        log[1][1] refers to the second event of the second case in the log


        return {'Operation': 'Addition', 'Result': result}
        pass

    def get_attributes(self, xes_log):
        sensitives = []
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

        sensitives = case_attribs + event_attribs
        sensitives.sort()
        # sensitives = case_attribs
        print("in function")
        print(sensitives)
        return sensitives


class Cryptography_AO(AnonymizationOperationInterface):
    """Extract text from a PDF."""

    def __init__(self):
        #self.name = name
        # d = list(hashlib.algorithms_guaranteed)
        # d.sort()
        pass

    def Process(self, xes_path: str, parameter) -> str:
        xes_log = xes_importer_factory.apply(xes_path)
        no_traces = len(xes_log)
        no_events = sum([len(trace) for trace in xes_log])

        h = hashlib.new('ripemd160')
        h.update(b"Nobody inspects the spammish repetition")
        h.hexdigest()

        result = h

        return {'Operation': 'Cryptography', 'Result': result}
        pass
