import clr
import System.Net.WebClient as WebClient
import System.Convert
import System.Text.Encoding as Encoding
import System.Net.Security
import System.Net
clr.AddReference('System.Web.Extensions')
import System.Web.Script.Serialization as json

def web_put(url,data,token):
    print 'Web put'
    System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12
    client = WebClient()
    client.Headers.Add('User-Agent','Iron Python')
    client.Headers.Add('Authorization','Basic ' + token)
    return client.UploadString(url,'PUT',data)


def github_upload(user,PAT,repo,repo_path,repo_file,local_file):
    ghapi_url = 'https://api.github.com/repos/' + user + '/' + repo + '/contents/' + repo_path + repo_file
    a = open(local_file,'r')
    token_gen = user + ':' + PAT
    token = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(token_gen))
    data = {
            'content': System.Convert.ToBase64String(Encoding.UTF8.GetBytes(a.read())),
            'encodeing': 'base64',
            'message': 'Commit-made'
    
    }
    json_serial = json.JavaScriptSerializer()
    json_data = json_serial.Serialize(data)
    print json_data
    result = web_put(ghapi_url,json_data,token)
    print 'File uploaded'


github_upload('GHUSER','GH_PAT','GHREPO','GHPATH','GHFILE','LOCALFILE')



