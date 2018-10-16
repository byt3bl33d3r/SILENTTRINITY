import clr
import System.Net.WebClient as WebClient
import System.Convert
import System.Text.Encoding.Unicode as Unicode
clr.AddRefference("System.Web.Extensions")
import System.Web.Script.Serialization as json
def web_get(url,token):
    client = WebClient()
    client.Headers.Add("Authorization",token)
    return client.DownloadString(url)

def web_put(url,data,token):
    client = WebClient()
    client.Headers.Add("Authorization",token)
    return client.UploadString(url,"PUT",data)

def web_post(url,data,token):
    client = WebClient()
    client.Headers.Add("Authorization",token)
    return client.UploadString(url,data)

def github_upload(user,token,repo,repo_path,repo_file,local_file):
    ghapi_url = "https://api.github.com/repos/" + user + "/" + repo + "/contents/" + repo_path + repo_file
    a = open(local_file, 'r')
    data = {
            "path":repo_file,
            "content": System.Convert.ToBase64String(Unicode.GetBytes(a.read())),
            "encodeing": "base64",
            "Message": "Commit-made"
    
    }
    json_serial = json.JavaScriptSerializer()
    json_data = json_serial.Serialize(data)
    result = web_put(ghapi_url,json_data)


github_upload(GITHUBUSER,GITHUBTOKEN,GITHUBREPO,REPOPATH,REPOFILE,LOCALFILE)



