from System.Net import WebClient

def download_url(url, destination, filename):
    WebClient().DownloadFile(url, destination + '\\' + filename)
    return 'File downloaded'

print download_url("URL", "DESTINATION", "FILENAME")
