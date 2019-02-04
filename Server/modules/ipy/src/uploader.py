from System import Convert
from System.IO import File


def DecodeBase64File(Data, FileName, FilePath="C:\\WINDOWS\\Temp\\"):
    path = "{}{}".format(FilePath, FileName)
    File.WriteAllBytes(path,Convert.FromBase64String(Data))
    return 'File copied to: {}'.format(path)

print DecodeBase64File("DATA", "FILENAME", FilePath="DESTINATION")