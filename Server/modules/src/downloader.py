from System import Convert
from System.IO import File


def EncodeFileBase64(FilePath):
    return Convert.ToBase64String( File.ReadAllBytes(FilePath))

print EncodeFileBase64(FilePath="FILE_PATH")