import System
import System.Threading
import System.Windows.Forms
import System.Drawing

public static def Main():
    r = Random()
    offset = OFFSET

    for i in range(1000):
        currentX = Cursor.Position.X
        currentY = Cursor.Position.Y
        x = r.Next(currentX - offset, currentX + offset + 1)
        y = r.Next(currentY - offset, currentY + offset + 1)
        Cursor.Position = Point(x, y)
        Thread.Sleep(10)

    print "Shaked and Baked"
