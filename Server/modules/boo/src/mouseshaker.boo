import System
from System import Random
from System.Windows.Forms import Cursor
from System.Drawing import Point

r = Random()
offset = OFFSET
output = "Shaked and Baked"

for i in range(1000):
    currentX = Cursor.Position.X
    currentY = Cursor.Position.Y
    x = r.Next(currentX - offset, currentX + offset + 1)
    y = r.Next(currentY - offset, currentY + offset + 1)
    Cursor.Position = Point(x, y)
    System.Threading.Thread.Sleep(10)
