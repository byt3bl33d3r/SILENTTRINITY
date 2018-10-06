import clr
clr.AddReference("System.Windows.Forms")
import System.Windows.Forms as WinForms

WinForms.MessageBox.Show(str("WINDOW_TEXT"), str("WINDOW_TITLE"))

print 'Popped'
