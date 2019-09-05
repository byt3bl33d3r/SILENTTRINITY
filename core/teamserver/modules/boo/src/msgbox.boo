import System.Windows.Forms as WinForms

public static def Start(job as duck, client as duck):
    print client.Guid
    WinForms.MessageBox.Show("WINDOW_TEXT", "WINDOW_TITLE")
    print 'Popped'
