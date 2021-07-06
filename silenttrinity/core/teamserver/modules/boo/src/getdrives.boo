import System
import System.IO

public static def Main():
    allDrives as (DriveInfo) = DriveInfo.GetDrives()
    for d as DriveInfo in allDrives:
        print d.Name
        print '  Type: ' + d.DriveType
        if d.IsReady == true:
            print '  Volume label: '+ d.VolumeLabel
            print '  File system: '+ d.DriveFormat
            print '  Total available space:    '+ d.AvailableFreeSpace +' bytes'
            print '  Total free space:         '+ d.TotalFreeSpace +' bytes'
            print '  Total size of drive:      '+ d.TotalSize +' bytes'