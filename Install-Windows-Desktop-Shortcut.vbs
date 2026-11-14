Set oWS = WScript.CreateObject("WScript.Shell")
Set oFSO = CreateObject("Scripting.FileSystemObject")
sAppDir = oFSO.GetParentFolderName(WScript.ScriptFullName)

' 1. Create Desktop Shortcut
sDesktop = oWS.SpecialFolders("Desktop")
sDesktopLink = sDesktop & "\ThreatPath AI.lnk"
Set oLink = oWS.CreateShortcut(sDesktopLink)
oLink.TargetPath = sAppDir & "\Launch-ThreatPath-Windows.bat"
oLink.WorkingDirectory = sAppDir
oLink.WindowStyle = 7
oLink.Description = "Launch ThreatPath AI Defensive Cybersecurity Platform"
oLink.IconLocation = "shell32.dll,47"
oLink.Save

' 2. Create Start Menu Programs Shortcut
sStartMenu = oWS.SpecialFolders("Programs")
sStartLink = sStartMenu & "\ThreatPath AI.lnk"
Set oStartLink = oWS.CreateShortcut(sStartLink)
oStartLink.TargetPath = sAppDir & "\Launch-ThreatPath-Windows.bat"
oStartLink.WorkingDirectory = sAppDir
oStartLink.WindowStyle = 7
oStartLink.Description = "Launch ThreatPath AI Defensive Cybersecurity Platform"
oStartLink.IconLocation = "shell32.dll,47"
oStartLink.Save

WScript.Echo "[OK] Created 'ThreatPath AI' icon on Windows Desktop and Start Menu!"
