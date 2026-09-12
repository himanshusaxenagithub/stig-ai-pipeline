' Internal helper — Start.bat runs this so no black console window ever
' appears. You do not need to touch this file; double-click Start.bat.
Option Explicit

Dim fso, sh, root
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")

root = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = root

If Not fso.FolderExists(fso.BuildPath(root, "stigui")) Then
  MsgBox "STIG Checker could not find the project files." & vbCrLf & vbCrLf & _
         "Keep Start.bat inside the unzipped folder, next to stigui.", _
         vbCritical, "STIG Checker"
  WScript.Quit 1
End If

Function OnPath(name)
  OnPath = (sh.Run("cmd /c where " & name & " >nul 2>nul", 0, True) = 0)
End Function

Dim py
If OnPath("py") Then
  py = "py"
ElseIf OnPath("pythonw") Then
  py = "pythonw"
ElseIf OnPath("python") Then
  py = "python"
Else
  Dim btn
  btn = MsgBox("STIG Checker needs Python 3.9 or newer, once." & vbCrLf & vbCrLf & _
               "1. Open https://www.python.org/downloads/" & vbCrLf & _
               "2. Run the installer and tick ""Add python.exe to PATH""." & vbCrLf & _
               "3. Close this box and double-click Start.bat again.", _
               vbExclamation + vbYesNo, "STIG Checker")
  If btn = vbYes Then sh.Run "https://www.python.org/downloads/"
  WScript.Quit 1
End If

' Window style 0 = hidden. False = do not wait; this script exits and the
' page stays open in the browser, run by the server in the background.
sh.Run py & " -m stigui --app", 0, False
