' Internal helper — Start.bat runs this so no black console window ever
' appears. You do not need to touch this file; double-click Start.bat.
Option Explicit

Dim fso, sh, root, py, localPy, btn, rc
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

localPy = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\STIG Checker\runtime\python.exe"

If OnPath("py") Then
  py = "py"
ElseIf OnPath("pythonw") Then
  py = "pythonw"
ElseIf OnPath("python") Then
  py = "python"
ElseIf fso.FileExists(localPy) Then
  py = """" & localPy & """"
Else
  btn = MsgBox("This PC does not have Python." & vbCrLf & vbCrLf & _
               "STIG Checker can download a private copy of Python 3.12 from python.org " & _
               "(~11 MB). It is not installed system-wide, is not added to PATH, and " & _
               "needs no administrator rights." & vbCrLf & vbCrLf & _
               "Download it now?", vbQuestion + vbYesNo, "STIG Checker")
  If btn <> vbYes Then WScript.Quit 1
  rc = sh.Run("powershell -NoProfile -ExecutionPolicy Bypass -File """ & _
              root & "\scripts\ensure-python.ps1""", 1, True)
  If rc <> 0 Or Not fso.FileExists(localPy) Then
    MsgBox "Could not download Python. Check the network, then try again.", _
           vbCritical, "STIG Checker"
    WScript.Quit 1
  End If
  py = """" & localPy & """"
End If

sh.Environment("Process")("PYTHONPATH") = root
sh.Run py & " -m stigui --app", 0, False
