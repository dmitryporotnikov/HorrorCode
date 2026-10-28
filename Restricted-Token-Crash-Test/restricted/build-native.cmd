@echo off
setlocal
where cl >nul 2>&1
if errorlevel 1 (
    echo Run this script from an x64 Native Tools Command Prompt for Visual Studio.
    exit /b 1
)
cd /d "%~dp0"
cl /nologo /c /O1 /GS- /Zl /W4 native-crasher.c /Fonative-crasher.obj
if errorlevel 1 exit /b 1
link /nologo native-crasher.obj kernel32.lib /NODEFAULTLIB /ENTRY:crash_entry /SUBSYSTEM:WINDOWS /MACHINE:X64 /DYNAMICBASE /NXCOMPAT /OUT:wer-native-crasher.exe
exit /b %errorlevel%
