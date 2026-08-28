@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /O2 /GS- main.cpp /link /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:__dummy_entry /DYNAMICBASE:NO /BASE:0x1E2F000000 /INCREMENTAL:NO kernel32.lib
if %errorlevel% neq 0 (
    echo Compilation failed!
    exit /b %errorlevel%
)
python crypt.py
