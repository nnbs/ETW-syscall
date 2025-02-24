@echo off
rem check ETW-Syscall.exe exist
if not exist ETW-Syscall.exe (
    echo "ETW-Syscall.exe not exist, please copy it to current folder"
    goto :eof
)

echo "Collecting ETW data..."
ETW-Syscall.exe

echo "Get syscall information..."
python getImageFunctionWithSymbols.py c:\Windows\System32\ntoskrnl.exe
python getImageFunctionWithSymbols.py c:\Windows\System32\win32k.sys

echo "Get driver base address..."
python GetDriverBaseaddress.py

echo "Remap syscall information..."
python mapSyscall.py

echo "syscall by process log on ProcessCallAPI.name.log"
echo "syscall by all process count on 'syscall.log'"
