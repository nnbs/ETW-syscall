import ctypes
import os
import argparse

# 定義符號信息結構 SYMBOL_INFO
MAX_SYM_NAME = 2000
class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", ctypes.c_ulong),
        ("TypeIndex", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", ctypes.c_ulong),
        ("Size", ctypes.c_ulong),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", ctypes.c_ulong),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", ctypes.c_ulong),
        ("Scope", ctypes.c_ulong),
        ("Tag", ctypes.c_ulong),
        ("NameLen", ctypes.c_ulong),
        ("MaxNameLen", ctypes.c_ulong),
        ("Name", ctypes.c_wchar * MAX_SYM_NAME),  # 符號名稱
    ]


# 加載 DbgHelp.dll
# 加載新版 DbgHelp.dll（如果有新版）
dbghelp_path = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll"
if os.path.exists(dbghelp_path):
    dbghelp = ctypes.WinDLL(dbghelp_path)
elif os.path.exists(f"{os.path.dirname(os.path.abspath(__file__))}\\dbghelp.dll"):
    dbghelp = ctypes.WinDLL(f"{os.path.dirname(os.path.abspath(__file__))}\\dbghelp.dll")
else:
    dbghelp = ctypes.WinDLL("DbgHelp.dll")

kernel32 = ctypes.WinDLL("Kernel32.dll")

# 定義函數返回值與參數類型
dbghelp.SymInitializeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_bool]
dbghelp.SymInitializeW.restype = ctypes.c_bool

dbghelp.SymLoadModuleExW.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
    ctypes.c_ulonglong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong
]
dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong

dbghelp.SymEnumSymbolsW.argtypes = [
    ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_wchar_p,
    ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(SYMBOL_INFO), ctypes.c_ulong, ctypes.c_void_p),
    ctypes.c_void_p
]
dbghelp.SymEnumSymbolsW.restype = ctypes.c_bool

dbghelp.SymCleanup.argtypes = [ctypes.c_void_p]
dbghelp.SymCleanup.restype = ctypes.c_bool

dbghelp.SymSetOptions.argtypes = [ctypes.c_ulong]
dbghelp.SymSetOptions.restype = ctypes.c_ulong

# 設定 `SYMOPT_DEBUG` 以偵錯符號載入
dbghelp.SymSetOptions(0x00000001 | 0x00000004 | 0x00000040)  # SYMOPT_DEBUG | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES


rva_map = {}
# 定義回調函數
def enum_symbols_callback(pSymInfo, SymbolSize, UserContext):
    symbol = pSymInfo.contents  # 獲取 SYMBOL_INFO 結構
    #print(symbol.Flags)
    #if(symbol.Flags & 0x800): # SYMFLAG_FUNCTION
    symbol_name = symbol.Name
    #print(symbol_name)
    #print(hex(symbol.Address - symbol.ModBase))

    rva_map[symbol.Address - symbol.ModBase] = symbol_name

    return True

def main(image_path):
    # 取得當前進程句柄
    hProcess = kernel32.GetCurrentProcess()

    # get current folder
    current_folder = os.path.dirname(os.path.abspath(__file__))

    # check symbols folder exists
    symbols_folder = os.path.join(current_folder, "symbols")
    if not os.path.exists(symbols_folder):
        os.mkdir(symbols_folder)

    # 設定符號存放路徑（這裡使用 Microsoft 符號伺服器）
    symbol_path = f"SRV*{symbols_folder}*https://msdl.microsoft.com/download/symbols"

    # 初始化符號解析
    if not dbghelp.SymInitializeW(hProcess, symbol_path, True):
        print("SymInitialize 失敗")
        exit(1)


    # 指定要解析的 DLL 或 EXE
    image_path = os.path.abspath(image_path)

    module_base = dbghelp.SymLoadModuleExW(hProcess, None, image_path, None, 0, 0, None, 0)
    if module_base == 0:
        print("SymLoadModuleEx 失敗")
        dbghelp.SymCleanup(hProcess)
        exit(1)

    # 列舉符號
    enum_callback = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(SYMBOL_INFO), ctypes.c_ulong, ctypes.c_void_p)(enum_symbols_callback)
    dbghelp.SymEnumSymbolsW(hProcess, module_base, None, enum_callback, None)

    # 清理
    dbghelp.SymCleanup(hProcess)



if __name__ == "__main__":

    # 設定命令列參數
    parser = argparse.ArgumentParser(description="Dump all API symbols from an image file.")
    parser.add_argument("image_path", type=str, help="Path to the DLL or EXE file")
    args = parser.parse_args()

    main(args.image_path)
    basename = os.path.basename(args.image_path)

    with(open(f"{basename}.api", 'w')) as f:
        for key in rva_map:
            f.write(f"{rva_map[key]}:{hex(key)}\n")
