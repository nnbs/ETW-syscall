import ctypes

# 加载 kernel32.dll 和 psapi.dll
kernel32 = ctypes.WinDLL("kernel32")
psapi = ctypes.WinDLL("psapi")

# 定义类型
LPVOID = ctypes.c_void_p
DWORD = ctypes.c_ulong
ARRAY_SIZE = 1024

# 分配缓冲区存储驱动程序地址
drivers = (LPVOID * ARRAY_SIZE)()
cb_needed = DWORD()

# 获取驱动程序基地址列表
if psapi.EnumDeviceDrivers(ctypes.byref(drivers), ctypes.sizeof(drivers), ctypes.byref(cb_needed)):
    num_drivers = cb_needed.value // ctypes.sizeof(LPVOID)

    # 设置 GetDeviceDriverBaseNameA() 的参数类型
    psapi.GetDeviceDriverBaseNameA.argtypes = [LPVOID, ctypes.c_char_p, DWORD]

    # 遍历所有驱动
    with open('driver.txt', 'w') as f:
        for i in range(num_drivers):
            driver_base = ctypes.cast(drivers[i], LPVOID)  # 确保 driver_base 是 LPVOID 类型
            driver_name = ctypes.create_string_buffer(256)

            if psapi.GetDeviceDriverBaseNameA(driver_base, driver_name, ctypes.sizeof(driver_name)):
                name = driver_name.value.decode()
                f.write(f"{name}:{hex(drivers[i])}\n")

else:
    print("Failed to enumerate device drivers")
