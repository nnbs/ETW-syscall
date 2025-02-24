
import ctypes
import string

_drive_cache = {}
def get_drive_volume(drive):
    """
    如果快取中有資料，直接回傳；否則呼叫 QueryDosDeviceW 並快取結果
    """
    global _drive_cache
    if drive not in _drive_cache:
        kernel32 = ctypes.windll.kernel32
        buffer_size = 1024
        buffer = ctypes.create_unicode_buffer(buffer_size)
        if kernel32.QueryDosDeviceW(drive, buffer, buffer_size):
            _drive_cache[drive] = buffer.value
        else:
            _drive_cache[drive] = None
    return _drive_cache[drive]

def device_to_dos_path(device_path):
    """
    將 device_path 轉換成 DOS 路徑。
    對於每個 A: 到 Z: 的盤符，從快取中獲取 device volume 名稱，
    若 device_path 是以該 volume 名稱開頭，則替換為盤符名稱。
    """
    for drive_letter in string.ascii_uppercase:
        drive = f"{drive_letter}:"
        volume_path = get_drive_volume(drive)
        if volume_path and volume_path in device_path:
            return device_path.replace(volume_path, drive, 1)

    # 若未匹配到任何盤符，則回傳原始路徑
    return device_path


def calculate_offsets():
    try:

        address_map = {}
        with open('driver.txt', 'r') as f_driver:
            for driver_info in f_driver:
                str_list = driver_info.strip().split(':')
                while '' in str_list:
                    str_list.remove('')
                if(len(str_list) == 2):
                    module = str_list[0]
                    base = int(str_list[1], 16)
                    try:
                        with open(f"{module}.api", 'r') as f_export:
                            for line in f_export:
                                str_list = line.strip().split(':')
                                while '' in str_list:
                                    str_list.remove('')
                                if(len(str_list) == 2):
                                    addr = str_list[1]
                                    address_map[int(addr, 16) + base] = f"{module}!{str_list[0]}"
                    except FileNotFoundError:
                        pass
                    except Exception as e:
                        print(f"Error processing file: {str(e)}")

        result = {}
        with open('ProcessCallAPI.name.log', 'w') as f_out:
            with open('ProcessCallAPI.txt', 'r') as f:
                for line in f:
                    # Split line by colon
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        try:
                            # Convert address from string to int (assuming hex)
                            addr = int(parts[0].strip(), 16)

                            # Get API name from second field
                            if addr in address_map:
                                api_name = address_map[addr]
                            else:
                                api_name = f"0x{addr:X}"
                        except ValueError:
                            print(f"Invalid address format in line: {line}")
                        #print(api_name)
                        if api_name in result:
                            result[api_name] += int(parts[1])
                        else:
                            result[api_name] = int(parts[1])
                        f_out.write(f"    {api_name}: {parts[1]}\n")
                    else:
                        f_out.write(device_to_dos_path(line))

        # Sort the dictionary by value, reverse
        sorted_data = dict(sorted(result.items(), key=lambda item: item[1], reverse=True))
        with open('syscall.log', 'w') as f_out:
            for key in sorted_data:
                f_out.write(f"{key}:{sorted_data[key]}\n")

    except FileNotFoundError:
        print("Error: syscall.txt not found")
    except Exception as e:
        print(f"Error processing file: {str(e)}")

if __name__ == "__main__":
    calculate_offsets()



