@echo off
setlocal enabledelayedexpansion

:: 创建一个临时文件存储包名和安装时间
set temp_file=%temp%\packages_with_time.txt
if exist %temp_file% del %temp_file%

:: 获取所有应用包名
for /f "tokens=*" %%A in ('adb shell pm list packages') do (
    set package=%%A
    set package=!package:package:=!

    :: 获取应用的安装时间
    for /f "tokens=*" %%B in ('adb shell dumpsys package !package! ^| findstr "firstInstallTime"') do (
        set install_time=%%B
        set install_time=!install_time:firstInstallTime=!
        echo !install_time! !package! >> %temp_file%
    )
)

:: 按安装时间排序并输出
echo 应用包名及安装时间（按时间排序）:
for /f "tokens=*" %%C in ('sort %temp_file%') do (
    echo %%C
)

:: 删除临时文件
del %temp_file%
endlocal
pause
