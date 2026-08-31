Set WshShell = CreateObject("WScript.Shell")

REM Start backend completely hidden
WshShell.CurrentDirectory = "F:\My Project\Baraq"
WshShell.Run "cmd /c python start_dev.py >nul 2>&1", 0, False

WScript.Sleep 4000

REM Start frontend completely hidden
WshShell.CurrentDirectory = "F:\My Project\Baraq\frontend"
WshShell.Run "cmd /c npm run dev >nul 2>&1", 0, False
