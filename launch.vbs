Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\DPDP-Scanner"
WshShell.Run "cmd.exe /c python -m streamlit run main.py", 0, false
