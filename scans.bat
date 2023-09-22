net user /add scans scans
mkdir C:\scans
icacls C:\scans /grant scans:(OI)(CI)F /T
net share scans=C:\scans /GRANT:scans,FULL