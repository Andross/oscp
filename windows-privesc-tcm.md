### Windows Privesc TCM

## System Enumeration

systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 

*Pull up patches*
wmic qfe

wmic qfe get Caption,Description,HotFixID,InstalledOn

*List all drives*
wmic logicdisk
