This tool audits FileSystem, Service, Registry, TaskScheduler ACL.

# Arguments
```
--path # Path for filesystem and registry audits, you can give "service" for service audit and "taskscheduler" for taskscheduler audit
--recursive # Enable recursion for filesystem and registry audits
--exclude # Exclude given paths for filesystem and registry audits
--user # Only shows given users
--group # Only shows given groups
--permission # Only shows given permission if rule has the flag of the permission
--debug # Show debug messages 
```

# Examples

```Powershell
.\WindowsACLAudit.exe --path "C:\"
.\WindowsACLAudit.exe --path "C:\" --recursive --user john --group conto --permission fullcontrol --exclude "C:\Users"
.\WindowsACLAudit.exe --path "HKLM\SOFTWARE"
.\WindowsACLAudit.exe --path "service"
.\WindowsACLAudit.exe --path "taskscheduler"
```