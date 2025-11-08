using System.Security.AccessControl;
using System.Security.Principal;

class FileSystemAudit
{
    private static bool _recursive = false;
    private static bool _skip_inherit_only = true;
    private static List<string> _excludeFolders = new List<string>();
    private static List<string> _includeUsers = new List<string>();
    private static List<string> _includeGroups = new List<string>();
    private static List<string> _includePermissions = new List<string>();
    private static List<string> _includeOwners = new List<string>();
    private static bool _debug = false;

    public static void Init()
    {
        _recursive = CLIArguments.Instance.Recursive;
        _skip_inherit_only = CLIArguments.Instance.Skip_Inherit_Only;
        _excludeFolders = CLIArguments.Instance.Exclude_Folders.ToList();
        _includeUsers = CLIArguments.Instance.Include_Users.ToList();
        _includeGroups = CLIArguments.Instance.Include_Groups.ToList();
        _includePermissions = CLIArguments.Instance.Include_Permissions.ToList();
        _includeOwners = CLIArguments.Instance.Include_Owners.ToList();
        _debug = CLIArguments.Instance.Debug;
    }

    public static void AuditPath(string path)
    {
        if (ShouldExclude(path))
        {
            if (_debug) Console.WriteLine($"Skipping excluded folder: {path}");
            return;
        }

        if (Directory.Exists(path))
        {
            AuditDirectory(path);
            AuditFilesInDirectory(path);

            // Recursively audit subdirectories if flag is set
            if (_recursive)
            {
                try
                {
                    string[] subDirectories = Directory.GetDirectories(path);
                    foreach (string subDir in subDirectories)
                    {
                        try
                        {
                            AuditPath(subDir);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            if (_debug) Console.WriteLine($"Access denied: {subDir}");
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    if (_debug) Console.WriteLine($"Access denied: {path}");
                }
            }
        }
        else if (File.Exists(path))
        {
            AuditFile(path);
        }
        else
        {
            if (_debug) Console.WriteLine($"Path '{path}' does not exist.");
        }
    }

    static void AuditFilesInDirectory(string directoryPath)
    {
        try
        {
            string[] files = Directory.GetFiles(directoryPath);
            foreach (string file in files)
            {
                AuditFile(file);
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (_debug) Console.WriteLine($"Access denied to files in directory.");
        }
    }

    static void AuditDirectory(string directoryPath)
    {
        try
        {
            // Using AccessControlSections.All causes access denied
            DirectoryInfo dirInfo = new DirectoryInfo(directoryPath);

            if (dirInfo.Root.FullName == directoryPath)
            {
                return;
            }

            DirectorySecurity dirOwnerSecurity = dirInfo.GetAccessControl(AccessControlSections.Owner);

            DirectorySecurity dirSecurity = dirInfo.GetAccessControl(AccessControlSections.Access);
            AuthorizationRuleCollection rules = dirSecurity.GetAccessRules(true, true, typeof(NTAccount));

            string owner = dirOwnerSecurity.GetOwner(typeof(NTAccount))?.Value ?? "Unknown";

            bool printed_key = false;

            if (_includeOwners.Count > 0)
            {
                foreach (string o in _includeOwners)
                {
                    if (owner.Equals(o, StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"Directory: {directoryPath}");
                        Console.WriteLine($"Owner: {owner}");
                        return;
                    }
                }
                return;
            }

            foreach (FileSystemAccessRule rule in rules)
            {
                if (ShouldIncludeRule(rule))
                {
                    if (!printed_key)
                    {
                        Console.WriteLine($"Directory: {directoryPath}");
                        Console.WriteLine($"Owner: {owner}");
                        Console.WriteLine($"Access Rules:");
                        printed_key = true;
                    }
                    PrintAccessRule(rule);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (_debug) Console.WriteLine($"Access denied to directory.");
        }
    }

    static void AuditFile(string filePath)
    {
        try
        {
            FileInfo fileInfo = new FileInfo(filePath);
            FileSecurity fileOwnerSecurity = fileInfo.GetAccessControl(AccessControlSections.Owner);

            bool printed_key = false;

            string owner = fileOwnerSecurity.GetOwner(typeof(NTAccount))?.Value ?? "Unknown";

            FileSecurity fileSecurity = fileInfo.GetAccessControl(AccessControlSections.Access);
            AuthorizationRuleCollection rules = fileSecurity.GetAccessRules(true, true, typeof(NTAccount));

            if (_includeOwners.Count > 0)
            {
                foreach (string o in _includeOwners)
                {
                    if (owner.Equals(o, StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"File: {filePath}");
                        Console.WriteLine($"Owner: {owner}");
                        return;
                    }
                }
                return;
            }

            foreach (FileSystemAccessRule rule in rules)
            {
                if (ShouldIncludeRule(rule))
                {
                    if (!printed_key)
                    {
                        Console.WriteLine($"File: {filePath}");
                        Console.WriteLine($"Owner: {owner}");
                        Console.WriteLine($"Access Rules:");
                        printed_key = true;
                    }

                    PrintAccessRule(rule);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (_debug) Console.WriteLine($"Access denied to file: {filePath}");
        }
        catch (Exception ex)
        {
            if (_debug) Console.WriteLine($"AuditFile Error: {ex.Message}");
        }
    }

    static void PrintAccessRule(FileSystemAccessRule rule)
    {
        // Since we are already checking file ACL, we skip inherit only propagation
        if (_skip_inherit_only && rule.PropagationFlags == PropagationFlags.InheritOnly)
        {
            return;
        }

        string identity = rule.IdentityReference.Value;
        string accessType = rule.AccessControlType == AccessControlType.Allow ? "ALLOW" : "DENY";
        string r = rule.FileSystemRights.ToString();
        if (((int)rule.FileSystemRights) == 268435456)
        {
            r = "FullControl";
        }
        else if (((int)rule.FileSystemRights) == -1610612736)
        {
            r = "ReadAndExecute, Synchronize";
        }
        else if (((int)rule.FileSystemRights) == -536805376)
        {
            r = "Modify, Synchronize";
        }

        Console.WriteLine($"  Identity: {identity}");
        Console.WriteLine($"     Type: {accessType}");
        Console.WriteLine($"     Rights: {r}");
        Console.WriteLine($"     Inherited: {(rule.IsInherited ? "Yes" : "No")}");
        Console.WriteLine($"     Propogation: {rule.PropagationFlags}");
        Console.WriteLine();
    }


    static bool ShouldIncludeRule(FileSystemAccessRule rule)
    {
        string identity = rule.IdentityReference.Value;
        bool _check;

        // If no filters specified, show all rules
        if (_includeUsers.Count == 0 && _includeGroups.Count == 0 && _includePermissions.Count == 0)
        {
            return true;
        }

        if (_includeUsers.Count > 0)
        {
            _check = false;
            foreach (string user in _includeUsers)
            {
                if (identity.ToString().EndsWith("\\" + user, StringComparison.OrdinalIgnoreCase))
                {
                    _check = true;
                    break;
                }
            }

            if (!_check) return false;
        }

        // Check if rule matches specified users

        if (_includeGroups.Count > 0)
        {
            _check = false;
            // Check if rule matches specified groups
            foreach (string group in _includeGroups)
            {
                if (identity.Equals(group, StringComparison.OrdinalIgnoreCase) ||
                identity.EndsWith("\\" + group, StringComparison.OrdinalIgnoreCase))
                {
                    _check = true;
                    break;
                }
            }
            if (!_check) return false;
        }

        if (_includePermissions.Count > 0)
        {
            _check = false;
            foreach (string permission in _includePermissions)
            {
                if (PermissionMatches(rule.FileSystemRights, permission))
                {
                    _check = true;
                    break;
                }
            }
            if (!_check) return false;
        }


        return true;
    }

    static bool PermissionMatches(FileSystemRights rights, string permission)
    {
        string permissionUpper = permission.ToUpper();
        switch (permissionUpper)
        {
            case "READ":
                return rights.HasFlag(FileSystemRights.Read);
            case "WRITE":
                return rights.HasFlag(FileSystemRights.Write);
            case "MODIFY":
                return rights.HasFlag(FileSystemRights.Modify);
            case "FULLCONTROL":
                return rights.HasFlag(FileSystemRights.FullControl);
            default:
                return false;
        }
    }

    static bool ShouldExclude(string path)
    {
        foreach (string excludeFolder in _excludeFolders)
        {
            if (path.Equals(excludeFolder, StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(excludeFolder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}
