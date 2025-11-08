using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;


class RegistryAudit
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
    static void PrintAccessRule(RegistryAccessRule rule)
    {
        // Since we are already checking file ACL, we skip inherit only propagation
        if (_skip_inherit_only && rule.PropagationFlags == PropagationFlags.InheritOnly)
        {
            return;
        }

        string identity = rule.IdentityReference.Value;
        string accessType = rule.AccessControlType == AccessControlType.Allow ? "ALLOW" : "DENY";
        string r = rule.RegistryRights.ToString();
        if (((int)rule.RegistryRights) == 268435456)
        {
            r = "FullControl";
        }
        else if (((int)rule.RegistryRights) == -1610612736)
        {
            r = "ReadAndExecute, Synchronize";
        }
        else if (((int)rule.RegistryRights) == -536805376)
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



    public static void AuditRegistryPath(string registryPath)
    {

        // Check if this path should be excluded
        if (ShouldExclude(registryPath))
        {
            if (_debug) Console.WriteLine($"Skipping excluded key: {registryPath}");
            return;
        }

        try
        {
            using (RegistryKey key = GetRegistryKey(registryPath))
            {
                if (key != null)
                {
                    AuditRegistryKey(key, registryPath);

                    if (_recursive)
                    {
                        try
                        {
                            string[] subKeyNames = key.GetSubKeyNames();
                            foreach (string subKeyName in subKeyNames)
                            {
                                string subKeyPath = registryPath.EndsWith("\\") ? registryPath + subKeyName : registryPath + "\\" + subKeyName;
                                AuditRegistryPath(subKeyPath);
                            }
                        }

                        catch (UnauthorizedAccessException)
                        {
                            if (_debug) Console.WriteLine($"Access denied to registry key: {registryPath}");

                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            if (_debug) Console.WriteLine($"Error: {ex.Message}");
        }
    }


    static void AuditRegistryKey(RegistryKey key, string keyPath)
    {
        try
        {
            RegistrySecurity keyOwnerSecurity = key.GetAccessControl(AccessControlSections.Owner);

            bool printed_key = false;

            string owner = keyOwnerSecurity.GetOwner(typeof(NTAccount))?.Value ?? "Unknown";

            RegistrySecurity keySecurity = key.GetAccessControl(AccessControlSections.Access);
            AuthorizationRuleCollection rules = keySecurity.GetAccessRules(true, true, typeof(NTAccount));

            if (_includeOwners.Count > 0)
            {
                foreach (string o in _includeOwners)
                {
                    if (owner.Equals(o, StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"Registry Key: {keyPath}");
                        Console.WriteLine($"Owner: {owner}");
                        return;
                    }
                }
                return;
            }
            
            foreach (RegistryAccessRule rule in rules)
            {

                if (ShouldIncludeRule(rule))
                {
                    if (!printed_key)
                    {
                        Console.WriteLine($"Registry Key: {keyPath}");
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
            if (_debug) Console.WriteLine($"Access denied to registry key.");
        }
    }

    static RegistryKey GetRegistryKey(string registryPath)
    {
        try
        {
            // Parse registry path to get root key and subkey
            string[] pathParts = registryPath.Split('\\');
            if (pathParts.Length == 0)
            {
                return null;
            }

            // Get the root key (HKEY_LOCAL_MACHINE, etc.)
            RegistryKey rootKey = GetRootKey(pathParts[0]);
            if (rootKey == null)
            {
                return null;
            }

            // Build the subkey path
            string subKeyPath = string.Join("\\", pathParts, 1, pathParts.Length - 1);

            return rootKey.OpenSubKey(subKeyPath, false);
        }
        catch (Exception)
        {
            return null;
        }
    }

    static RegistryKey GetRootKey(string rootKeyName)
    {
        switch (rootKeyName.ToUpper())
        {
            case "HKEY_LOCAL_MACHINE":
            case "HKLM":
                return Registry.LocalMachine;
            case "HKEY_CURRENT_USER":
            case "HKCU":
                return Registry.CurrentUser;
            case "HKEY_CLASSES_ROOT":
            case "HKCR":
                return Registry.ClassesRoot;
            case "HKEY_USERS":
            case "HKU":
                return Registry.Users;
            case "HKEY_CURRENT_CONFIG":
            case "HKCC":
                return Registry.CurrentConfig;
            default:
                return null;
        }
    }
    
    static bool ShouldIncludeRule(RegistryAccessRule rule)
    {
        string identity = rule.IdentityReference.Value;

        // If no filters specified, show all rules
        if (_includeUsers.Count == 0 && _includeGroups.Count == 0 && _includePermissions.Count == 0)
        {
            return true;
        }

        // Check if rule matches specified users
        foreach (string user in _includeUsers)
        {
            if (identity.ToString().EndsWith("\\" + user, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Check if rule matches specified groups
        foreach (string group in _includeGroups)
            {
                if (identity.Equals(group, StringComparison.OrdinalIgnoreCase) ||
                identity.EndsWith("\\" + group, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (string permission in _includePermissions)
        {
            if (PermissionMatches(rule.RegistryRights, permission))
            {
                return true;
            }
        }

        return false;
    }


    static bool PermissionMatches(RegistryRights rights, string permission)
    {
        string permissionUpper = permission.ToUpper();
        
        switch (permissionUpper)
        {
            case "READ":
                return rights.HasFlag(RegistryRights.ReadKey);
            case "MODIFY":
                return rights.HasFlag(RegistryRights.WriteKey);
            case "DELETE":
                return rights.HasFlag(RegistryRights.Delete);
            case "FULLCONTROL":
                return rights.HasFlag(RegistryRights.FullControl);
            case "CREATE":
                return rights.HasFlag(RegistryRights.CreateSubKey);
            case "LIST":
                return rights.HasFlag(RegistryRights.EnumerateSubKeys);
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
