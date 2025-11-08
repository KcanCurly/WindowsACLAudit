using System.ServiceProcess;
using System.Security.AccessControl;
using System.Security.Principal;

class ServiceAudit
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

    public static void AuditAllServices()
    {
        try
        {
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                AuditService(service);
            }
        }
        catch (Exception ex)
        {
            if (_debug) Console.WriteLine($"Error retrieving services: {ex.Message}");
        }
    }

    static void AuditService(ServiceController service)
    {
        try
        {
            string servicePath = $"SYSTEM\\CurrentControlSet\\Services\\{service.ServiceName}";
            
            using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(servicePath))
            {
                if (key != null)
                {
                    RegistrySecurity serviceOwnerSecurity = key.GetAccessControl(AccessControlSections.Owner);
                    
                    string owner = serviceOwnerSecurity.GetOwner(typeof(NTAccount))?.Value ?? "Unknown";

                    if (_includeOwners.Count > 0)
                    {
                        foreach (string o in _includeOwners)
                        {
                            if (owner.Equals(o, StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine($"Service: {service.ServiceName}");
                                Console.WriteLine($"Display Name: {service.DisplayName}");
                                Console.WriteLine($"Status: {service.Status}");
                                Console.WriteLine($"Owner: {owner}");
                                return;
                            }
                        }
                        return;
                    }


                    Console.WriteLine($"Service: {service.ServiceName}");
                    Console.WriteLine($"Display Name: {service.DisplayName}");
                    Console.WriteLine($"Status: {service.Status}");
                    Console.WriteLine($"Owner: {owner}");
                    Console.WriteLine($"Access Rules:");
                    
                    RegistrySecurity serviceSecurity = key.GetAccessControl(AccessControlSections.Access);
                    AuthorizationRuleCollection rules = serviceSecurity.GetAccessRules(true, true, typeof(NTAccount));
                    
                    bool hasMatchingRules = false;
                    foreach (RegistryAccessRule rule in rules)
                    {
                        if (ShouldIncludeRule(rule))
                        {
                            PrintServiceAccessRule(rule);
                        }
                    }
                    
                }
                else
                {
                    if (_debug) Console.WriteLine($"Service registry key not found: {service.ServiceName}");
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (_debug) Console.WriteLine($"Access denied to service: {service.ServiceName}");

        }
        catch (Exception ex)
        {
            if (_debug) Console.WriteLine($"Error auditing service '{service.ServiceName}': {ex.Message}");
        }
    }

    static void PrintServiceAccessRule(RegistryAccessRule rule)
    {
        string identity = rule.IdentityReference.Value;
        string accessType = rule.AccessControlType == AccessControlType.Allow ? "ALLOW" : "DENY";

        Console.WriteLine($"  Identity: {identity}");
        Console.WriteLine($"     Type: {accessType}");
        Console.WriteLine($"     Rights: {rule.RegistryRights}");
        Console.WriteLine($"     Inherited: {(rule.IsInherited ? "Yes" : "No")}");


        
        Console.WriteLine();
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
}