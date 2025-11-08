using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.TaskScheduler;
using Task = Microsoft.Win32.TaskScheduler.Task;

class TaskSchedulerAudit
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

    public static List<Task> GetStartupTriggeredTasks()
    {
        var startupTasks = new List<Task>();

        using (TaskService ts = new TaskService())
        {
            foreach (Task task in ts.AllTasks)
            {
                foreach (Trigger trigger in task.Definition.Triggers)
                {
                    if (trigger.TriggerType == TaskTriggerType.Boot ||
                        trigger.TriggerType == TaskTriggerType.Logon)
                    {
                        startupTasks.Add(task);
                        break;
                    }
                }
            }

            return startupTasks;
        }
    }

    public static void DisplayStartupTasks()
    {
        var tasks = GetStartupTriggeredTasks();

        foreach (var task in tasks)
        {
            TaskSecurity taskSecurity = task.GetAccessControl();

            AuthorizationRuleCollection rules = taskSecurity.GetAccessRules(true, true, typeof(NTAccount));

            string owner = taskSecurity.GetOwner(typeof(NTAccount))?.Value ?? "Unknown";

            foreach (string o in _includeOwners)
            {
                if (owner.Equals(o, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Task: {task.Name}");
                    Console.WriteLine($"State: {task.State}");
                    Console.WriteLine($"Enabled: {task.Enabled}");
                    Console.WriteLine($"Runs As: {task.Definition.Principal.Account}");
                    Console.WriteLine($"Startup: {task.Path}");

                    Console.WriteLine($"Triggers:");
                    foreach (var trigger in task.Definition.Triggers)
                    {
                        Console.WriteLine($"  Trigger Type: {trigger.TriggerType}");
                        Console.WriteLine($"  Description: {task.Definition.RegistrationInfo.Description}");

                        foreach (var action in task.Definition.Actions)
                            Console.WriteLine($"  Action: {action}");

                        Console.WriteLine();
                    }
                    Console.WriteLine($"Security:");
                    Console.WriteLine($"  Owner:{owner}");
                    return;
                }
            }
        

            bool printed_key = false;

            foreach (TaskAccessRule rule in rules)
            {
                if (ShouldIncludeRule(rule))
                {
                    if (!printed_key)
                    {
                        Console.WriteLine($"Task: {task.Name}");
                        Console.WriteLine($"State: {task.State}");
                        Console.WriteLine($"Enabled: {task.Enabled}");
                        Console.WriteLine($"Runs As: {task.Definition.Principal.Account}");
                        Console.WriteLine($"Startup: {task.Path}");

                        Console.WriteLine($"Triggers:");
                        foreach (var trigger in task.Definition.Triggers)
                        {
                            Console.WriteLine($"  Trigger Type: {trigger.TriggerType}");
                            Console.WriteLine($"  Description: {task.Definition.RegistrationInfo.Description}");

                            foreach (var action in task.Definition.Actions)
                                Console.WriteLine($"  Action: {action}");

                            Console.WriteLine();
                        }
                        Console.WriteLine($"Security:");
                        Console.WriteLine($"  Owner:{owner}");
                        Console.WriteLine($"Access Rules:");
                        printed_key = true;
                    }

                    PrintAccessRule(rule);
                }
            }

        }
    }

    static void PrintAccessRule(TaskAccessRule rule)
    {
        string identity = rule.IdentityReference.Value;
        string accessType = rule.AccessControlType == AccessControlType.Allow ? "ALLOW" : "DENY";
        string r = rule.TaskRights.ToString();
        if (((int)rule.TaskRights) == 268435456)
        {
            r = "FullControl";
        }
        else if (((int)rule.TaskRights) == -1610612736)
        {
            r = "ReadAndExecute, Synchronize";
        }
        else if (((int)rule.TaskRights) == -536805376)
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

    static bool ShouldIncludeRule(TaskAccessRule rule)
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
                if (PermissionMatches(rule.TaskRights, permission))
                {
                    _check = true;
                    break;
                }
            }
            if (!_check) return false;
        }


        return true;
    }

    static bool PermissionMatches(TaskRights rights, string permission)
    {
        string permissionUpper = permission.ToUpper();
        switch (permissionUpper)
        {
            case "READ":
                return rights.HasFlag(TaskRights.Read);
            case "MODIFY":
                return rights.HasFlag(TaskRights.Write);
            case "DELETE":
                return rights.HasFlag(TaskRights.Delete);
            case "FULLCONTROL":
                return rights.HasFlag(TaskRights.FullControl);
            default:
                return false;
        }
    }
}