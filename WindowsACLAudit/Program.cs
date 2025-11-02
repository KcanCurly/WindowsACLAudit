
class WindowsSystemAudit
{
    static void Main(string[] args)
    {
        ParseArguments(args);
    }

    static void ParseArguments(string[] args)
    {
        if (args.Length == 0)
        {
            ShowHelp();
            return;
        }

        var options = Huzzah.CommandLineArgumentParser.Parse<CLIArguments>(args).ParsedOptions;
        CLIArguments.Instance = options;

        string path = options.Path;


        Console.WriteLine("=== Windows ACL Auditor ===");
        Console.WriteLine($"Recursive mode: {(CLIArguments.Instance.Recursive ? "Enabled" : "Disabled")}");
        if (CLIArguments.Instance.Exclude_Folders.ToList().Count > 0)
        {
            Console.WriteLine($"Excluded: {string.Join(", ", CLIArguments.Instance.Exclude_Folders.ToList())}");
        }
        if (CLIArguments.Instance.Include_Users.ToList().Count > 0)
        {
            Console.WriteLine($"Included users: {string.Join(", ", CLIArguments.Instance.Include_Users.ToList())}");
        }
        if (CLIArguments.Instance.Include_Groups.ToList().Count > 0)
        {
            Console.WriteLine($"Included groups: {string.Join(", ", CLIArguments.Instance.Include_Groups.ToList())}");
        }
        if (CLIArguments.Instance.Include_Permissions.ToList().Count > 0)
        {
            Console.WriteLine($"Included permissions: {string.Join(", ", CLIArguments.Instance.Include_Permissions.ToList())}");
        }
        Console.WriteLine(new string('-', 60));

        if (path.ToUpperInvariant().StartsWith("HK"))
        {
            RegistryAudit.Init();
            RegistryAudit.AuditRegistryPath(path);
        }
        else if (path.ToUpperInvariant().StartsWith("TASKSCHEDULER"))
        {
            TaskSchedulerAudit.Init();
            TaskSchedulerAudit.DisplayStartupTasks();
        }
        else if (path.ToUpperInvariant().StartsWith("SERVICE"))
        {
            ServiceAudit.Init();
            ServiceAudit.AuditAllServices();
        }
        else
        {
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.WriteLine($"Error: Path '{path}' does not exist.");
                return;
            }
            FileSystemAudit.Init();
            FileSystemAudit.AuditPath(path);
        }
    }

    static void ShowHelp()
    {
        Console.WriteLine("=== Windows ACL Auditor ===");
        Console.WriteLine("Usage: WindowsSystemAudit.exe <path> <flags>");
        Console.WriteLine();
    }
}
