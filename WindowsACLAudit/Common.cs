class CLIArguments
{
    public static CLIArguments Instance;
    
    [Huzzah.OptionParameter(LongName = "path", ShortName = 'p')]
    public string Path { get; set; }
    [Huzzah.OptionParameter(DefaultValue = false, LongName = "recursive", ShortName = 'r')]
    public bool Recursive { get; set; }
    [Huzzah.OptionParameter(DefaultValue = false, LongName = "debug", ShortName = 'd')]
    public bool Debug { get; set; }
    [Huzzah.OptionParameter(DefaultValue = true, LongName = "skip-inherit-only")]
    public bool Skip_Inherit_Only { get; set; }
    [Huzzah.OptionParameter(LongName ="exclude", ShortName = 'e', DefaultValue = new string[] {})]
    public string[] Exclude_Folders { get; set; }
    [Huzzah.OptionParameter(LongName = "user", ShortName = 'u', DefaultValue = new string[] {})]
    public string[] Include_Users { get; set; }
    [Huzzah.OptionParameter(LongName = "group", ShortName = 'g', DefaultValue = new string[] {})]
    public string[] Include_Groups { get; set; }
    [Huzzah.OptionParameter(LongName = "permission", DefaultValue = new string[] {})]
    public string[] Include_Permissions { get; set; }
}