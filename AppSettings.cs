namespace LogGuardV2;

public class AppSettings
{
    // Source & Watch
    public string LogDirectory       { get; set; } = @"C:\ProgramData\LogGuard\watch\";
    public string WatchPattern       { get; set; } = "postgresql-*.log";
    public string Timezone           { get; set; } = "UTC";
    public string LogLineFormat      { get; set; } = "%m [%p] %q%u@%h %d ";
    public bool   FollowRotation     { get; set; } = true;
    public bool   ReplayOnStart      { get; set; } = false;

    // Parser fields
    public bool ParseCoreFields         { get; set; } = true;
    public bool ParseConnectionDetails  { get; set; } = true;
    public bool ParseQueryDetails       { get; set; } = true;
    public bool ParseSystemMetrics      { get; set; } = false;
    public bool ParseRawMessage         { get; set; } = true;
    public bool RedactPasswords         { get; set; } = true;

    // Alerts
    public string AlertWebhookUrl       { get; set; } = "https://hooks.internal/logguard/alerts";
    public string AlertMinLevel         { get; set; } = "ERROR";
    public bool   DesktopNotifications  { get; set; } = true;
    public bool   AudioBeepOnFatal      { get; set; } = false;
}
