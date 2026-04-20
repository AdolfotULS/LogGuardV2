using LogGuardV2.src.Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace LogGuardV2.src
{
    class AppSettings
    {
        #region PostgreSQL Log Settings
        internal static string LogDirectory { get; set; }
        internal static string watchPattern { get; set; } = "postgresql-*.log";
        internal static string TimeZone { get; set; } = "UTC";
        internal static string LogFormat { get; set; } = "%m [%p] %q%u@%h %d";

        internal static bool FollowRotation { get; set; } = true;
        internal static bool ReplayHistory { get; set; } = false;

        #endregion

        #region Parser Settings

        internal static bool Timestamp { get; set; } = true;
        internal static bool ConnectionDetails { get; set; } = true;
        internal static bool QueryDetails { get; set; } = true;
        internal static bool SystemMetrics { get; set; } = false;
        internal static bool RawMesssage { get; set; } = true;
        internal static bool RedactPasswords { get; set; } = true;

        #endregion

        #region Alerts
        internal static string WebHookUrl { get; set; }
        internal static LogLevel.LogLevelEnum MinimumAlertLevel { get; set; } = LogLevel.LogLevelEnum.ERROR;
        internal static bool DesktopNotifications { get; set; } = true;
        internal static bool SoundAlerts { get; set; } = false;
        #endregion
    }
}
