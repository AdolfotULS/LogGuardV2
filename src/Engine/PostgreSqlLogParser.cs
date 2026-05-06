using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace LogGuardV2.src.Engine
{
    public enum PgLogLineType
    {
        Unknown,
        General,
        Statement,
        Duration,
        ConnectionReceived,
        ConnectionAuthenticated,
        ConnectionAuthorized,
        Disconnection
    }

    public sealed class PgLogEntry
    {
        public DateTimeOffset Timestamp { get; set; }
        public string ProcessId { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Message { get; set; } = "";
        public PgLogLineType Type { get; set; } = PgLogLineType.Unknown;

        public double? DurationMs { get; set; }
        public string? Host { get; set; }
        public int? Port { get; set; }
        public string? Identity { get; set; }
        public string? Method { get; set; }
        public string? AuthFile { get; set; }
        public int? AuthLine { get; set; }
        public string? User { get; set; }
        public string? Database { get; set; }
        public string? ApplicationName { get; set; }
        public string? SessionTime { get; set; }

        public override string ToString()
            => $"[{Type}] Ts={Timestamp:O}, Pid={ProcessId}, Severity={Severity}, Message={Message}";
    }

    public static class PostgreSqlLogParser
    {
        // Timestamp and timezone captured separately to support non-UTC servers
        private static readonly Regex HeaderRegex = new(
            @"^(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?<tz>\S+)\s+\[(?<pid>\d+)\]\s+(?<severity>[A-Z]+):\s{1,}(?<message>[\s\S]*)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex StatementRegex = new(
            @"^statement:\s*(?<statement>[\s\S]*)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex DurationRegex = new(
            @"^duration:\s*(?<duration_ms>\d+(?:\.\d+)?)\s+ms(?:\s+(?<detail>.*))?$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex ConnectionReceivedRegex = new(
            @"^connection received:\s+host=(?<host>\S+)(?:\s+port=(?<port>\d+))?$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex ConnectionAuthenticatedRegex = new(
            @"^connection authenticated:\s+identity=""(?<identity>[^""]+)""\s+method=(?<method>[^\s]+)\s+\((?<auth_file>.*?):(?<auth_line>\d+)\)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex ConnectionAuthorizedRegex = new(
            @"^connection authorized:\s+user=(?<user>[^\s]+)\s+database=(?<database>[^\s]+)(?:\s+application_name=(?<application_name>.+))?$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex DisconnectionRegex = new(
            @"^disconnection:\s+session time:\s+(?<session_time>\S+)\s+user=(?<user>[^\s]+)\s+database=(?<database>[^\s]+)\s+host=(?<host>\S+)(?:\s+port=(?<port>\d+))?$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        /// <summary>Fast check — does this line start a new log entry?</summary>
        public static bool LooksLikeHeader(string line) => HeaderRegex.IsMatch(line);

        public static bool TryParse(string line, out PgLogEntry? entry)
        {
            entry = null;

            var headerMatch = HeaderRegex.Match(line);
            if (!headerMatch.Success)
                return false;

            var tsStr = headerMatch.Groups["ts"].Value;
            var tzStr = headerMatch.Groups["tz"].Value;

            if (!DateTime.TryParseExact(tsStr, "yyyy-MM-dd HH:mm:ss.fff",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                return false;

            var timestamp = ResolveTimestamp(dt, tzStr);
            var message   = headerMatch.Groups["message"].Value;

            entry = new PgLogEntry
            {
                Timestamp = timestamp,
                ProcessId = headerMatch.Groups["pid"].Value,
                Severity  = headerMatch.Groups["severity"].Value,
                Message   = message,
                Type      = PgLogLineType.General
            };

            ParseTypedMessage(message, entry);
            return true;
        }

        private static DateTimeOffset ResolveTimestamp(DateTime dt, string tz)
        {
            if (tz.Equals("UTC", StringComparison.OrdinalIgnoreCase))
                return new DateTimeOffset(dt, TimeSpan.Zero);

            // +HH:MM or -HH:MM offset
            if (tz.Length >= 5 && (tz[0] == '+' || tz[0] == '-') &&
                TimeSpan.TryParseExact(tz[1..], @"hh\:mm", CultureInfo.InvariantCulture, out var tsOffset))
            {
                var offset = tz[0] == '+' ? tsOffset : tsOffset.Negate();
                return new DateTimeOffset(dt, offset);
            }

            // IANA / Windows timezone name
            if (TimeZoneInfo.TryFindSystemTimeZoneById(tz, out var tzi))
                return new DateTimeOffset(dt, tzi.GetUtcOffset(dt));

            // Unknown timezone — assume UTC, don't drop the entry
            return new DateTimeOffset(dt, TimeSpan.Zero);
        }

        private static void ParseTypedMessage(string message, PgLogEntry entry)
        {
            Match m;

            m = StatementRegex.Match(message);
            if (m.Success)
            {
                entry.Type    = PgLogLineType.Statement;
                entry.Message = m.Groups["statement"].Value;
                return;
            }

            m = DurationRegex.Match(message);
            if (m.Success)
            {
                entry.Type      = PgLogLineType.Duration;
                entry.DurationMs = ParseNullableDouble(m.Groups["duration_ms"].Value);
                entry.Message   = m.Groups["detail"].Success ? m.Groups["detail"].Value : "duration";
                return;
            }

            m = ConnectionReceivedRegex.Match(message);
            if (m.Success)
            {
                entry.Type = PgLogLineType.ConnectionReceived;
                entry.Host = m.Groups["host"].Value;
                entry.Port = ParseNullableInt(m.Groups["port"].Value);
                return;
            }

            m = ConnectionAuthenticatedRegex.Match(message);
            if (m.Success)
            {
                entry.Type     = PgLogLineType.ConnectionAuthenticated;
                entry.Identity = m.Groups["identity"].Value;
                entry.Method   = m.Groups["method"].Value;
                entry.AuthFile = m.Groups["auth_file"].Value;
                entry.AuthLine = ParseNullableInt(m.Groups["auth_line"].Value);
                return;
            }

            m = ConnectionAuthorizedRegex.Match(message);
            if (m.Success)
            {
                entry.Type            = PgLogLineType.ConnectionAuthorized;
                entry.User            = m.Groups["user"].Value;
                entry.Database        = m.Groups["database"].Value;
                entry.ApplicationName = m.Groups["application_name"].Value;
                return;
            }

            m = DisconnectionRegex.Match(message);
            if (m.Success)
            {
                entry.Type        = PgLogLineType.Disconnection;
                entry.SessionTime = m.Groups["session_time"].Value;
                entry.User        = m.Groups["user"].Value;
                entry.Database    = m.Groups["database"].Value;
                entry.Host        = m.Groups["host"].Value;
                entry.Port        = ParseNullableInt(m.Groups["port"].Value);
            }
        }

        private static double? ParseNullableDouble(string value)
        {
            if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var result))
                return result;
            return null;
        }

        private static int? ParseNullableInt(string value)
        {
            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
                return result;
            return null;
        }
    }
}
