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

        // Campos comunes/opcionales
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
        {
            return $"[{Type}] Ts={Timestamp:O}, Pid={ProcessId}, Severity={Severity}, Message={Message}";
        }
    }

    public static class PostgreSqlLogParser
    {
        // Cabecera común:
        // 2026-04-19 02:52:36.760 UTC [34] LOG:  connection authorized: ...
        private static readonly Regex HeaderRegex = new(
            @"^(?<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\w+)\s+\[(?<pid>\d+)\]\s+(?<severity>[A-Z]+):\s{1,}(?<message>[\s\S]*)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex StatementRegex = new(
            @"^statement:\s*(?<statement>[\s\S]*)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex DurationRegex = new(
            @"^duration:\s*(?<duration_ms>\d+(?:\.\d+)?)\s+ms(?:\s+(?<detail>.*))?$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex ConnectionReceivedRegex = new(
            @"^connection received:\s+host=(?<host>\S+)\s+port=(?<port>\d+)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex ConnectionAuthenticatedRegex = new(
            @"^connection authenticated:\s+identity=""(?<identity>[^""]+)""\s+method=(?<method>[^\s]+)\s+\((?<auth_file>.*?):(?<auth_line>\d+)\)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex ConnectionAuthorizedRegex = new(
            @"^connection authorized:\s+user=(?<user>[^\s]+)\s+database=(?<database>[^\s]+)\s+application_name=(?<application_name>.+)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private static readonly Regex DisconnectionRegex = new(
            @"^disconnection:\s+session time:\s+(?<session_time>\S+)\s+user=(?<user>[^\s]+)\s+database=(?<database>[^\s]+)\s+host=(?<host>\S+)\s+port=(?<port>\d+)$",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static bool TryParse(string line, out PgLogEntry? entry)
        {
            entry = null;

            var headerMatch = HeaderRegex.Match(line);
            if (!headerMatch.Success)
                return false;

            if (!DateTimeOffset.TryParseExact(
                    headerMatch.Groups["timestamp"].Value,
                    "yyyy-MM-dd HH:mm:ss.fff 'UTC'",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal,
                    out var timestamp))
            {
                return false;
            }

            var message = headerMatch.Groups["message"].Value;

            entry = new PgLogEntry
            {
                Timestamp = timestamp,
                ProcessId = headerMatch.Groups["pid"].Value,
                Severity = headerMatch.Groups["severity"].Value,
                Message = message,
                Type = PgLogLineType.General
            };

            ParseTypedMessage(message, entry);
            return true;
        }

        private static void ParseTypedMessage(string message, PgLogEntry entry)
        {
            Match m;

            m = StatementRegex.Match(message);
            if (m.Success)
            {
                entry.Type = PgLogLineType.Statement;
                entry.Message = m.Groups["statement"].Value;
                return;
            }

            m = DurationRegex.Match(message);
            if (m.Success)
            {
                entry.Type = PgLogLineType.Duration;
                entry.DurationMs = ParseNullableDouble(m.Groups["duration_ms"].Value);
                entry.Message = m.Groups["detail"].Success
                    ? m.Groups["detail"].Value
                    : "duration";
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
                entry.Type = PgLogLineType.ConnectionAuthenticated;
                entry.Identity = m.Groups["identity"].Value;
                entry.Method = m.Groups["method"].Value;
                entry.AuthFile = m.Groups["auth_file"].Value;
                entry.AuthLine = ParseNullableInt(m.Groups["auth_line"].Value);
                return;
            }

            m = ConnectionAuthorizedRegex.Match(message);
            if (m.Success)
            {
                entry.Type = PgLogLineType.ConnectionAuthorized;
                entry.User = m.Groups["user"].Value;
                entry.Database = m.Groups["database"].Value;
                entry.ApplicationName = m.Groups["application_name"].Value;
                return;
            }

            m = DisconnectionRegex.Match(message);
            if (m.Success)
            {
                entry.Type = PgLogLineType.Disconnection;
                entry.SessionTime = m.Groups["session_time"].Value;
                entry.User = m.Groups["user"].Value;
                entry.Database = m.Groups["database"].Value;
                entry.Host = m.Groups["host"].Value;
                entry.Port = ParseNullableInt(m.Groups["port"].Value);
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
