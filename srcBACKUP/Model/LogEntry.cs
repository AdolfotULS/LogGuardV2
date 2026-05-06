namespace LogGuardV2.src.Model
{
    public class LogEntry
    {
        public string Timestamp  { get; set; } = "";
        public int    Pid        { get; set; }
        public string Level      { get; set; } = "";
        public string UserHost   { get; set; } = "";
        public string Database   { get; set; } = "";
        public string Query      { get; set; } = "";
        public double Duration   { get; set; }
        public bool   IsInjected { get; set; }
        public string ThreatType { get; set; } = "";
    }
}
