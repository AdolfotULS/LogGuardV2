using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using LogGuardV2.src.Model;

namespace LogGuardV2.src.Engine
{
    public static class NfaLoader
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true
        };

        /// <summary>Loads all enabled *.json automaton profiles from <paramref name="folder"/>.</summary>
        public static List<NfaEngine> LoadAll(string folder)
        {
            var engines = new List<NfaEngine>();
            if (!Directory.Exists(folder)) return engines;

            foreach (var file in Directory.GetFiles(folder, "*.json"))
            {
                try
                {
                    var json    = File.ReadAllText(file);
                    var profile = JsonSerializer.Deserialize<NFAModule.AutomatonProfile>(json, JsonOpts);
                    if (profile?.Enabled == true)
                        engines.Add(new NfaEngine(profile));
                }
                catch
                {
                    // Skip malformed profile files
                }
            }

            return engines;
        }
    }
}
