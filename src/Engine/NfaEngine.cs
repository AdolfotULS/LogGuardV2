using System.Collections.Generic;
using System.Linq;
using LogGuardV2.src.Model;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Runs substring NFA matching on a token stream.
    /// At each step the start states are re-added so any substring
    /// matching the automaton is detected, not just full-string matches.
    /// </summary>
    public sealed class NfaEngine
    {
        public string ProfileId   { get; }
        public string ProfileName { get; }
        public string ThreatType  { get; }
        public string Severity    { get; }

        private readonly HashSet<string> _startStates;
        private readonly HashSet<string> _acceptStates;
        // _delta[fromState][symbol] = list of toStates
        private readonly Dictionary<string, Dictionary<string, List<string>>> _delta;

        public IReadOnlyList<string> RequireAbsentTokens { get; }

        public NfaEngine(NFAModule.AutomatonProfile profile)
        {
            ProfileId   = profile.ProfileId;
            ProfileName = profile.Name;
            ThreatType  = profile.ThreatType;

            _startStates  = profile.States.Where(s => s.IsStart).Select(s => s.Id).ToHashSet();
            _acceptStates = profile.States.Where(s => s.IsAccept).Select(s => s.Id).ToHashSet();

            _delta = new();
            foreach (var t in profile.Transitions)
            {
                if (!_delta.TryGetValue(t.From, out var bySymbol))
                    _delta[t.From] = bySymbol = new();
                if (!bySymbol.TryGetValue(t.Symbol, out var tos))
                    bySymbol[t.Symbol] = tos = new();
                tos.Add(t.To);
            }

            RequireAbsentTokens = profile.RequireAbsentTokens.AsReadOnly();
            Severity            = profile.Metadata.Severity;
        }

        /// <summary>
        /// Returns true if the token stream contains a substring accepted by this NFA.
        /// Accepts IReadOnlyList so callers can pass a materialized list without boxing.
        /// </summary>
        public bool Run(IReadOnlyList<string> tokens)
        {
            var active = new HashSet<string>(_startStates);
            var next   = new HashSet<string>(_startStates.Count + 4);

            for (int i = 0; i < tokens.Count; i++)
            {
                var token = tokens[i];
                next.Clear();
                next.UnionWith(_startStates);

                foreach (var state in active)
                {
                    if (!_delta.TryGetValue(state, out var bySymbol)) continue;
                    if (!bySymbol.TryGetValue(token, out var tos))    continue;
                    foreach (var s in tos) next.Add(s);
                }

                (active, next) = (next, active);

                if (active.Overlaps(_acceptStates))
                    return true;
            }

            return false;
        }
    }
}
