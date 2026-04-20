using System;
using System.Collections.Generic;
using System.Text;

namespace LogGuardV2.src.Model
{
    internal class NFAModule
    {
        public sealed class AutomatonProfile
        {
            public string ProfileId { get; init; } = "";
            public string Name { get; init; } = "";
            public string Version { get; init; } = "";
            public bool Enabled { get; init; }
            public string ThreatType { get; init; } = "";
            public TargetDefinition Target { get; init; } = new();
            public List<string> Alphabet { get; init; } = new();
            public List<StateDefinition> States { get; init; } = new();
            public List<TransitionDefinition> Transitions { get; init; } = new();
            public MetadataDefinition Metadata { get; init; } = new();
        }

        public sealed class TargetDefinition
        {
            public string Source { get; init; } = "";
            public string InputField { get; init; } = "";
            public string Tokenizer { get; init; } = "";
        }

        public sealed class StateDefinition
        {
            public string Id { get; init; } = "";
            public bool IsStart { get; init; }
            public bool IsAccept { get; init; }
        }

        public sealed class TransitionDefinition
        {
            public string From { get; init; } = "";
            public string Symbol { get; init; } = "";
            public string To { get; init; } = "";
        }

        public sealed class MetadataDefinition
        {
            public string Severity { get; init; } = "";
            public string Description { get; init; } = "";
            public List<string> Tags { get; init; } = new();
        }
    }
}
