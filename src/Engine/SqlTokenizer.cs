using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace LogGuardV2.src.Engine
{
    public static class SqlTokenizer
    {
        // Match `1=1` or `'abc'='abc'` — tautology patterns
        private static readonly Regex TautologyNum = new(
            @"\b(\d+)\s*=\s*\1\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex TautologyStr = new(
            @"'([^']*)'\s*=\s*'\1'",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Order matters: comments and strings before keywords and symbols
        private static readonly Regex TokenRegex = new(
            @"--[^\r\n]*|/\*[\s\S]*?\*/|'[^']*'|__TAUTO__|\b(?:SELECT|UNION|OR|AND|WHERE|FROM|ALTER|USER|WITH|GRANT|SUPERUSER|ROLE|TO|LIMIT)\b|\*|=|\w+",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static IEnumerable<string> Tokenize(string sql)
        {
            sql = TautologyNum.Replace(sql, " __TAUTO__ ");
            sql = TautologyStr.Replace(sql, " __TAUTO__ ");

            foreach (Match m in TokenRegex.Matches(sql))
            {
                var tok = m.Value;

                if (tok == "__TAUTO__")             { yield return "TAUTOLOGY"; continue; }
                if (tok.StartsWith("--") ||
                    tok.StartsWith("/*"))           { yield return "COMMENT";   continue; }
                if (tok.StartsWith("'"))            { yield return "STRING";    continue; }
                if (tok == "*")                     { yield return "STAR";      continue; }
                if (tok == "=")                     { yield return "EQUALS";    continue; }

                yield return tok.ToUpperInvariant() switch
                {
                    "SELECT"    => "SELECT",
                    "UNION"     => "UNION",
                    "OR"        => "OR",
                    "AND"       => "AND",
                    "WHERE"     => "WHERE",
                    "FROM"      => "FROM",
                    "ALTER"     => "ALTER",
                    "USER"      => "USER",
                    "WITH"      => "WITH",
                    "GRANT"     => "GRANT",
                    "SUPERUSER" => "SUPERUSER",
                    "ROLE"      => "ROLE",
                    "TO"        => "TO",
                    "LIMIT"     => "LIMIT",
                    _           => "IDENT"
                };
            }
        }
    }
}
