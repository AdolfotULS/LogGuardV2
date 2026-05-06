using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace LogGuardV2.src.Engine
{
    /// <summary>
    /// Converts a raw SQL string into a canonical token sequence for NFA threat detection.
    ///
    /// Pipeline:
    ///   1. Normalize  — comment fusion, hex/percent/unicode decode, dollar-quote strip
    ///   2. Tautology  — bounded-regex replacement of always-true boolean patterns
    ///   3. Scan       — state-machine tokenizer (no regex, immune to ReDoS)
    ///   4. Fuse       — multi-word token consolidation (UNION ALL, INTO OUTFILE, …)
    ///
    /// Thread-safe: all state is static read-only after startup.
    /// </summary>
    public static class SqlTokenizer
    {
        // ── Tautology regexes (all captures bounded — provably ReDoS-safe) ──────

        // N=N  e.g. 1=1, 42=42
        private static readonly Regex TautoNumEq = new(
            @"\b(\d{1,10})\s*=\s*\1\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        // N>0  e.g. 1>0, 5>0
        private static readonly Regex TautoNumGt = new(
            @"\b[1-9]\d{0,9}\s*>\s*0\b|\b0\s*<\s*[1-9]\d{0,9}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        // N<>M or N!=M (different literals — inequality always true)
        private static readonly Regex TautoNumNeq = new(
            @"\b(\d{1,10})\s*(?:<>|!=)\s*(?!\1\b)\d{1,10}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        // 'x'='x'  (same string, capture bounded to 128 chars)
        private static readonly Regex TautoStrEq = new(
            @"'([^']{0,128})'\s*=\s*'\1'",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        // a=a  (same identifier, bounded to 32 chars, no adjacent word chars)
        private static readonly Regex TautoIdentEq = new(
            @"(?<!\w)([A-Za-z_]\w{0,31})\s*=\s*\1(?!\w)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        // ── Keyword → canonical token ────────────────────────────────────────────
        private static readonly Dictionary<string, string> Keywords =
            new(160, StringComparer.OrdinalIgnoreCase)
        {
            // Internal tautology marker emitted by the normalizer
            ["__TAUTO__"]          = "TAUTOLOGY",

            // ── Query structure
            ["SELECT"]             = "SELECT",
            ["FROM"]               = "FROM",
            ["WHERE"]              = "WHERE",
            ["UNION"]              = "UNION",
            ["ALL"]                = "ALL",
            ["DISTINCT"]           = "DISTINCT",
            ["JOIN"]               = "JOIN",
            ["INNER"]              = "JOIN",
            ["OUTER"]              = "JOIN",
            ["CROSS"]              = "JOIN",
            ["LIMIT"]              = "LIMIT",
            ["OFFSET"]             = "OFFSET",
            ["ORDER"]              = "ORDER",
            ["GROUP"]              = "GROUP",
            ["BY"]                 = "BY",
            ["HAVING"]             = "HAVING",
            ["TOP"]                = "TOP",
            ["AS"]                 = "AS",
            ["ON"]                 = "ON",
            ["LEFT"]               = "LEFT",
            ["RIGHT"]              = "RIGHT",

            // ── Boolean / comparison
            ["OR"]                 = "OR",
            ["AND"]                = "AND",
            ["NOT"]                = "NOT",
            ["IN"]                 = "IN",
            ["LIKE"]               = "LIKE",
            ["ILIKE"]              = "LIKE",
            ["BETWEEN"]            = "BETWEEN",
            ["IS"]                 = "IS",
            ["NULL"]               = "NULL",
            ["EXISTS"]             = "EXISTS",
            ["ANY"]                = "ANY",
            ["SOME"]               = "ANY",

            // ── DML
            ["INSERT"]             = "INSERT",
            ["INTO"]               = "INTO",
            ["UPDATE"]             = "UPDATE",
            ["SET"]                = "SET",
            ["DELETE"]             = "DELETE",
            ["MERGE"]              = "MERGE",
            ["REPLACE"]            = "INSERT",
            ["VALUES"]             = "VALUES",
            ["RETURNING"]          = "RETURNING",

            // ── DDL
            ["CREATE"]             = "CREATE",
            ["DROP"]               = "DROP",
            ["ALTER"]              = "ALTER",
            ["TRUNCATE"]           = "TRUNCATE",
            ["RENAME"]             = "RENAME",
            ["TABLE"]              = "TABLE",
            ["INDEX"]              = "INDEX",
            ["VIEW"]               = "VIEW",
            ["DATABASE"]           = "DATABASE",
            ["SCHEMA"]             = "SCHEMA",
            ["SEQUENCE"]           = "SEQUENCE",

            // ── Execution / control
            ["EXEC"]               = "EXEC",
            ["EXECUTE"]            = "EXECUTE",
            ["CALL"]               = "EXEC",
            ["DO"]                 = "EXEC",
            ["DECLARE"]            = "DECLARE",
            ["CAST"]               = "CAST",
            ["CONVERT"]            = "CAST",
            ["WAITFOR"]            = "WAITFOR",
            ["DELAY"]              = "DELAY",
            ["SLEEP"]              = "SLEEP",
            ["PG_SLEEP"]           = "SLEEP",
            ["DBMS_PIPE"]          = "SLEEP",
            ["BENCHMARK"]          = "BENCHMARK",

            // ── Evasion / obfuscation functions
            ["CHAR"]               = "CHAR_FUNC",
            ["NCHAR"]              = "CHAR_FUNC",
            ["CHR"]                = "CHAR_FUNC",
            ["ASCII"]              = "ASCII_FUNC",
            ["ORD"]                = "ASCII_FUNC",
            ["CONCAT"]             = "CONCAT_FUNC",
            ["CONCAT_WS"]          = "CONCAT_FUNC",
            ["GROUP_CONCAT"]       = "CONCAT_FUNC",
            ["STRING_AGG"]         = "CONCAT_FUNC",
            ["HEX"]                = "HEX_FUNC",
            ["UNHEX"]              = "HEX_FUNC",
            ["TO_HEX"]             = "HEX_FUNC",
            ["ENCODE"]             = "HEX_FUNC",
            ["DECODE"]             = "HEX_FUNC",
            ["SUBSTRING"]          = "SUBSTR_FUNC",
            ["SUBSTR"]             = "SUBSTR_FUNC",
            ["SUBSTRING_INDEX"]    = "SUBSTR_FUNC",
            ["MID"]                = "SUBSTR_FUNC",
            ["LOAD_FILE"]          = "LOAD_FILE",
            ["OUTFILE"]            = "OUTFILE",
            ["DUMPFILE"]           = "OUTFILE",

            // ── Dangerous system objects / procedures
            ["XP_CMDSHELL"]        = "XP_CMDSHELL",
            ["XP_REGREAD"]         = "XP_CMDSHELL",
            ["XP_REGWRITE"]        = "XP_CMDSHELL",
            ["SP_EXECUTESQL"]      = "EXEC",
            ["OPENROWSET"]         = "XP_CMDSHELL",
            ["OPENDATASOURCE"]     = "XP_CMDSHELL",
            ["INFORMATION_SCHEMA"] = "INFORMATION_SCHEMA",
            ["PG_SHADOW"]          = "SYSTEM_TABLE",
            ["PG_USER"]            = "SYSTEM_TABLE",
            ["PG_ROLES"]           = "SYSTEM_TABLE",
            ["PG_AUTHID"]          = "SYSTEM_TABLE",
            ["SYSOBJECTS"]         = "SYSTEM_TABLE",
            ["SYSCOLUMNS"]         = "SYSTEM_TABLE",
            ["ALL_TABLES"]         = "SYSTEM_TABLE",
            ["DBA_USERS"]          = "SYSTEM_TABLE",
            ["MSysObjects"]        = "SYSTEM_TABLE",

            // ── Access control
            ["GRANT"]              = "GRANT",
            ["REVOKE"]             = "REVOKE",
            ["WITH"]               = "WITH",
            ["TO"]                 = "TO",
            ["USER"]               = "USER",
            ["ROLE"]               = "ROLE",
            ["SUPERUSER"]          = "SUPERUSER",
            ["REPLICATION"]        = "SUPERUSER",
            ["BYPASSRLS"]          = "SUPERUSER",
            ["CREATEROLE"]         = "SUPERUSER",

            // ── Version / fingerprinting
            ["VERSION"]            = "VERSION",
            ["@@VERSION"]          = "VERSION",
            ["@@SERVERNAME"]       = "VERSION",

            // ── Flow control
            ["CASE"]               = "CASE",
            ["WHEN"]               = "WHEN",
            ["THEN"]               = "THEN",
            ["ELSE"]               = "ELSE",
            ["END"]                = "END",
            ["IF"]                 = "IF",
        };

        // ── Public entry point ────────────────────────────────────────────────────

        /// <summary>
        /// Returns a materialized token list for use by multiple NFA engines.
        /// Thread-safe: no shared mutable state.
        /// </summary>
        public static List<string> Tokenize(string sql)
        {
            if (string.IsNullOrEmpty(sql)) return new List<string>(0);

            var normalized = Normalize(sql);           // phase 1: structural cleanup + encoding
            var withTauto  = MarkTautologies(normalized); // phase 2: tautology annotation
            var raw        = ScanTokens(withTauto);    // phase 3: state-machine scan
            return FuseMultiword(raw);                 // phase 4: multi-word consolidation
        }

        // ── Phase 1: Normalize ────────────────────────────────────────────────────
        //
        // Handles:
        //   - block comment fusion   SE/**/LECT    → SELECT
        //   - line comment removal   -- remark     → (space)
        //   - hex literal decode     0x53454c4543  → text
        //   - percent-encode decode  %53%45%4C     → SEL
        //   - unicode escape decode  S        → S
        //   - dollar-quote           $$text$$      → 'DOLLARSTR'
        //   - single-quote strings   'text'        → passed through for ScanTokens
        //
        // Block comments are removed WITHOUT substituting a space so that
        // deliberately split keywords (SE/*x*/LECT) are fused back together.

        private static string Normalize(string input)
        {
            var sb = new StringBuilder(input.Length);
            int i = 0, n = input.Length;

            while (i < n)
            {
                char c = input[i];

                // ── Line comment: -- ... newline ─────────────────────────────────
                if (c == '-' && i + 1 < n && input[i + 1] == '-')
                {
                    sb.Append(' ');
                    i += 2;
                    while (i < n && input[i] != '\n' && input[i] != '\r') i++;
                    continue;
                }

                // ── Block comment: /* ... */ — NO space so SE/*x*/LECT → SELECT ─
                if (c == '/' && i + 1 < n && input[i + 1] == '*')
                {
                    i += 2;
                    int depth = 1;
                    while (i + 1 < n && depth > 0)
                    {
                        if (input[i] == '/' && input[i + 1] == '*') { depth++; i += 2; }
                        else if (input[i] == '*' && input[i + 1] == '/') { depth--; i += 2; }
                        else i++;
                    }
                    continue;
                }

                // ── Hex literal: 0xHH... → decoded ASCII (limit 256 bytes) ──────
                if (c == '0' && i + 1 < n && (input[i + 1] == 'x' || input[i + 1] == 'X'))
                {
                    int j = i + 2;
                    while (j < n && IsHexChar(input[j])) j++;
                    int hexLen = j - (i + 2);
                    if (hexLen >= 2 && hexLen <= 512 && hexLen % 2 == 0)
                    {
                        sb.Append(' ');
                        for (int k = i + 2; k < j; k += 2)
                        {
                            int val = (HexVal(input[k]) << 4) | HexVal(input[k + 1]);
                            if (val >= 0x20 && val < 0x7F) sb.Append((char)val);
                        }
                        sb.Append(' ');
                        i = j;
                        continue;
                    }
                    // Fall through: not a decodable hex literal
                }

                // ── Single-quoted string: copy verbatim (ScanTokens handles it) ─
                if (c == '\'')
                {
                    sb.Append(c); i++;
                    while (i < n)
                    {
                        char s = input[i]; sb.Append(s); i++;
                        if (s != '\'') continue;
                        if (i < n && input[i] == '\'') { sb.Append('\''); i++; } // '' escape
                        else break;
                    }
                    continue;
                }

                // ── Dollar-quoted string (PostgreSQL): $$...$$, $tag$...$tag$ ───
                if (c == '$')
                {
                    int j = i + 1;
                    while (j < n && input[j] != '$' && (char.IsLetterOrDigit(input[j]) || input[j] == '_')) j++;
                    if (j < n && input[j] == '$')
                    {
                        string tag      = input.Substring(i, j - i + 1);
                        int    bodyStart = j + 1;
                        int    closeIdx  = input.IndexOf(tag, bodyStart, StringComparison.Ordinal);
                        if (closeIdx >= 0)
                        {
                            sb.Append("'DOLLARSTR'");
                            i = closeIdx + tag.Length;
                            continue;
                        }
                    }
                    sb.Append(c); i++;
                    continue;
                }

                // ── Percent-encoded byte: %XX ────────────────────────────────────
                if (c == '%' && i + 2 < n && IsHexChar(input[i + 1]) && IsHexChar(input[i + 2]))
                {
                    int val = (HexVal(input[i + 1]) << 4) | HexVal(input[i + 2]);
                    sb.Append(val >= 0x20 && val < 0x7F ? (char)val : ' ');
                    i += 3;
                    continue;
                }

                // ── Unicode escape: \uXXXX ───────────────────────────────────────
                if (c == '\\' && i + 5 < n && input[i + 1] == 'u'
                    && IsHexChar(input[i + 2]) && IsHexChar(input[i + 3])
                    && IsHexChar(input[i + 4]) && IsHexChar(input[i + 5]))
                {
                    int cp = (HexVal(input[i + 2]) << 12) | (HexVal(input[i + 3]) << 8)
                           | (HexVal(input[i + 4]) << 4)  |  HexVal(input[i + 5]);
                    sb.Append(cp >= 0x20 && cp < 0x7F ? (char)cp : ' ');
                    i += 6;
                    continue;
                }

                sb.Append(c); i++;
            }

            return sb.ToString();
        }

        // ── Phase 2: Tautology annotation ────────────────────────────────────────

        private static string MarkTautologies(string sql)
        {
            // Apply in specificity order; each pass works on the previous result.
            // All patterns are bounded — no catastrophic backtracking.
            sql = TautoStrEq.Replace(sql, " __TAUTO__ ");    // 'x'='x'
            sql = TautoNumEq.Replace(sql, " __TAUTO__ ");    // 1=1
            sql = TautoNumNeq.Replace(sql, " __TAUTO__ ");   // 1<>2, 1!=2
            sql = TautoNumGt.Replace(sql, " __TAUTO__ ");    // 1>0
            sql = TautoIdentEq.Replace(sql, " __TAUTO__ ");  // a=a
            return sql;
        }

        // ── Phase 3: State-machine token scanner ──────────────────────────────────
        //
        // No regex — immune to ReDoS regardless of input length or content.
        // Single allocation pass: pre-sized list, Substring only for word extraction.

        private static List<string> ScanTokens(string input)
        {
            var tokens = new List<string>(64);
            int i = 0, n = input.Length;

            while (i < n)
            {
                char c = input[i];

                // Skip whitespace
                if (char.IsWhiteSpace(c)) { i++; continue; }

                // Identifier or keyword (letter, underscore, or @@ for system vars)
                if (char.IsLetter(c) || c == '_' || (c == '@' && i + 1 < n && input[i + 1] == '@'))
                {
                    int start = i;
                    if (c == '@') i += 2; // skip @@
                    while (i < n && (char.IsLetterOrDigit(input[i]) || input[i] == '_')) i++;
                    var word = input.Substring(start, i - start);
                    tokens.Add(Keywords.TryGetValue(word, out var kw) ? kw : "IDENT");
                    continue;
                }

                // Number — emit NUMBER (tautologies already replaced before this phase)
                if (char.IsDigit(c))
                {
                    while (i < n && (char.IsDigit(input[i]) || input[i] == '.')) i++;
                    tokens.Add("NUMBER");
                    continue;
                }

                // Single-quoted string
                if (c == '\'')
                {
                    i++;
                    while (i < n)
                    {
                        char s = input[i]; i++;
                        if (s != '\'') continue;
                        if (i < n && input[i] == '\'') { i++; continue; } // '' escape
                        break;
                    }
                    tokens.Add("STRING");
                    continue;
                }

                // Operators and structural punctuation
                switch (c)
                {
                    case '*': tokens.Add("STAR");      i++; break;
                    case '=': tokens.Add("EQUALS");    i++; break;
                    case '(': tokens.Add("LPAREN");    i++; break;
                    case ')': tokens.Add("RPAREN");    i++; break;
                    case ';': tokens.Add("SEMICOLON"); i++; break;
                    case ',': tokens.Add("COMMA");     i++; break;

                    case '!':
                        if (i + 1 < n && input[i + 1] == '=') { tokens.Add("NEQ"); i += 2; }
                        else i++;
                        break;

                    case '<':
                        if      (i + 1 < n && input[i + 1] == '>') { tokens.Add("NEQ"); i += 2; }
                        else if (i + 1 < n && input[i + 1] == '=') { tokens.Add("LTE"); i += 2; }
                        else { tokens.Add("LT"); i++; }
                        break;

                    case '>':
                        if (i + 1 < n && input[i + 1] == '=') { tokens.Add("GTE"); i += 2; }
                        else { tokens.Add("GT"); i++; }
                        break;

                    case '|':
                        if (i + 1 < n && input[i + 1] == '|')
                        { tokens.Add("CONCAT_OP"); i += 2; }   // PostgreSQL string concat
                        else i++;
                        break;

                    case '-':
                        // Residual line comment (Normalize should have caught it; defensive)
                        if (i + 1 < n && input[i + 1] == '-')
                        {
                            tokens.Add("COMMENT");
                            while (i < n && input[i] != '\n' && input[i] != '\r') i++;
                        }
                        else i++;
                        break;

                    case '/':
                        // Residual block comment (Normalize should have caught it; defensive)
                        if (i + 1 < n && input[i + 1] == '*')
                        {
                            tokens.Add("COMMENT");
                            i += 2;
                            while (i + 1 < n && !(input[i] == '*' && input[i + 1] == '/')) i++;
                            if (i + 1 < n) i += 2;
                        }
                        else i++;
                        break;

                    default: i++; break;
                }
            }

            return tokens;
        }

        // ── Phase 4: Multi-word token fusion ──────────────────────────────────────

        private static List<string> FuseMultiword(List<string> tokens)
        {
            int count = tokens.Count;
            if (count < 2) return tokens;

            var result = new List<string>(count);
            for (int i = 0; i < count; i++)
            {
                var cur  = tokens[i];
                var next = i + 1 < count ? tokens[i + 1] : null;

                switch (cur)
                {
                    case "UNION"   when next == "ALL":     result.Add("UNION_ALL");      i++; break;
                    case "INTO"    when next == "OUTFILE":  result.Add("INTO_OUTFILE");   i++; break;
                    case "INTO"    when next == "DUMPFILE": result.Add("INTO_OUTFILE");   i++; break;
                    case "WAITFOR" when next == "DELAY":   result.Add("WAITFOR_DELAY");  i++; break;
                    case "EXEC"    when next == "LPAREN":   result.Add("EXEC");           break; // keep both
                    default: result.Add(cur); break;
                }
            }

            return result;
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        private static bool IsHexChar(char c)
            => (uint)(c - '0') <= 9 || (uint)(c - 'a') <= 5 || (uint)(c - 'A') <= 5;

        private static int HexVal(char c)
        {
            if ((uint)(c - '0') <= 9) return c - '0';
            if ((uint)(c - 'a') <= 5) return c - 'a' + 10;
            if ((uint)(c - 'A') <= 5) return c - 'A' + 10;
            return 0;
        }
    }
}