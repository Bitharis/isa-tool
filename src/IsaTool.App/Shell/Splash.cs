using System.Reflection;

namespace IsaTool.App.Shell;

/// <summary>Startup banner; skipped when output is redirected or --no-splash is given.</summary>
public static class Splash
{
    /// <summary>Gets the application's short slogan.</summary>
    public const string Tagline = "see everything. trust nothing.";

    private static readonly string[][] IsaLetters =
    [
        [" ___ ", "|_ _|", " | | ", " | | ", "|___|"],
        [" ____  ", "/ ___| ", @"\___ \ ", " ___) |", "|____/ "],
        ["    _    ", @"   / \   ", @"  / _ \  ", @" / ___ \ ", @"/_/   \_\"],
    ];

    private static readonly string[][] ToolLetters =
    [
        [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
        ["  ___  ", @" / _ \ ", "| | | |", "| |_| |", @" \___/ "],
        ["  ___  ", @" / _ \ ", "| | | |", "| |_| |", @" \___/ "],
        [" _     ", "| |    ", "| |    ", "| |___ ", "|_____|"],
    ];

    private static readonly string[] Left = Join(IsaLetters);
    private static readonly string[] Right = Join(ToolLetters);

    /// <summary>Gets the rendered ASCII logo lines.</summary>
    public static IReadOnlyList<string> LogoLines { get; } = [.. Left.Zip(Right, (l, r) => l + r)];

    /// <summary>Displays the startup banner unless it has been disabled or no interactive console is available.</summary>
    public static void Show(string[] args)
    {
        if (args.Contains("--no-splash") || Console.IsOutputRedirected || Console.IsInputRedirected)
        {
            return;
        }

        try
        {
            Console.Clear();
            Console.WriteLine();
            for (var i = 0; i < Left.Length; i++)
            {
                Console.Write("  ");
                Write(Left[i], ConsoleColor.Cyan);
                Write(Right[i], ConsoleColor.Green);
                Console.WriteLine();
            }

            var rule = new string('=', LogoLines[0].Length);
            Console.WriteLine();
            WriteLine("  " + rule, ConsoleColor.DarkGray);
            WriteLine("  " + Tagline, ConsoleColor.Yellow);
            WriteLine($"  troubleshooting multi-tool  |  v{Version()}  |  .NET {Environment.Version.Major}", ConsoleColor.Gray);
            WriteLine("  HTTP * DNS * TLS * ports * proxy * plugins", ConsoleColor.DarkGray);
            WriteLine("  " + rule, ConsoleColor.DarkGray);
            Console.WriteLine();
            WriteLine("  loading...  (press any key to skip)", ConsoleColor.DarkGray);

            for (var waited = 0; waited < 3000 && !Console.KeyAvailable; waited += 30)
            {
                Thread.Sleep(30);
            }

            if (Console.KeyAvailable)
            {
                Console.ReadKey(true);
            }

            Console.Clear();
        }
        catch (IOException)
        {
            // No usable console; carry on without a splash.
        }
    }

    private static string[] Join(string[][] letters) =>
        [.. Enumerable.Range(0, letters[0].Length).Select(row => string.Concat(letters.Select(l => l[row])))];

    private static string Version()
    {
        var info = typeof(Splash).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return info?.Split('+')[0] ?? "1.0.0";
    }

    private static void Write(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ResetColor();
    }

    private static void WriteLine(string text, ConsoleColor color)
    {
        Write(text, color);
        Console.WriteLine();
    }
}
