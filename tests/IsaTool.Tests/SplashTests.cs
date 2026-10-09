using IsaTool.App.Shell;

namespace IsaTool.Tests;

/// <summary>Tests splash-screen rendering and opt-out behavior.</summary>
public class SplashTests
{
    [Fact]
    public void Logo_IsRectangularAsciiThatFitsAnEightyColumnTerminal()
    {
        var lines = Splash.LogoLines;

        Assert.Equal(5, lines.Count);
        Assert.Single(lines.Select(l => l.Length).Distinct());
        Assert.InRange(lines[0].Length, 1, 70);
        Assert.All(lines, l => Assert.All(l, c => Assert.InRange(c, ' ', '~')));
    }

    [Fact]
    public void Show_DoesNothingWhenOptedOut() => Splash.Show(["--no-splash"]);
}
