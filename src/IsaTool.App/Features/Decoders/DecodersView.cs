using IsaTool.App.Shell;

namespace IsaTool.App.Features.Decoders;

/// <summary>Provides interactive JSON, JWT, and Base64 decoding tools.</summary>
public sealed class DecodersView : FeatureView
{
    public DecodersView()
    {
        var input = AddField("Input");
        AddButton("Format JSON", _ => Run(() => Codecs.FormatJson(input.Text)));
        AddButtonSameRow("Decode JWT", _ => Run(() =>
        {
            var j = Codecs.DecodeJwt(input.Text);
            var exp = j.Expires is null ? "no exp claim" : $"{j.Expires:u} ({(j.Expired == true ? "EXPIRED" : "valid")})";
            return $"Header:\n{j.Header}\n\nPayload:\n{j.Payload}\n\nExpiry: {exp}\nSignature NOT verified.";
        }));
        AddButtonSameRow("Base64 enc", _ => Run(() => Codecs.Base64Encode(input.Text)));
        AddButtonSameRow("Base64 dec", _ => Run(() => Codecs.Base64Decode(input.Text)));
        Build();
    }

    /// <inheritdoc />
    public override string FeatureName => "Decoders";

    private Task Run(Func<string> work)
    {
        try
        {
            SetOutput(work());
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException or ArgumentException)
        {
            SetOutput($"ERROR: {ex.Message}");
        }

        return Task.CompletedTask;
    }
}
