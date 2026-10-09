# IsaTool

```text
 ___  ____      _     _____   ___    ___   _
|_ _|/ ___|    / \   |_   _| / _ \  / _ \ | |
 | | \___ \   / _ \    | |  | | | || | | || |
 | |  ___) | / ___ \   | |  | |_| || |_| || |___
|___||____/ /_/   \_\  |_|   \___/  \___/ |_____|
=================================================
 see everything. trust nothing.
=================================================
```

Cross-platform (Windows and Linux) terminal UI multi-tool for troubleshooting software and web services. Built on .NET 10 and Terminal.Gui. Small, readable code with few dependencies (Terminal.Gui, DnsClient).

## Build and run

Requires the .NET 10 SDK.

```
dotnet run --project src/IsaTool.App
dotnet test IsaTool.slnx
```

Self-contained single-file binaries:

```
dotnet publish src/IsaTool.App -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o out/linux-x64
dotnet publish src/IsaTool.App -c Release -r win-x64   --self-contained -p:PublishSingleFile=true -o out/win-x64
```

The binary is named `isatool`.

## Using it

Pick a tool from the list on the left (Up/Down). Press Tab to enter the right pane, Shift+Tab to return to the list, or F6 to switch panes directly. Inside the right pane, Tab moves between fields and buttons; Enter presses a button. Ctrl+Q quits. The in-app **Help** entry has the same reference.

| Tool | Purpose |
|---|---|
| HTTP client | Request with method, headers, body; shows redirect chain, timing, headers, body |
| DNS lookup | A, AAAA, CNAME, MX, NS, TXT, SOA, PTR against system or a chosen DNS server |
| TLS certificate | Chain, validity/expiry, SANs, protocol, cipher, chain errors |
| Port scan | TCP connect scan, e.g. `22,80,443,8000-8100` |
| Ping / traceroute | ICMP ping and TTL-based traceroute (no root needed) |
| Log viewer | Tail a file, text or regex filter, follow mode |
| Processes | Live process list sorted by CPU or memory |
| Health monitor | Periodic HTTP checks of several URLs, uptime percentage |
| Decoders | JSON formatter, JWT decoder (no signature verification), Base64 |
| Intercepting proxy | Loopback HTTP/HTTPS proxy that decrypts and records traffic (see below) |
| Assessment | Save named scopes, run basic checks, compare results and export reports |

### Assessments

Enter an assessment name and exact hosts or full `http://` / `https://` URLs, separated by semicolons. Wildcards and network ranges are rejected. You can optionally list specific TCP ports to check; no ports are scanned unless you enter them. Type exactly `I AM AUTHORIZED` before running.

Checks include DNS resolution, TLS certificate trust and expiry for HTTPS targets, common website security headers and cookie settings, and the TCP ports you chose. These checks are basic signals, not proof that a system is secure or vulnerable. Missing headers may be appropriate for some services, so review evidence in context.

Scopes and up to 500 results are saved locally in `assessments.json` under the IsaTool user settings folder. Type a saved assessment's name and choose **Load saved** to restore its targets and ports; you must confirm authorization again before running. Choose **Compare previous** to see findings that appeared or disappeared. **Export JSON** or **Export HTML** saves the latest result to the path in **Report file**. Reports can contain internal host names and findings; store and share them carefully.

### Intercepting proxy

1. Press **CA info / install help**. A local root CA is generated in the user config directory (`IsaTool/proxy-ca`), named `IsaTool Debug Proxy CA - REMOVE WHEN DONE`. Leaf certificates it issues are named `... O=IsaTool Debug Proxy (generated)` and last 7 days.
2. Install the CA where the client you are testing trusts it, using the commands shown (Windows, Debian/Ubuntu, RHEL, or per-process options such as `curl --cacert` and `NODE_EXTRA_CA_CERTS`).
3. **Start proxy**, then point the client at `127.0.0.1:8888` (for example `HTTPS_PROXY=http://127.0.0.1:8888`).
4. Captured flows are listed live; enter a number in **Flow #** and press **Show flow** for headers and the decoded body (gzip/deflate/br, JSON pretty-printed).
   - **Capture filters** (applied on Start): *Only hosts* and *Ignore hosts* take comma-separated patterns such as `api.corp.com, *.corp.com` (`*.corp.com` does not match `corp.com`). Hosts that don't qualify are tunnelled untouched: not decrypted, not recorded, and no certificate or pinning problems.
   - **View filters** (press **Apply filter**): *Search* (URL, headers, decoded bodies), *Status* (`4xx,5xx,404,err`), *Content type* (`json,xml`). Filters are saved in the settings file and restored on the next run.
5. When finished, remove the CA from the trust store (commands in the same screen), then press **Delete CA files** to destroy the private key.

#### Rewrite rules

Press **Rules file** to create `proxy-rules.json` (in the IsaTool config directory) with commented-out examples (nothing is active until you uncomment a rule), edit it, then press **Reload rules** (also applied automatically on Start). Rules apply only to captured hosts, never to tunnelled ones. Flows changed by a rule are marked `*` in the list, and the detail view lists each applied action. Mocked responses carry an `X-IsaTool-Mock` header. Invalid rules are skipped and reported.

```json
{ "rules": [
  { "name": "Add test token", "match": { "host": "api.corp.com", "path": "/v1/*", "method": "GET,POST" },
    "actions": [ { "type": "setRequestHeader", "name": "Authorization", "value": "Bearer TEST" } ] },
  { "name": "Flag 5xx", "match": { "status": "5xx" }, "actions": [ { "type": "tag", "value": "server error" } ] }
] }
```

| Phase | Actions |
|---|---|
| Request | `setRequestHeader{name,value}`, `removeRequestHeader{name}`, `replaceRequestBody{find,replace}`, `redirectHost{host[:port]}`, `mockResponse{status,body,contentType}`, `delay{ms}`, `drop` |
| Response | `setResponseHeader`, `removeResponseHeader`, `replaceResponseBody{find,replace}`, `setStatus{status}`, `delayResponse{ms}` |
| Any | `tag{value}` |

`match` fields (all optional, all must match): `host` and `path` use `*` wildcards; `method` and `status` take lists (`POST,PUT`, `4xx,503`). A rule with `status` may only use response actions and `tag`. Body replacement is plain text on UTF-8 bodies (gzip/deflate/br are decoded first and the `Content-Encoding` header is removed). `redirectHost` changes the target and the `Host` header follows it. Python scripting for logic that rules can't express is planned as a later step.
Limits: listens on loopback only; HTTP/1.1 only; bodies are buffered (no streaming or WebSocket); apps with certificate pinning will refuse the certificate (shown as a failed CONNECT). Captured traffic may contain credentials and lives in memory only.

Long-running tools stop with the Stop button or when you switch tools.

### Plugins

Plugins are compiled .NET class libraries that extend the proxy. They can modify, mock or drop requests (`IRequestHook`), modify responses (`IResponseHook`), and render bodies in the flow detail view (`IBodyDecoder`). A plugin references only `src/IsaTool.Plugins.Abstractions` and implements these interfaces in public classes with a parameterless constructor. `samples/RequestSigning` is a working example (HMAC request signing plus a form-body decoder).

1. Publish the plugin: `dotnet publish samples/RequestSigning -c Release -o RequestSigning`.
2. Copy that folder into the plugin folder shown on the **Plugins** screen (`IsaTool/plugins/` in your config directory) so you have `plugins/RequestSigning/RequestSigning.dll`. The folder name must equal the main DLL name.
3. Open **Plugins**, review the entry, and press **Allow** with its number. Allow stores the SHA-256 of every file in the folder (except `.pdb`) in `plugins/allowed-plugins.json`.
4. Start the proxy. Flows touched by a plugin are marked `*` and list the plugin in the detail view.

Safety: plugins are **not sandboxed** and run with your full user rights, including access to all decrypted traffic. Nothing loads unless you approved it; if any file in the folder changes, the plugin is refused until you press Allow again (a plugin changed while IsaTool is running requires a restart). A plugin that throws three times is disabled, and its errors are shown on the flow and on the Plugins screen. Plugins only apply to captured hosts. Hooks run synchronously inside the proxy, so keep them fast. A plugin built for a different contract major version is refused. The sample reads `ISATOOL_SIGNING_KEY` (and optionally `ISATOOL_SIGNING_HOST`) from the environment and does nothing without the key.

#### Writing your own plugin

**1. Create the project.** A class library targeting `net10.0` that references only the contracts project. `Private="false"` stops the contracts DLL being copied into your output, because IsaTool supplies its own copy.

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\IsaTool.Plugins.Abstractions\IsaTool.Plugins.Abstractions.csproj" Private="false" />
  </ItemGroup>
</Project>
```

Outside this repo, build `IsaTool.Plugins.Abstractions` and reference its DLL instead. The assembly name must stay `IsaTool.Plugins.Abstractions`.

**2. Write the plugin class.** Public, non-abstract, with a public parameterless constructor, implementing one or more interfaces. `Name` and `Description` are shown on the Plugins screen. One DLL may contain several plugin classes.

| Interface | Method | Use |
|---|---|---|
| `IRequestHook` | `RequestOutcome OnRequest(MutableRequest)` | Change the request, or return `RequestOutcome.MockWith(...)` / `RequestOutcome.DropConnection()`. Otherwise return `RequestOutcome.Continue`. |
| `IResponseHook` | `void OnResponse(MutableRequest, MutableResponse)` | Change the response before the client sees it. |
| `IBodyDecoder` | `string? TryDecode(DecoderInput)` | Return readable text for a body, or `null` if it is not yours. Bodies arrive decompressed; check `input.ContentType`. |

```csharp
using IsaTool.Plugins;

namespace MyPlugin;

public sealed class AddTraceId : IRequestHook
{
    public string Name => "Trace id";
    public string Description => "Adds X-Trace-Id to every captured request.";

    public RequestOutcome OnRequest(MutableRequest request)
    {
        request.SetHeader("X-Trace-Id", Guid.NewGuid().ToString("N"));
        return RequestOutcome.Continue;
    }
}
```

**3. Build and install.** Run `dotnet publish MyPlugin -c Release -o MyPlugin`, then copy the whole output folder into the plugin folder shown on the **Plugins** screen so you have `plugins/MyPlugin/MyPlugin.dll`. The folder name must equal the main DLL name; include any extra DLLs your plugin needs.

**4. Approve it.** Open **Plugins** and press **Refresh**; the plugin shows as `NOT ALLOWED` with its SHA-256. Review the code, enter its number in **Plugin #** and press **Allow**. Then start the proxy; flows a plugin changed are marked `*`.

Notes for development:

- After every rebuild the hash changes, so the plugin shows `CHANGED SINCE APPROVED` until you press **Allow** again. If it was already loaded in a running IsaTool, restart IsaTool as well.
- Plugins run after the rewrite rules and only on captured hosts.
- An exception in a hook is caught and shown on the flow and on the Plugins screen; after three errors the plugin is disabled.
- Hooks run synchronously inside the proxy, so keep them fast.
- A plugin built for a different contracts major version is refused with a message.
- To debug, attach your IDE to the running `isatool` process and set breakpoints in the plugin.
- Plugins are not sandboxed: only press **Allow** for code you wrote or reviewed.

## Layout

Code is organised per feature: `src/IsaTool.App/Features/<Name>/` holds the service (testable logic) and the view (UI). `src/IsaTool.Core` holds shared helpers. To add a feature, subclass `FeatureView` and add it to the list in `Program.cs`.

## Responsible use

Only scan or probe systems you own or are authorised to test.
