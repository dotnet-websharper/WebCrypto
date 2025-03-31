# WebSharper WebCrypto API Binding

This repository provides an F# [WebSharper](https://websharper.com/) binding for the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), enabling WebSharper applications to perform cryptographic operations such as encryption, decryption, hashing, and key generation.

## Repository Structure

The repository consists of two main projects:

1. **Binding Project**:

   - Contains the F# WebSharper binding for the WebCrypto API.

2. **Sample Project**:
   - Demonstrates how to use the WebCrypto API with WebSharper syntax.
   - Includes a GitHub Pages demo: [View Demo](https://dotnet-websharper.github.io/WebCrypto/).

## Installation

To use this package in your WebSharper project, add the NuGet package:

```bash
   dotnet add package WebSharper.WebCrypto
```

## Building

### Prerequisites

- [.NET SDK](https://dotnet.microsoft.com/download) installed on your machine.

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/dotnet-websharper/WebCrypto.git
   cd WebCrypto
   ```

2. Build the Binding Project:

   ```bash
   dotnet build WebSharper.WebCrypto/WebSharper.WebCrypto.fsproj
   ```

3. Build and Run the Sample Project:

   ```bash
   cd WebSharper.WebCrypto.Sample
   dotnet build
   dotnet run
   ```

4. Open the hosted demo to see the Sample project in action:
   [https://dotnet-websharper.github.io/WebCrypto/](https://dotnet-websharper.github.io/WebCrypto/)

## Example Usage

Below is an example of how to use the WebCrypto API in a WebSharper project:

```fsharp
namespace WebSharper.WebCrypto.Sample

open WebSharper
open WebSharper.JavaScript
open WebSharper.UI
open WebSharper.UI.Client
open WebSharper.UI.Templating
open WebSharper.WebCrypto

[<JavaScript>]
module Client =
    // The templates are loaded from the DOM, so you just can edit index.html
    // and refresh your browser, no need to recompile unless you add or remove holes.
    type IndexTemplate = Template<"wwwroot/index.html", ClientLoad.FromDocument>

    // Variable to store user input password
    let passwordInput = Var.Create ""
    // Variable to store the resulting hashed password
    let hashedPassword = Var.Create "Waiting for input..."

    // Access the Crypto object to interact with Web Crypto API
    let crypto = JS.Window.Crypto |> As<Crypto>

    // Function to hash a password using SHA-256
    let hashPassword () =
        promise {
            let password = passwordInput.Value
            let encoder = JS.Eval("new TextEncoder()")
            // Encode the password into a Uint8Array
            let data = encoder?encode(password) |> As<Uint8Array>

            // Compute SHA-256 hash of the password
            let! hashBuffer = crypto.Subtle.Digest("SHA-256", data)

            // Convert the hash buffer into a Uint8Array
            let hashArray = Uint8Array(hashBuffer)
            printfn($"{hashArray}")

            // Convert the buffer to a hexadecimal string
            let hexString =
                Seq.init hashArray.Length (fun i -> hashArray.Get(i))
                |> Seq.map (fun byte -> sprintf "%02x" byte)  // Convert to 2-char hex
                |> String.concat ""

            // Update the UI with the hashed password
            hashedPassword.Value <- $"Hashed: {hexString}"
        }

    [<SPAEntryPoint>]
    let Main () =

        IndexTemplate.Main()
            // Bind user input to password variable
            .Password(passwordInput)
            // Bind the hashing function to the button click
            .HashPassword(fun _ ->
                async {
                    do! hashPassword() |> Promise.AsAsync
                }
                |> Async.StartImmediate
            )
            // Display the hashed password in the UI
            .HashedPassword(hashedPassword.V)
            .Doc()
        |> Doc.RunById "main"
```

This example demonstrates how to hash a user-entered password using SHA-256 with the WebCrypto API in WebSharper.

## Important Considerations

- **Security Best Practices**: Always use secure key storage and avoid exposing cryptographic keys in client-side code.
- **Browser Support**: Some older browsers may not fully support the WebCrypto API; check [MDN WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for compatibility details.
- **Performance**: The WebCrypto API is optimized for performance and is significantly faster than JavaScript-based cryptographic libraries.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE.md) file for details.

## Acknowledgments

Special thanks to the WebSharper team and contributors for their efforts in enabling seamless integration of APIs into F# projects.
