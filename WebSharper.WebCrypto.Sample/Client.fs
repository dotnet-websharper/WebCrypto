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

    let passwordInput = Var.Create ""
    let hashedPassword = Var.Create "Waiting for input..."

    let crypto = JS.Window.Crypto |> As<Crypto>
    
    let hashPassword () =
        promise {
            let password = passwordInput.Value
            let encoder = JS.Eval("new TextEncoder()")
            let data = encoder?encode(password) |> As<Uint8Array>

            let! hashBuffer = crypto.Subtle.Digest("SHA-256", data)

            let hashArray = Uint8Array(hashBuffer)
            printfn($"{hashArray}")

            // Convert the buffer to a hexadecimal string
            let hexString =
                Seq.init hashArray.Length (fun i -> hashArray.Get(i))
                |> Seq.map (fun byte -> sprintf "%02x" byte)  // Convert to 2-char hex
                |> String.concat ""

            hashedPassword.Value <- $"Hashed: {hexString}"
        }

    [<SPAEntryPoint>]
    let Main () =

        IndexTemplate.Main()
            .Password(passwordInput)
            .HashPassword(fun _ -> 
                async { 
                    do! hashPassword() |> Promise.AsAsync 
                } 
                |> Async.StartImmediate
            )
            .HashedPassword(hashedPassword.V)
            .Doc()
        |> Doc.RunById "main"
