namespace WebSharper.WebCrypto.Sample

open WebSharper
open WebSharper.JavaScript
open WebSharper.UI
open WebSharper.UI.Client
open WebSharper.UI.Notation
open WebSharper.UI.Templating
open WebSharper.WebCrypto

[<JavaScript>]
module Client =
    // The template is loaded from the DOM, so editing index.html and refreshing
    // the browser is enough; a rebuild is only needed when holes change.
    type IndexTemplate = Template<"wwwroot/index.html", ClientLoad.FromDocument>

    let statusMessage = Var.Create "Ready."
    let textInput = Var.Create "Hello WebSharper"
    let hashResult = Var.Create ""
    let randomResult = Var.Create ""
    let ciphertext = Var.Create ""
    let decrypted = Var.Create ""
    let uuid = Var.Create ""

    // Web Crypto is exposed on the window (and in workers). SubtleCrypto is only
    // available in a secure context (HTTPS or localhost).
    let crypto = WindowCrypto()

    let private isMissing (o: obj) =
        isNull o || o ===. JS.Undefined

    let private subtleAvailable =
        not (isMissing (box crypto.Subtle))

    let capabilities =
        if subtleAvailable then
            "SubtleCrypto is available (secure context)."
        else
            "SubtleCrypto is unavailable. Serve the page over HTTPS or from localhost."

    let private strToBuf (s: string) : Uint8Array =
        let enc : obj = JS.Eval "new TextEncoder()"
        enc?encode(s) |> As<Uint8Array>

    let private bufToStr (b: ArrayBuffer) : string =
        let dec : obj = JS.Eval "new TextDecoder()"
        dec?decode(Uint8Array(b)) |> As<string>

    let private toHex (buffer: ArrayBuffer) : string =
        let bytes = Uint8Array(buffer)
        Seq.init bytes.Length (fun i -> bytes.Get(i))
        |> Seq.map (fun b -> sprintf "%02x" b)
        |> String.concat ""

    // The AES-GCM key, IV and ciphertext are kept so that encrypt and decrypt round-trip.
    let aesKey = Var.Create<CryptoKey> (As<CryptoKey> JS.Undefined)
    let aesIv = Var.Create<Uint8Array> (As<Uint8Array> JS.Undefined)
    let aesCiphertext = Var.Create<ArrayBuffer> (As<ArrayBuffer> JS.Undefined)

    let hashText () =
        promise {
            if not subtleAvailable then
                statusMessage := "SubtleCrypto is unavailable."
            else
                try
                    let! digest = crypto.Subtle.Digest("SHA-256", strToBuf textInput.Value)
                    hashResult := toHex digest
                    statusMessage := "Computed the SHA-256 digest."
                with ex ->
                    Console.Error("Digest failed:", ex.Message)
                    statusMessage := "Hash failed: " + ex.Message
        }

    let randomValues () =
        try
            let bytes = crypto.GetRandomValues(Uint8Array(16)) |> As<Uint8Array>
            randomResult.Value <-
                "Random bytes: "
                + (Seq.init bytes.Length (fun i -> bytes.Get(i))
                   |> Seq.map (fun b -> sprintf "%02x" b)
                   |> String.concat "")
            statusMessage := "Filled a 16-byte array with cryptographically secure random values."
        with ex ->
            Console.Error("getRandomValues failed:", ex.Message)
            statusMessage := "Random generation failed: " + ex.Message

    let newUuid () =
        try
            uuid := crypto.RandomUUID()
            statusMessage := "Generated a random UUID."
        with ex ->
            Console.Error("randomUUID failed:", ex.Message)
            statusMessage := "UUID generation failed: " + ex.Message

    let encryptText () =
        promise {
            if not subtleAvailable then
                statusMessage := "SubtleCrypto is unavailable."
            else
                try
                    let usages = [| KeyUsages.Encrypt; KeyUsages.Decrypt |]
                    let! generated =
                        crypto.Subtle.GenerateKey(
                            AesKeyGenParams(name = "AES-GCM", length = 256),
                            true,
                            usages)
                    let key = generated |> As<CryptoKey>

                    // Exercise exportKey + importKey round-tripping the raw key bytes.
                    let! rawKey = crypto.Subtle.ExportKey(Format.Raw, key)
                    let rawBytes = rawKey |> As<ArrayBuffer>
                    let! imported =
                        crypto.Subtle.ImportKey(
                            Format.Raw,
                            rawBytes,
                            AesKeyGenParams(name = "AES-GCM", length = 256),
                            true,
                            usages)
                    let importedKey = imported |> As<CryptoKey>

                    let iv = crypto.GetRandomValues(Uint8Array(12)) |> As<Uint8Array>
                    let! encrypted =
                        crypto.Subtle.Encrypt(
                            AesGcmParams(name = "AES-GCM", iv = iv),
                            importedKey,
                            strToBuf textInput.Value)

                    aesKey := importedKey
                    aesIv := iv
                    aesCiphertext := encrypted
                    decrypted := ""
                    ciphertext.Value <-
                        sprintf
                            "Encrypted \"%s\" to %d byte(s) with a fresh AES-GCM-256 key (raw key %d bytes, IV %d bytes)."
                            textInput.Value
                            (Uint8Array(encrypted).Length)
                            (Uint8Array(rawBytes).Length)
                            iv.Length
                    statusMessage := "Encrypted. Press Decrypt to round-trip."
                with ex ->
                    Console.Error("Encrypt failed:", ex.Message)
                    statusMessage := "Encrypt failed: " + ex.Message
        }

    let decryptText () =
        promise {
            if isMissing (box aesKey.Value) || isMissing (box aesIv.Value) || isMissing (box aesCiphertext.Value) then
                statusMessage := "Press Encrypt first to generate a key, IV and ciphertext."
            else
                try
                    let! plain =
                        crypto.Subtle.Decrypt(
                            AesGcmParams(name = "AES-GCM", iv = aesIv.Value),
                            aesKey.Value,
                            aesCiphertext.Value)

                    decrypted := bufToStr plain
                    statusMessage := "Decrypted and recovered the original text."
                with ex ->
                    Console.Error("Decrypt failed:", ex.Message)
                    statusMessage := "Decrypt failed: " + ex.Message
        }

    [<SPAEntryPoint>]
    let Main () =
        IndexTemplate.Main()
            .hashText(fun _ -> hashText() |> ignore)
            .randomValues(fun _ -> randomValues())
            .encryptText(fun _ -> encryptText() |> ignore)
            .decryptText(fun _ -> decryptText() |> ignore)
            .newUuid(fun _ -> newUuid())
            .textInput(textInput)
            .hashResult(hashResult.V)
            .randomResult(randomResult.V)
            .ciphertext(ciphertext.V)
            .decrypted(decrypted.V)
            .uuid(uuid.V)
            .status(statusMessage.V)
            .capabilities(capabilities)
            .Doc()
        |> Doc.RunById "main"
