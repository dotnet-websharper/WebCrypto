namespace WebSharper.WebCrypto

open WebSharper
open WebSharper.JavaScript

[<JavaScript; AutoOpen>]
module Extensions =

    type Window with
        [<Inline "this.crypto">]
        member this.Crypto with get(): Crypto = X<Crypto>

    type WorkerGlobalScope with
        [<Inline "$this.crypto">]
        member this.Crypto with get(): Crypto = X<Crypto>
