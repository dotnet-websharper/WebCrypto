namespace WebSharper.WebCrypto

open WebSharper
open WebSharper.JavaScript

[<JavaScript; AutoOpen>]
module Extensions =

    /// The `Crypto` object of the current window (`window.crypto`).
    ///
    /// A module function is used instead of a `Window.Crypto` extension member
    /// because core already exposes a `Window.Crypto` property (typed as `obj`),
    /// which would shadow the extension.
    [<Inline "window.crypto">]
    let WindowCrypto () : Crypto = X<Crypto>

    /// The `Crypto` object of a worker's global scope (`self.crypto`).
    [<Inline "self.crypto">]
    let WorkerCrypto () : Crypto = X<Crypto>
