namespace WebSharper.WebCrypto

open WebSharper
open WebSharper.JavaScript
open WebSharper.InterfaceGenerator

module Definition =

    module Enum = 
        let KeyUsages = 
            Pattern.EnumStrings "KeyUsages" [
                "encrypt"
                "decrypt"
                "sign"
                "verify"
                "deriveKey"
                "deriveBits"
                "wrapKey"
                "unwrapKey"
            ]

        let Format = 
            Pattern.EnumStrings "Format" [
                "raw"
                "pkcs8"
                "spki"
                "jwk"
            ]

    let TypedArray = T<Int8Array> + T<Uint8Array> + T<Uint8ClampedArray>
                    + T<Int16Array> + T<Uint16Array> + T<Int32Array> + T<Uint32Array> 

    let BufferData = T<ArrayBuffer> + TypedArray + T<DataView>

    let ObjOrString = T<obj> + T<string>

    let CryptoKey =
        Class "CryptoKey"
        |+> Instance [
            "type" =? T<string>
            "extractable" =? T<bool>
            "algorithm" =? T<obj>
            "usages" =? !| T<string>
        ]

    let CryptoKeyPair = 
        Pattern.Config "CryptoKeyPair" {
            Required = []
            Optional = [
                "privateKey", CryptoKey.Type
                "publicKey", CryptoKey.Type
            ]
        }

    let AesCbcParams = 
        Pattern.Config "AesCbcParams" {
            Required = []
            Optional = [
                "name", T<string>
                "iv", BufferData
            ]
        }

    let AesCtrParams = 
        Pattern.Config "AesCtrParams" {
            Required = []
            Optional = [
                "name", T<string>
                "counter", BufferData
                "length", T<int>
            ]
        }

    let AesGcmParams = 
        Pattern.Config "AesGcmParams" {
            Required = []
            Optional = [
                "name", T<string>
                "iv", BufferData
                "additionalData", BufferData
                "tagLength", T<int>
            ]
        }

    let AesKeyGenParams = 
        Pattern.Config "AesKeyGenParams" {
            Required = []
            Optional = [
                "name", T<string>
                "length", T<int>
            ]
        }

    let EcKeyGenParams = 
        Pattern.Config "EcKeyGenParams" {
            Required = []
            Optional = [
                "name", T<string>
                "namedCurve", T<string>
            ]
        }

    let EcKeyImportParams = 
        Pattern.Config "EcKeyImportParams" {
            Required = []
            Optional = [
                "name", T<string>
                "namedCurve", T<string>
            ]
        }

    let EcdhKeyDeriveParams = 
        Pattern.Config "EcdhKeyDeriveParams" {
            Required = []
            Optional = [
                "name", T<string>
                "public", CryptoKey.Type
            ]
        }

    let EcdsaParams = 
        Pattern.Config "EcdsaParams" {
            Required = []
            Optional = [
                "name", T<string>
                "hash", T<string>
            ]
        }

    let HkdfParams = 
        Pattern.Config "HkdfParams" {
            Required = []
            Optional = [
                "name", T<string>
                "hash", T<string>
                "salt", BufferData
                "info", BufferData
            ]
        }

    let HmacImportParams = 
        Pattern.Config "HmacImportParams" {
            Required = []
            Optional = [
                "name", T<string>
                "hash", T<string>
                "length", T<int>
            ]
        }

    let HmacKeyGenParams = 
        Pattern.Config "HmacKeyGenParams" {
            Required = []
            Optional = [
                "name", T<string>
                "hash", T<string>
                "length", T<int>
            ]
        }

    let Pbkdf2Params = 
        Pattern.Config "Pbkdf2Params" {
            Required = []
            Optional = [
                "name", T<string>
                "hash", T<string>
                "salt", BufferData
                "iterations", T<int>
            ]
        }

    let RsaHashedImportParams = 
        Pattern.Config "RsaHashedImportParams" {
            Required = []
            Optional = [
                "name", T<string>
                "hash", T<string>
            ]
        }

    let RsaHashedKeyGenParams = 
        Pattern.Config "RsaHashedKeyGenParams" {
            Required = []
            Optional = [
                "name", T<string>
                "modulusLength", T<int>
                "publicExponent", T<Uint8Array>
                "hash", T<string>
            ]
        }

    let RsaOaepParams = 
        Pattern.Config "RsaOaepParams" {
            Required = []
            Optional = [
                "name", T<string>
                "label", BufferData
            ]
        }

    let RsaPssParams = 
        Pattern.Config "RsaPssParams" {
            Required = []
            Optional = [
                "name", T<string>
                "saltLength", T<int>
            ]
        }

    let Keys = CryptoKey + CryptoKeyPair

    let SubtleCrypto =

        Class "SubtleCrypto"
        |+> Instance [
            "encrypt" => T<obj>?algorithm * Keys?key * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "decrypt" => T<obj>?algorithm * Keys?key * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "sign" => ObjOrString?algorithm * Keys?key * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "verify" => ObjOrString?algorithm * Keys?key * T<ArrayBuffer>?signature * BufferData?data ^-> T<Promise<bool>>
            "digest" => T<obj>?algorithm * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "generateKey" => T<obj>?algorithm * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<_>>[Keys]
            "deriveKey" => T<obj>?algorithm * Keys?baseKey * T<obj>?derivedKeyAlgorithm * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<_>>[Keys]
            "deriveBits" => T<obj>?algorithm * Keys?baseKey * T<int>?length ^-> T<Promise<ArrayBuffer>>
            "importKey" => Enum.Format?format * BufferData?keyData * T<obj>?algorithm * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<_>>[Keys]
            "exportKey" => Enum.Format?format * Keys?key ^-> T<Promise<ArrayBuffer>>
            "wrapKey" => Enum.Format?format * Keys?key * Keys?wrappingKey * T<obj>?wrapAlgorithm ^-> T<Promise<ArrayBuffer>>
            "unwrapKey" => T<string>?format * T<ArrayBuffer>?wrappedKey * Keys?unwrappingKey * T<obj>?unwrapAlgo * T<obj>?unwrappedKeyAlgo * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<_>>[Keys]
        ]

    let Crypto =
        Class "Crypto"
        |+> Instance [
            "subtle" =? SubtleCrypto
            "getRandomValues" => TypedArray?array ^-> TypedArray
            "randomUUID" => T<unit> ^-> T<string>
        ]

    let Window =
        Class "Window"
        |+> Instance [
            "crypto" =? Crypto
        ]

    let WorkerGlobalScope =
        Class "WorkerGlobalScope"
        |+> Instance [
            "crypto" =? Crypto
        ]

    let Assembly =
        Assembly [
            Namespace "WebSharper.WebCrypto" [
                WorkerGlobalScope
                Window
                Crypto
                SubtleCrypto
                RsaPssParams
                RsaOaepParams
                RsaHashedKeyGenParams
                RsaHashedImportParams
                Pbkdf2Params
                HmacKeyGenParams
                HmacImportParams
                HkdfParams
                EcdsaParams
                EcdhKeyDeriveParams
                EcKeyImportParams
                EcKeyGenParams
                AesKeyGenParams
                AesGcmParams
                AesCtrParams
                AesCbcParams
                CryptoKeyPair
                CryptoKey
                Enum.Format
                Enum.KeyUsages
            ]
        ]

[<Sealed>]
type Extension() =
    interface IExtension with
        member ext.Assembly =
            Definition.Assembly

[<assembly: Extension(typeof<Extension>)>]
do ()
