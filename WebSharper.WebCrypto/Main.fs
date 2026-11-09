namespace WebSharper.WebCrypto

open WebSharper
open WebSharper.JavaScript
open WebSharper.InterfaceGenerator

#nowarn "3886" // single-element Required/Optional lists are intentional

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

        let KeyType = 
            Pattern.EnumStrings "KeyType" [
                "secret"
                "private"
                "public"
            ]

    let TypedArray = T<Int8Array> + T<Uint8Array> + T<Uint8ClampedArray>
                    + T<Int16Array> + T<Uint16Array> + T<Int32Array> + T<Uint32Array> 

    let BufferData = T<ArrayBuffer> + TypedArray + T<DataView>

    let ObjOrString = T<obj> + T<string>

    let KeyAlgorithm =
        Pattern.Config "KeyAlgorithm" {
            Required = [
                "name", T<string>
            ]
            Optional = []
        }

    let CryptoKey =
        Class "CryptoKey"
        |+> Instance [
            "type" =? Enum.KeyType.Type
            "extractable" =? T<bool>
            "algorithm" =? KeyAlgorithm.Type
            "usages" =? !| Enum.KeyUsages
        ]

    let CryptoKeyPair = 
        Pattern.Config "CryptoKeyPair" {
            Required = []
            Optional = [
                "privateKey", CryptoKey.Type
                "publicKey", CryptoKey.Type
            ]
        }

    let JsonWebKey = 
        Pattern.Config "JsonWebKey" {
            Required = [
                "kty", T<string>
            ]
            Optional = [
                "use", T<string>
                "key_ops", !| T<string>
                "alg", T<string>
                "ext", T<bool>
                "crv", T<string>
                "x", T<string>
                "y", T<string>
                "d", T<string>
                "n", T<string>
                "e", T<string>
                "k", T<string>
                "p", T<string>
                "q", T<string>
                "dp", T<string>
                "dq", T<string>
                "qi", T<string>
                "oth", T<obj>
            ]
        }

    let AesCbcParams = 
        Pattern.Config "AesCbcParams" {
            Required = [
                "name", T<string>
                "iv", BufferData
            ]
            Optional = []
        }

    let AesCtrParams = 
        Pattern.Config "AesCtrParams" {
            Required = [
                "name", T<string>
                "counter", BufferData
                "length", T<int>
            ]
            Optional = []
        }

    let AesGcmParams = 
        Pattern.Config "AesGcmParams" {
            Required = [
                "name", T<string>
                "iv", BufferData
            ]
            Optional = [
                "additionalData", BufferData
                "tagLength", T<int>
            ]
        }

    let AesKeyGenParams = 
        Pattern.Config "AesKeyGenParams" {
            Required = [
                "name", T<string>
                "length", T<int>
            ]
            Optional = []
        }

    let EcKeyGenParams = 
        Pattern.Config "EcKeyGenParams" {
            Required = [
                "name", T<string>
                "namedCurve", T<string>
            ]
            Optional = []
        }

    let EcKeyImportParams = 
        Pattern.Config "EcKeyImportParams" {
            Required = [
                "name", T<string>
                "namedCurve", T<string>
            ]
            Optional = []
        }

    let EcdhKeyDeriveParams = 
        Pattern.Config "EcdhKeyDeriveParams" {
            Required = [
                "name", T<string>
                "public", CryptoKey.Type
            ]
            Optional = []
        }

    let EcdsaParams = 
        Pattern.Config "EcdsaParams" {
            Required = [
                "name", T<string>
                "hash", T<string>
            ]
            Optional = []
        }

    let HkdfParams = 
        Pattern.Config "HkdfParams" {
            Required = [
                "name", T<string>
                "hash", T<string>
                "salt", BufferData
                "info", BufferData
            ]
            Optional = []
        }

    let HmacImportParams = 
        Pattern.Config "HmacImportParams" {
            Required = [
                "name", T<string>
                "hash", T<string>
            ]
            Optional = [
                "length", T<int>
            ]
        }

    let HmacKeyGenParams = 
        Pattern.Config "HmacKeyGenParams" {
            Required = [
                "name", T<string>
                "hash", T<string>
            ]
            Optional = [
                "length", T<int>
            ]
        }

    let Pbkdf2Params = 
        Pattern.Config "Pbkdf2Params" {
            Required = [
                "name", T<string>
                "hash", T<string>
                "salt", BufferData
                "iterations", T<int>
            ]
            Optional = []
        }

    let RsaHashedImportParams = 
        Pattern.Config "RsaHashedImportParams" {
            Required = [
                "name", T<string>
                "hash", T<string>
            ]
            Optional = []
        }

    let RsaHashedKeyGenParams = 
        Pattern.Config "RsaHashedKeyGenParams" {
            Required = [
                "name", T<string>
                "modulusLength", T<int>
                "publicExponent", T<Uint8Array>
                "hash", T<string>
            ]
            Optional = []
        }

    let RsaOaepParams = 
        Pattern.Config "RsaOaepParams" {
            Required = [
                "name", T<string>
            ]
            Optional = [
                "label", BufferData
            ]
        }

    let RsaPssParams = 
        Pattern.Config "RsaPssParams" {
            Required = [
                "name", T<string>
                "saltLength", T<int>
            ]
            Optional = []
        }

    let Keys = CryptoKey + CryptoKeyPair

    let SubtleCrypto =

        Class "SubtleCrypto"
        |+> Instance [
            "encrypt" => T<obj>?algorithm * Keys?key * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "decrypt" => T<obj>?algorithm * Keys?key * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "sign" => ObjOrString?algorithm * Keys?key * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "verify" => ObjOrString?algorithm * Keys?key * BufferData?signature * BufferData?data ^-> T<Promise<bool>>
            "digest" => T<obj>?algorithm * BufferData?data ^-> T<Promise<ArrayBuffer>>
            "generateKey" => T<obj>?algorithm * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<obj>>
            "deriveKey" => T<obj>?algorithm * Keys?baseKey * T<obj>?derivedKeyAlgorithm * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<obj>>
            "deriveBits" => T<obj>?algorithm * Keys?baseKey * T<int>?length ^-> T<Promise<ArrayBuffer>>
            "importKey" => Enum.Format?format * BufferData?keyData * T<obj>?algorithm * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<obj>>
            "exportKey" => Enum.Format?format * Keys?key ^-> T<Promise<obj>>
            "wrapKey" => Enum.Format?format * Keys?key * Keys?wrappingKey * T<obj>?wrapAlgorithm ^-> T<Promise<ArrayBuffer>>
            "unwrapKey" => Enum.Format?format * T<ArrayBuffer>?wrappedKey * Keys?unwrappingKey * T<obj>?unwrapAlgo * T<obj>?unwrappedKeyAlgo * T<bool>?extractable * (!| Enum.KeyUsages)?keyUsages ^-> T<Promise<obj>>
        ]

    let Crypto =
        Class "Crypto"
        |+> Instance [
            "subtle" =? SubtleCrypto
            "getRandomValues" => TypedArray?array ^-> TypedArray
            "randomUUID" => T<unit> ^-> T<string>
        ]

    let Assembly =
        Assembly [
            Namespace "WebSharper.WebCrypto" [
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
                JsonWebKey
                CryptoKeyPair
                CryptoKey
                KeyAlgorithm
                Enum.KeyType
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
