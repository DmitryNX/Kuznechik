# Алгоритм синхронного шифрования "Кузнечик" (ГОСТ Р 34.12-2015, ГОСТ Р 34.13-2015)

Реализация алгоритма блочного синхронного шифрования "Кузнечик" на языке Rust.

## Режимы шифрования:

| Struct |            Title            |                      Название                      | Reduction |
|:------:|:--------------------------- |:-------------------------------------------------- |:---------:|
| AlgEcb | Electronic Codebook         | Режим простой замены                               |    ЕСВ    |
| AlgCtr | Counter                     | Режим гаммирования                                 |    CTR    |
| AlgOfb | Output Feedback             | Режим гаммирования с обратной связью по выходу     |    OFB    |
| AlgCbc | Cipher Block Chaining       | Режим простой замены с зацеплением                 |    СВС    |
| AlgCfb | Cipher Feedback             | Режим гаммирования с обратной связью по шифртексту |    CFB    |
| AlgMac | Message Authentication Code | Режим выработки имитовставки                       |    MAC    |

## Использование (AlgOfb):

В следующем примере производится шифрование и расшиврование блока данных `data` длиной 64 байта по методу OFB. 
Шифрование по другим методам аналогично, в некоторых гамма не требуется 
(подробнее в [tests.rs](https://github.com/DmitryNX/Kuznechik/blob/master/src/tests.rs)).

```
extern crate kuznechik;

use self::kuznechik::{KeyStore, Kuznechik, AlgOfb};

fn main() {
    // Инициализация
    let password = "Kuznechik";
    let data = Vec::from("Hello, World!");

    let gamma = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];

    let kuz = KeyStore::with_password(password);
    let mut cipher = AlgOfb::new(&kuz).gamma(gamma.clone());

    // Шифрование
    let enc_data = cipher.encrypt(data.clone());

    // Расшифрование
    // Установка гаммы в первоначальное значение, так как алгоритм OFB изменяет её во время выполнения
    cipher.set_gamma(gamma);
    let dec_data = cipher.decrypt(enc_data);

    // Проверка результата
    assert_eq!(data, dec_data);
}
```
