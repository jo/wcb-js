# Webcryptobox
WebCrypto compatible encryption CLI in JavaScript.

This CLI handles the [Webcryptobox](https://github.com/jo/webcryptobox) encryption API.

Compatible packages:
* [wcb JavaScript](https://github.com/jo/wcb-js)
* [wcb Rust](https://github.com/jo/wcb-rs)

See [Webcryptobox JavaScript](https://github.com/jo/webcryptobox-js) for the library.


## Installation
Install the script with npm:

```sh
npn install -g wcbjs
```

## Usage

```sh
$ wcbjs
wcbjs <command> [options]

Commands:
  wcbjs key                                 Generate symmetric key
  wcbjs encrypt <key> [filename]            Encrypt message. Message either read
                                             from "filename" or STDIN.
  wcbjs decrypt <key> [filename]            Decrypt box. Box either read from "f
                                            ilename" or STDIN.
  wcbjs private-key                         Generate private key
  wcbjs public-key [filename]               Get corresponding public key from pr
                                            ivate key, either specified via "fil
                                            ename" or read from STDIN
  wcbjs fingerprint [filename]              Calculate fingerprint of public key,
                                             either specified via FILENAME or re
                                            ad from STDIN.
  wcbjs derive-key <private_key> [public_k  Derive symmetric key from private an
  ey]                                       d public key.
  wcbjs derive-password <private_key> [pub  Derive password from private and pub
  lic_key]                                  lic key.
  wcbjs encrypt-private-key <passphrase> [  Encrypt private key with passphrase.
  filename]                                  Key either read from "filename" or
                                            STDIN.
  wcbjs decrypt-private-key <passphrase> [  Decrypt private key with passphrase.
  filename]                                  Key either read from "filename" or
                                            STDIN.
  wcbjs encrypt-private-key-to <private_ke  Encrypt private key with private and
  y> <public_key> [filename]                 public key. Private key either read
                                             from "filename" or STDIN.
  wcbjs decrypt-private-key-from <private_  Decrypt private key with private and
  key> <public_key> [filename]               public key. Private key either read
                                             from "filename" or STDIN.
  wcbjs encrypt-to <private_key> <public_k  Encrypt message with private and pub
  ey> [filename]                            lic key. Message either read from "f
                                            ilename" or STDIN.
  wcbjs decrypt-from <private_key> <public  Decrypt box with private and public
  _key> [filename]                          key. Box either read from "filename"
                                             or STDIN.

Options:
  --version  Show version number                                       [boolean]
  --help     Show help                                                 [boolean]
```

Note that for symmetric encryption the password is visible eg. in `ps`, so that's not recommended if you need strong security. Reach out to me if using environment variables instead would be good fit, I'd be happy to add it.

## License
This project is licensed under the Apache 2.0 License.

© 2022 Johannes J. Schmidt
