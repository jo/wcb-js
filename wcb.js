#!/usr/bin/env node

import * as wcb from '../webcryptobox-js/index.js'

import _yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
const yargs = _yargs(hideBin(process.argv))

import { readFileSync, existsSync } from 'fs'

yargs
  .usage('$0 <command> [options]')

  .command('key', 'Generate symmetric key', {}, async argv => {
    const key = await wcb.generateKey()
    const bits = await wcb.exportKey(key)
    const keyHex = wcb.encodeHex(bits)
    console.log(keyHex)
  })

  .command('encrypt <key> [filename]', 'Encrypt message. Message either read from "filename" or STDIN.', yargs => yargs
    .positional('key', {
      type: 'string',
      describe: 'aes key in hex'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'filename of message content'
    })
    .check(argv => {
      if (!argv.key.match(/^[0-9a-f]{64}$/)) {
        throw new Error('key must be a 64 digit hex string')
      }
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const keyData = wcb.decodeHex(argv.key)
      const key = await wcb.importKey(keyData)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const message = readFileSync(filename)
      const box = await wcb.encrypt({ key, message })
      const boxBase64 = wcb.encodeBase64(box)
      console.log(boxBase64)
    })

  .command('decrypt <key> [filename]', 'Decrypt box. Box either read from "filename" or STDIN.', yargs => yargs
    .positional('key', {
      type: 'string',
      describe: 'aes key in hex'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to message content'
    })
    .check(argv => {
      if (!argv.key.match(/^[0-9a-f]{64}$/)) {
        throw new Error('key must be a 64 digit hex string')
      }
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const keyData = wcb.decodeHex(argv.key)
      const key = await wcb.importKey(keyData)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const boxBase64 = readFileSync(filename, { encoding:'utf8' })
      const box = wcb.decodeBase64(boxBase64)
      const messageData = await wcb.decrypt({ key, box })
      const message = wcb.encodeText(messageData)
      console.log(message)
    })

  .command('private-key', 'Generate private key', {}, async argv => {
    const { privateKey } = await wcb.generateKeyPair()
    const pem = await wcb.exportPrivateKeyPem(privateKey)
    console.log(pem)
  })

  .command('public-key [filename]', 'Get corresponding public key from private key, either specified via "filename" or read from STDIN', yargs => yargs
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to encrypted message content'
    })
    .check(argv => {
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const filename = argv.filename === '-' ? 0 : argv.filename
      const privateKeyPem = readFileSync(filename, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.getPublicKey(privateKey)
      const pem = await wcb.exportPublicKeyPem(publicKey)
      console.log(pem)
    })

  .command('fingerprint [filename]', 'Calculate fingerprint of public key, either specified via FILENAME or read from STDIN.', yargs => yargs
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to key pem'
    })
    .option('sha', {
      alias: 's',
      default: 'sha256',
      describe: 'specify the sha type',
      choices: ['sha1', 'sha256']
    })
    .check(argv => {
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const filename = argv.filename === '-' ? 0 : argv.filename
      const keyPem = readFileSync(filename, { encoding:'utf8' })
      const isPrivateKey = keyPem.match(/^-----BEGIN PRIVATE KEY-----/)
      const key = isPrivateKey ? await wcb.importPrivateKeyPem(keyPem) : await wcb.importPublicKeyPem(keyPem)
      const publicKey = isPrivateKey ? await wcb.getPublicKey(key) : key
      const isSha1 = argv.sha === 'sha1'
      const bits = isSha1 ? await wcb.sha1Fingerprint(publicKey) : await wcb.sha256Fingerprint(publicKey)
      const fingerprint = wcb.encodeHex(bits)
      console.log(fingerprint)
    })

  .command('derive-key <private_key> [public_key]', 'Derive symmetric key from private and public key.', yargs => yargs
    .positional('private_key', {
      type: 'string',
      describe: 'path to private key pem'
    })
    .positional('public_key', {
      type: 'string',
      default: '-',
      describe: 'path to public key pem'
    })
    .check(argv => {
      if (!existsSync(argv.private_key)) {
        throw new Error(`Cannot open ${argv.private_key} - does the file exist?`)
      }
      if (argv.public_key !== '-' && !existsSync(argv.public_key)) {
        throw new Error(`Cannot open ${argv.public_key} - does the file exist?`)
      }
      return true
    }), async argv => {
      const privateKeyPem = readFileSync(argv.private_key, { encoding:'utf8' })
      const publicKeyFilename = argv.public_key === '-' ? 0 : argv.public_key
      const publicKeyPem = readFileSync(publicKeyFilename, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.importPublicKeyPem(publicKeyPem)
      const key = await wcb.deriveKey({ privateKey, publicKey })
      const keyBits = await wcb.exportKey(key)
      const keyHex = wcb.encodeHex(keyBits)
      console.log(keyHex)
    })

  .command('derive-password <private_key> [public_key]', 'Derive password from private and public key.', yargs => yargs
    .positional('private_key', {
      type: 'string',
      describe: 'path to private key pem'
    })
    .positional('public_key', {
      type: 'string',
      default: '-',
      describe: 'path to public key pem'
    })
    .option('length', {
      alias: 'l',
      type: 'number',
      default: 16,
      describe: 'number of password bytes to generate'
    })
    .check(argv => {
      if (!existsSync(argv.private_key)) {
        throw new Error(`Cannot open ${argv.private_key} - does the file exist?`)
      }
      if (argv.public_key !== '-' && !existsSync(argv.public_key)) {
        throw new Error(`Cannot open ${argv.public_key} - does the file exist?`)
      }
      if (argv.length > 32) {
        throw new Error(`Too long: ${argv.length} - must be less than 32 bytes`)
      }
      if (argv.length < 1) {
        throw new Error(`Too short: ${argv.length} - must be at least 1 byte`)
      }
      return true
    }), async argv => {
      const privateKeyPem = readFileSync(argv.private_key, { encoding:'utf8' })
      const publicKeyFilename = argv.public_key === '-' ? 0 : argv.public_key
      const publicKeyPem = readFileSync(publicKeyFilename, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.importPublicKeyPem(publicKeyPem)
      const password = await wcb.derivePassword({ privateKey, publicKey, length: argv.length })
      console.log(password)
    })

  .command('encrypt-private-key <passphrase> [filename]', 'Encrypt private key with passphrase. Key either read from "filename" or STDIN.', yargs => yargs
    .positional('passphrase', {
      type: 'string',
      describe: 'passphrase for key encryption'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'filename of message content'
    })
    .check(argv => {
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const passphrase = wcb.decodeText(argv.passphrase)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const privateKeyPem = readFileSync(filename, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const pem = await wcb.exportEncryptedPrivateKeyPem({ passphrase, key: privateKey })
      console.log(pem)
    })

  .command('decrypt-private-key <passphrase> [filename]', 'Decrypt private key with passphrase. Key either read from "filename" or STDIN.', yargs => yargs
    .positional('passphrase', {
      type: 'string',
      describe: 'passphrase for key encryption'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to message content'
    })
    .check(argv => {
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const passphrase = wcb.decodeText(argv.passphrase)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const encryptedPrivateKeyPem = readFileSync(filename, { encoding:'utf8' })
      const privateKey = await wcb.importEncryptedPrivateKeyPem({ passphrase, pem: encryptedPrivateKeyPem })
      const pem = await wcb.exportPrivateKeyPem(privateKey)
      console.log(pem)
    })

  .command('encrypt-private-key-to <private_key> <public_key> [filename]', 'Encrypt private key with private and public key. Private key either read from "filename" or STDIN.', yargs => yargs
    .positional('private_key', {
      type: 'string',
      describe: 'path to private key pem'
    })
    .positional('public_key', {
      type: 'string',
      describe: 'path to public key pem'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to private key pem to encrypt'
    })
    .check(argv => {
      if (!existsSync(argv.private_key)) {
        throw new Error(`Cannot open ${argv.private_key} - does the file exist?`)
      }
      if (!existsSync(argv.public_key)) {
        throw new Error(`Cannot open ${argv.public_key} - does the file exist?`)
      }
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const privateKeyPem = readFileSync(argv.private_key, { encoding:'utf8' })
      const publicKeyPem = readFileSync(argv.public_key, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.importPublicKeyPem(publicKeyPem)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const privateKeyPemToEncrypt = readFileSync(filename)
      const privateKeyToEncrypt = await wcb.importPrivateKeyPem(privateKeyPem)
      const pem = await wcb.exportEncryptedPrivateKeyPemTo({ privateKey, publicKey, key: privateKeyToEncrypt })
      console.log(pem)
    })

  .command('decrypt-private-key-from <private_key> <public_key> [filename]', 'Decrypt private key with private and public key. Private key either read from "filename" or STDIN.', yargs => yargs
    .positional('private_key', {
      type: 'string',
      describe: 'path to private key pem'
    })
    .positional('public_key', {
      type: 'string',
      describe: 'path to public key pem'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to encrypted private key pem'
    })
    .check(argv => {
      if (!existsSync(argv.private_key)) {
        throw new Error(`Cannot open ${argv.private_key} - does the file exist?`)
      }
      if (!existsSync(argv.public_key)) {
        throw new Error(`Cannot open ${argv.public_key} - does the file exist?`)
      }
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const privateKeyPem = readFileSync(argv.private_key, { encoding:'utf8' })
      const publicKeyPem = readFileSync(argv.public_key, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.importPublicKeyPem(publicKeyPem)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const encryptedPrivateKeyPem = readFileSync(filename, { encoding:'utf8' })
      const encryptedPrivateKey = await wcb.importEncryptedPrivateKeyPemFrom({ privateKey, publicKey, pem: encryptedPrivateKeyPem })
      const pem = await wcb.exportPrivateKeyPem(encryptedPrivateKey)
      console.log(pem)
    })


  .command('encrypt-to <private_key> <public_key> [filename]', 'Encrypt message with private and public key. Message either read from "filename" or STDIN.', yargs => yargs
    .positional('private_key', {
      type: 'string',
      describe: 'path to private key pem'
    })
    .positional('public_key', {
      type: 'string',
      describe: 'path to public key pem'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path of message content'
    })
    .check(argv => {
      if (!existsSync(argv.private_key)) {
        throw new Error(`Cannot open ${argv.private_key} - does the file exist?`)
      }
      if (!existsSync(argv.public_key)) {
        throw new Error(`Cannot open ${argv.public_key} - does the file exist?`)
      }
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const privateKeyPem = readFileSync(argv.private_key, { encoding:'utf8' })
      const publicKeyPem = readFileSync(argv.public_key, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.importPublicKeyPem(publicKeyPem)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const message = readFileSync(filename)
      const box = await wcb.encryptTo({ privateKey, publicKey, message })
      const boxBase64 = wcb.encodeBase64(box)
      console.log(boxBase64)
    })

  .command('decrypt-from <private_key> <public_key> [filename]', 'Decrypt box with private and public key. Box either read from "filename" or STDIN.', yargs => yargs
    .positional('private_key', {
      type: 'string',
      describe: 'path to private key pem'
    })
    .positional('public_key', {
      type: 'string',
      describe: 'path to public key pem'
    })
    .positional('filename', {
      type: 'string',
      default: '-',
      describe: 'path to message content'
    })
    .check(argv => {
      if (!existsSync(argv.private_key)) {
        throw new Error(`Cannot open ${argv.private_key} - does the file exist?`)
      }
      if (!existsSync(argv.public_key)) {
        throw new Error(`Cannot open ${argv.public_key} - does the file exist?`)
      }
      if (argv.filename !== '-' && !existsSync(argv.filename)) {
        throw new Error(`Cannot open ${argv.filename} - does the file exist?`)
      }
      return true
    }), async argv => {
      const privateKeyPem = readFileSync(argv.private_key, { encoding:'utf8' })
      const publicKeyPem = readFileSync(argv.public_key, { encoding:'utf8' })
      const privateKey = await wcb.importPrivateKeyPem(privateKeyPem)
      const publicKey = await wcb.importPublicKeyPem(publicKeyPem)
      const filename = argv.filename === '-' ? 0 : argv.filename
      const boxBase64 = readFileSync(filename, { encoding:'utf8' })
      const box = wcb.decodeBase64(boxBase64)
      const messageData = await wcb.decryptFrom({ privateKey, publicKey, box })
      const message = wcb.encodeText(messageData)
      console.log(message)
    })


  .demandCommand(1)
  .help()
  .argv
