import { getCipherInfo } from 'crypto'
import { TextDecoder } from 'util'

import { validateEnv } from '@doist/ui-extensions-server'

import { Logger } from '@nestjs/common'
import { decryptData, EncryptionTransformer } from 'typeorm-encrypted'

import type { FindOperator, ValueTransformer } from 'typeorm'
import type { EncryptionOptions } from 'typeorm-encrypted'

const logger = new Logger('RotatingEncryptionTransformer')

const HEX = /^[0-9a-f]+$/i

export type DecryptedValue = {
    plaintext: string
    /** Whether the value is already encrypted with the current key, `DB_ENCRYPTION_KEY`. */
    isCurrentKey: boolean
}

/**
 * Encrypts with the current key and decrypts with either the current key or a fallback key, so
 * the app can read rows written before and after a key rotation. Values are stored the same way
 * as by `typeorm-encrypted`'s `EncryptionTransformer` (base64 of IV + ciphertext).
 *
 * With `aes-256-cbc` there's no integrity check: decrypting with the wrong key fails on the
 * padding most of the time, but about 1 in 256 times it "succeeds" with random bytes. So a result
 * is only accepted if it's valid UTF-8 text with no control characters, which all the encrypted
 * columns (tokens, email address, name) are. Random bytes pass that check about once in ten
 * million wrong-key attempts. A value that no key turns into clean text is an error.
 *
 * Reads through `from` log the two outcomes that matter during a rotation: a value read with the
 * fallback key (a row still waiting to be re-encrypted), and a value no key can read (the user's
 * request fails). The logs carry neither values nor row ids.
 */
export class RotatingEncryptionTransformer implements ValueTransformer {
    private readonly writer: EncryptionTransformer

    constructor(private readonly keys: readonly [EncryptionOptions, ...EncryptionOptions[]]) {
        keys.forEach((key, index) => validateKey(key, index === 0 ? 'current' : 'fallback'))
        this.writer = new EncryptionTransformer(keys[0])
    }

    to(value?: string | FindOperator<unknown> | null): string | FindOperator<unknown> | undefined {
        return this.writer.to(value)
    }

    from(value?: string | null): string | undefined {
        if (!value) {
            return undefined
        }

        let decrypted: DecryptedValue
        try {
            decrypted = this.decrypt(value)
        } catch (error: unknown) {
            logger.error('Could not decrypt a database value with any configured key', {
                reason: 'no-key',
                keyCount: this.keys.length,
            })
            throw error
        }

        if (!decrypted.isCurrentKey) {
            logger.warn('Decrypted a database value with DB_ENCRYPTION_FALLBACK_KEY', {
                reason: 'fallback-key',
            })
        }
        return decrypted.plaintext
    }

    /**
     * Decrypts a stored, non-empty value with whichever key it was encrypted with. Doesn't log:
     * callers that decrypt many values at once, like the re-encryption migration, log a summary.
     */
    decrypt(value: string): DecryptedValue {
        const data = Buffer.from(value, 'base64')
        let lastError: unknown

        for (const [index, key] of this.keys.entries()) {
            let bytes: Buffer
            try {
                bytes = decryptData(data, key)
            } catch (error: unknown) {
                lastError = error
                continue
            }

            const text = decodeText(bytes)
            if (text !== undefined) {
                return { plaintext: text, isCurrentKey: index === 0 }
            }
        }

        // The cause is a crypto error, which never includes the value.
        throw new Error('Could not decrypt value with any configured key', { cause: lastError })
    }
}

/**
 * Reads the encryption settings from env: `DB_ENCRYPTION_KEY` is used to encrypt and decrypt,
 * and `DB_ENCRYPTION_FALLBACK_KEY`, when set, only to decrypt.
 */
export function getEncryptionKeys(): [EncryptionOptions, ...EncryptionOptions[]] {
    const algorithm = validateEnv(process.env.DB_ENCRYPTION_ALGORITHM, 'DB_ENCRYPTION_ALGORITHM')
    const ivLength = Number(
        validateEnv(process.env.DB_ENCRYPTION_IV_LENGTH, 'DB_ENCRYPTION_IV_LENGTH'),
    )
    const currentKey = validateEnv(process.env.DB_ENCRYPTION_KEY, 'DB_ENCRYPTION_KEY')
    const fallbackKey = process.env.DB_ENCRYPTION_FALLBACK_KEY

    const current = { key: currentKey, algorithm, ivLength }
    return fallbackKey && fallbackKey !== currentKey
        ? [current, { key: fallbackKey, algorithm, ivLength }]
        : [current]
}

/**
 * The transformer for the encrypted `User` columns. Like `@doist/ui-extensions-server`, it returns
 * none when there's no database configured (unit tests).
 */
export function getUserEncryptionTransformer(): RotatingEncryptionTransformer | undefined {
    if (process.env.DB_HOST === undefined) {
        return undefined
    }
    return new RotatingEncryptionTransformer(getEncryptionKeys())
}

// Without `stream: true`, each `decode` call is independent, so one instance can be shared.
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true })

// eslint-disable-next-line no-control-regex -- matching control characters is the point
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/

function decodeText(bytes: Buffer): string | undefined {
    let text: string
    try {
        text = UTF8_DECODER.decode(bytes)
    } catch {
        return undefined
    }
    return CONTROL_CHARACTERS.test(text) ? undefined : text
}

/**
 * Fails if a key can't work with its algorithm. Without this, a mistyped key (wrong length, or
 * not hex, which `Buffer.from(key, 'hex')` silently truncates) only shows up when a value fails to
 * decrypt, indistinguishable from a value encrypted with another key. The message never includes
 * the key.
 */
function validateKey({ key, algorithm, ivLength }: EncryptionOptions, which: string): void {
    const cipher = getCipherInfo(algorithm)
    if (!cipher) {
        throw new Error(`Unknown encryption algorithm ${algorithm}`)
    }
    const expectedLength = cipher.keyLength * 2
    if (key.length !== expectedLength || !HEX.test(key)) {
        throw new Error(
            `The ${which} encryption key must be ${expectedLength} hex characters for ${algorithm}`,
        )
    }
    if (cipher.ivLength !== undefined && ivLength !== cipher.ivLength) {
        throw new Error(`The IV length for ${algorithm} must be ${cipher.ivLength}`)
    }
}
