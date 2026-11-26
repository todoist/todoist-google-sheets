import { User as UserBase } from '@doist/ui-extensions-server'

import { Logger } from '@nestjs/common'
import { DataSource } from 'typeorm'
import { EncryptionTransformer } from 'typeorm-encrypted'

import { User as UserEntity } from '../src/entities/user.entity'
import {
    getEncryptionKeys,
    RotatingEncryptionTransformer,
} from '../src/utils/rotating-encryption-transformer'

import type { EncryptionOptions } from 'typeorm-encrypted'

// Dummy keys for tests only.
const OLD_KEY = 'edeb8ab8fd6a506e7dd8559132cbc56e4cc998d81d2117c7495075e92e82655c'
const NEW_KEY = '5f0c2a1d9e3b47c68a1e2d3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c'
const OPTIONS = { algorithm: 'aes-256-cbc', ivLength: 16 }
const OLD: EncryptionOptions = { key: OLD_KEY, ...OPTIONS }
const NEW: EncryptionOptions = { key: NEW_KEY, ...OPTIONS }

const ENCRYPTED_COLUMNS = ['authToken', 'refreshToken', 'emailAddress', 'name']

describe('RotatingEncryptionTransformer', () => {
    it('encrypts with the current key', () => {
        const stored = new RotatingEncryptionTransformer([NEW, OLD]).to('secret') as string

        expect(new EncryptionTransformer(NEW).from(stored)).toEqual('secret')
        // The old key usually throws here, but about 1 in 256 times it returns noise instead, so
        // only assert that it doesn't recover the value.
        let withOldKey: string | undefined
        try {
            withOldKey = new EncryptionTransformer(OLD).from(stored)
        } catch {
            withOldKey = undefined
        }
        expect(withOldKey).not.toEqual('secret')
    })

    it('decrypts values encrypted with either key', () => {
        const transformer = new RotatingEncryptionTransformer([NEW, OLD])

        const fromNew = new EncryptionTransformer(NEW).to('with-new') as string
        const fromOld = new EncryptionTransformer(OLD).to('with-old') as string

        expect(transformer.decrypt(fromNew)).toEqual({ plaintext: 'with-new', isCurrentKey: true })
        expect(transformer.decrypt(fromOld)).toEqual({ plaintext: 'with-old', isCurrentKey: false })
    })

    it('reads with the old key first while still writing with it (before the swap)', () => {
        const transformer = new RotatingEncryptionTransformer([OLD, NEW])
        const fromNew = new EncryptionTransformer(NEW).to('written-after-swap') as string

        expect(transformer.from(fromNew)).toEqual('written-after-swap')
        expect(new EncryptionTransformer(OLD).from(transformer.to('x') as string)).toEqual('x')
    })

    it('reads thousands of values with the other key without returning noise', () => {
        // Wrong-key decryption passes the CBC padding check about 1 in 256 times; the text check
        // must catch every one of those.
        const transformer = new RotatingEncryptionTransformer([NEW, OLD])
        const oldWriter = new EncryptionTransformer(OLD)

        for (let i = 0; i < 5000; i++) {
            const value = `ya29.token-${i}`
            expect(transformer.from(oldWriter.to(value) as string)).toEqual(value)
        }
    })

    it('keeps non-ASCII text', () => {
        const transformer = new RotatingEncryptionTransformer([NEW, OLD])
        const stored = new EncryptionTransformer(OLD).to('Zoë 🦊 José') as string

        expect(transformer.from(stored)).toEqual('Zoë 🦊 José')
    })

    it('logs reads that needed the fallback key, without the value', () => {
        const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
        const transformer = new RotatingEncryptionTransformer([NEW, OLD])

        transformer.from(new EncryptionTransformer(NEW).to('current') as string)
        expect(warn).not.toHaveBeenCalled()

        transformer.from(new EncryptionTransformer(OLD).to('do-not-log') as string)
        expect(warn).toHaveBeenCalledTimes(1)
        expect(warn).toHaveBeenCalledWith(
            'Decrypted a database value with DB_ENCRYPTION_FALLBACK_KEY',
            { reason: 'fallback-key' },
        )
    })

    it('logs and rethrows when no key can read a value', () => {
        const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
        const otherKey = { ...OPTIONS, key: 'a'.repeat(64) }
        const stored = new EncryptionTransformer(otherKey).to('do-not-log') as string

        expect(() => new RotatingEncryptionTransformer([NEW, OLD]).from(stored)).toThrow(
            'Could not decrypt value with any configured key',
        )
        expect(error).toHaveBeenCalledWith(
            'Could not decrypt a database value with any configured key',
            { reason: 'no-key', keyCount: 2 },
        )
    })

    it('does not log when decrypting directly (the migration logs a summary)', () => {
        const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

        new RotatingEncryptionTransformer([NEW, OLD]).decrypt(
            new EncryptionTransformer(OLD).to('x') as string,
        )

        expect(warn).not.toHaveBeenCalled()
    })

    it('returns nothing for empty values, like typeorm-encrypted', () => {
        const transformer = new RotatingEncryptionTransformer([NEW, OLD])

        expect(transformer.from(null)).toBeUndefined()
        expect(transformer.from('')).toBeUndefined()
        expect(transformer.to(null)).toBeUndefined()
    })

    it('fails without leaking the value when no key can decrypt it', () => {
        const otherKey = { ...OPTIONS, key: 'a'.repeat(64) }
        const transformer = new RotatingEncryptionTransformer([NEW, OLD])

        // Many values, so the ~1 in 256 cases where a wrong key passes the padding check are hit.
        for (let i = 0; i < 2000; i++) {
            const stored = new EncryptionTransformer(otherKey).to(`do-not-leak-${i}`) as string

            let error: Error | undefined
            try {
                transformer.decrypt(stored)
            } catch (e: unknown) {
                error = e as Error
            }

            expect(error?.message).toEqual('Could not decrypt value with any configured key')
            expect(String(error?.cause)).not.toContain('do-not-leak')
        }
    })
})

describe('getEncryptionKeys', () => {
    const originalEnv = process.env

    beforeEach(() => {
        process.env = {
            ...originalEnv,
            DB_ENCRYPTION_ALGORITHM: OPTIONS.algorithm,
            DB_ENCRYPTION_IV_LENGTH: String(OPTIONS.ivLength),
            DB_ENCRYPTION_KEY: NEW_KEY,
        }
        delete process.env.DB_ENCRYPTION_FALLBACK_KEY
    })

    afterEach(() => {
        process.env = originalEnv
    })

    it('uses only the current key when there is no fallback', () => {
        expect(getEncryptionKeys()).toEqual([NEW])
    })

    it('adds the fallback key after the current one', () => {
        process.env.DB_ENCRYPTION_FALLBACK_KEY = OLD_KEY

        expect(getEncryptionKeys()).toEqual([NEW, OLD])
    })

    it('ignores a fallback key equal to the current one', () => {
        process.env.DB_ENCRYPTION_FALLBACK_KEY = NEW_KEY

        expect(getEncryptionKeys()).toEqual([NEW])
    })

    it('requires the current key', () => {
        delete process.env.DB_ENCRYPTION_KEY

        expect(() => getEncryptionKeys()).toThrow('DB_ENCRYPTION_KEY')
    })
})

describe('User entity', () => {
    const originalEnv = process.env

    afterEach(() => {
        process.env = originalEnv
    })

    async function buildMetadata(entity: () => unknown) {
        const dataSource = new DataSource({
            type: 'mysql',
            database: 'metadata-only',
            entities: [entity() as never],
        })
        // Builds entity metadata without connecting to a database.
        await (dataSource as unknown as { buildMetadatas(): Promise<void> }).buildMetadatas()
        const metadata = dataSource.entityMetadatas[0]
        if (!metadata) {
            throw new Error('No entity metadata')
        }
        return metadata
    }

    it('uses the rotating transformer for every encrypted column', async () => {
        process.env = {
            ...originalEnv,
            DB_HOST: 'localhost',
            DB_ENCRYPTION_ALGORITHM: OPTIONS.algorithm,
            DB_ENCRYPTION_IV_LENGTH: String(OPTIONS.ivLength),
            DB_ENCRYPTION_KEY: NEW_KEY,
            DB_ENCRYPTION_FALLBACK_KEY: OLD_KEY,
        }
        let User: unknown
        jest.isolateModules(() => {
            // Loaded after setting env: the transformer is built when the entity module loads.
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            User = (require('../src/entities/user.entity') as { User: unknown }).User
        })

        const { columns } = await buildMetadata(() => User)
        const encrypted = columns.filter((c) => ENCRYPTED_COLUMNS.includes(c.propertyName))

        expect(encrypted.map((c) => c.propertyName).sort()).toEqual([...ENCRYPTED_COLUMNS].sort())
        for (const column of encrypted) {
            const transformer = column.transformer as RotatingEncryptionTransformer
            const fromOld = new EncryptionTransformer(OLD).to(column.propertyName) as string

            // Reads data written with the fallback key, and writes with the current key.
            expect(transformer.from(fromOld)).toEqual(column.propertyName)
            expect(new EncryptionTransformer(NEW).from(transformer.to('x') as string)).toEqual('x')
        }
    })

    it("keeps the library's column definitions, so the schema doesn't change", async () => {
        process.env = { ...originalEnv, DB_HOST: 'localhost' }
        let User: unknown
        jest.isolateModules(() => {
            // Loaded after setting env: the transformer is built when the entity module loads.
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            User = (require('../src/entities/user.entity') as { User: unknown }).User
        })

        function schemaOf({
            tableName,
            columns,
            indices,
        }: Awaited<ReturnType<typeof buildMetadata>>) {
            return {
                tableName,
                indices: indices.map((index) => ({
                    name: index.name,
                    columns: index.columns.map((c) => c.databaseName),
                    isUnique: index.isUnique,
                })),
                columns: columns
                    .map((c) => ({
                        name: c.databaseName,
                        type: c.type,
                        length: c.length,
                        isNullable: c.isNullable,
                        isPrimary: c.isPrimary,
                        isGenerated: c.isGenerated,
                        default: c.default as unknown,
                        unsigned: c.unsigned,
                    }))
                    .sort((a, b) => a.name.localeCompare(b.name)),
            }
        }

        expect(schemaOf(await buildMetadata(() => User))).toEqual(
            schemaOf(await buildMetadata(() => UserBase)),
        )
    })

    it('copies every field in set, like the library entity', () => {
        const data = {
            twistId: 42,
            authToken: 'access',
            refreshToken: 'refresh',
            tokenExpiresAt: new Date('2026-11-26T00:00:00Z'),
            externalUserId: 'google-123',
            emailAddress: 'one@example.com',
            name: 'One',
        }
        const ours = new UserEntity()
        const library = new UserBase()

        ours.set(data)
        library.set(data)

        expect({ ...ours }).toEqual(data)
        expect({ ...ours }).toEqual({ ...library })
    })
})
