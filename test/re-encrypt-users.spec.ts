import { Logger } from '@nestjs/common'

import { EncryptionTransformer } from 'typeorm-encrypted'

import { ReEncryptUsersWithKey21795681180350 } from '../src/migrations/1795681180350-re-encrypt-users-with-key2'
import { ReEncryptRemainingUsers1795681352903 } from '../src/migrations/1795681352903-re-encrypt-remaining-users'
import { BATCH_SIZE, reEncryptUsers } from '../src/utils/re-encrypt-users'

import type { QueryRunner } from 'typeorm'

// Dummy keys for tests only.
const OLD_KEY = 'edeb8ab8fd6a506e7dd8559132cbc56e4cc998d81d2117c7495075e92e82655c'
const NEW_KEY = '5f0c2a1d9e3b47c68a1e2d3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c'
const OPTIONS = { algorithm: 'aes-256-cbc', ivLength: 16 }

const oldTransformer = new EncryptionTransformer({ key: OLD_KEY, ...OPTIONS })
const newTransformer = new EncryptionTransformer({ key: NEW_KEY, ...OPTIONS })

const COLUMNS = ['authToken', 'refreshToken', 'emailAddress', 'name'] as const

type Row = {
    id: number
    authToken: string | null
    refreshToken: string | null
    emailAddress: string | null
    name: string | null
}
type Values = Omit<Row, 'id'>

/**
 * Stands in for MySQL: serves the three queries the re-encryption runs against an in-memory table.
 */
function createQueryRunner(rows: Row[], options: { afterSelect?: () => void } = {}) {
    const query = jest.fn((sql: string, params: unknown[] = []) => {
        if (sql.startsWith('SELECT COUNT(*)')) {
            return Promise.resolve([{ count: String(rows.length) }])
        }
        if (sql.startsWith('SELECT')) {
            const [lastId, limit] = params as [number, number]
            const page = rows
                .filter((row) => row.id > lastId)
                .sort((a, b) => a.id - b.id)
                .slice(0, limit)
                .map((row) => ({ ...row }))
            // Lets a test change rows after they were read, as another task saving them would.
            options.afterSelect?.()
            return Promise.resolve(page)
        }
        if (sql.startsWith('UPDATE')) {
            // Params: for each column, (id, new value) per row; the ids for `WHERE id IN`; then, per
            // row, its id and the values that were read, which the row must still hold.
            const rowCount = params.length / (COLUMNS.length * 2 + 1 + 1 + COLUMNS.length)
            const conditionOffset = COLUMNS.length * rowCount * 2 + rowCount
            const unchanged = new Set<number>()
            for (let i = 0; i < rowCount; i++) {
                const offset = conditionOffset + i * (1 + COLUMNS.length)
                const id = params[offset] as number
                const row = rows.find((r) => r.id === id)
                // Null-safe comparison, like MySQL's `<=>`.
                if (row && COLUMNS.every((column, c) => row[column] === params[offset + 1 + c])) {
                    unchanged.add(id)
                }
            }
            COLUMNS.forEach((column, columnIndex) => {
                const offset = columnIndex * rowCount * 2
                for (let i = 0; i < rowCount; i++) {
                    const id = params[offset + i * 2] as number
                    const value = params[offset + i * 2 + 1] as string | null
                    const row = rows.find((r) => r.id === id)
                    if (row && unchanged.has(id)) {
                        row[column] = value
                    }
                }
            })
            return Promise.resolve()
        }
        throw new Error(`Unexpected query: ${sql}`)
    })
    return { queryRunner: { query } as unknown as QueryRunner, query }
}

function updateCalls(query: { mock: { calls: unknown[][] } }): unknown[][] {
    return query.mock.calls.filter(([sql]) => String(sql).startsWith('UPDATE'))
}

function encryptedRow(id: number, values: Values, transformer = oldTransformer): Row {
    function encrypt(value: string | null) {
        return value === null ? null : (transformer.to(value) as string)
    }
    return {
        id,
        authToken: encrypt(values.authToken),
        refreshToken: encrypt(values.refreshToken),
        emailAddress: encrypt(values.emailAddress),
        name: encrypt(values.name),
    }
}

function decryptRow(row: Row, transformer: EncryptionTransformer): Row {
    function decrypt(value: string | null) {
        return value === null ? null : transformer.from(value) ?? null
    }
    return {
        id: row.id,
        authToken: decrypt(row.authToken),
        refreshToken: decrypt(row.refreshToken),
        emailAddress: decrypt(row.emailAddress),
        name: decrypt(row.name),
    }
}

const ONE: Values = {
    authToken: 'access-1',
    refreshToken: 'refresh-1',
    emailAddress: 'one@example.com',
    name: 'Zoë',
}
const TWO: Values = { authToken: 'access-2', refreshToken: null, emailAddress: null, name: null }

describe('re-encrypting users', () => {
    const originalEnv = process.env
    const logger = new Logger('test')

    beforeEach(() => {
        jest.spyOn(logger, 'log').mockImplementation(() => undefined)
        process.env = {
            ...originalEnv,
            DB_ENCRYPTION_ALGORITHM: OPTIONS.algorithm,
            DB_ENCRYPTION_IV_LENGTH: String(OPTIONS.ivLength),
            DB_ENCRYPTION_KEY: NEW_KEY,
            DB_ENCRYPTION_FALLBACK_KEY: OLD_KEY,
        }
    })

    afterEach(() => {
        process.env = originalEnv
    })

    describe('reEncryptUsers', () => {
        it('re-encrypts every encrypted column with the current key', async () => {
            const rows = [encryptedRow(1, ONE), encryptedRow(2, TWO)]
            const { queryRunner } = createQueryRunner(rows)

            const result = await reEncryptUsers(queryRunner, logger)

            expect(result).toEqual({ rowsTotal: 2, rowsReEncrypted: 2 })
            expect(rows.map((row) => decryptRow(row, newTransformer))).toEqual([
                { id: 1, ...ONE },
                { id: 2, ...TWO },
            ])
        })

        it('leaves rows already on the current key untouched', async () => {
            const current = encryptedRow(1, ONE, newTransformer)
            const stored = { ...current }
            const { queryRunner, query } = createQueryRunner([current, encryptedRow(2, TWO)])

            const result = await reEncryptUsers(queryRunner, logger)

            expect(result).toEqual({ rowsTotal: 2, rowsReEncrypted: 1 })
            expect(current).toEqual(stored)
            expect(updateCalls(query)).toHaveLength(1)
        })

        it('re-encrypts a row where only some columns are on the old key', async () => {
            const row = encryptedRow(1, ONE, newTransformer)
            row.name = oldTransformer.to('Zoë') as string
            const { queryRunner } = createQueryRunner([row])

            await reEncryptUsers(queryRunner, logger)

            expect(decryptRow(row, newTransformer)).toEqual({ id: 1, ...ONE })
        })

        it('only updates rows that still hold the values it read, comparing NULLs safely', async () => {
            const rows = [encryptedRow(1, ONE), encryptedRow(2, TWO)]
            const read = rows.map((row) => ({ ...row }))
            const { queryRunner, query } = createQueryRunner(rows)

            await reEncryptUsers(queryRunner, logger)

            const [sql, params] = updateCalls(query)[0] as [string, unknown[]]
            expect(sql).toContain('`authToken` <=> ?')
            expect(sql).toContain('`name` <=> ?')
            // The condition carries each row's id and the values that were read, NULLs included.
            expect(params.slice(-10)).toEqual([
                1,
                read[0]!.authToken,
                read[0]!.refreshToken,
                read[0]!.emailAddress,
                read[0]!.name,
                2,
                read[1]!.authToken,
                null,
                null,
                null,
            ])
            // Row 2, with three NULL columns, was still re-encrypted.
            expect(decryptRow(rows[1]!, newTransformer)).toEqual({ id: 2, ...TWO })
        })

        it("doesn't overwrite a row saved after it was read", async () => {
            const row = encryptedRow(1, ONE)
            const storedRefreshToken = row.refreshToken
            const other = encryptedRow(2, TWO)
            const refreshed = oldTransformer.to('access-refreshed') as string
            const { queryRunner } = createQueryRunner([row, other], {
                // An old task still serving the previous deploy refreshes the token meanwhile.
                afterSelect: () => {
                    row.authToken = refreshed
                },
            })

            const result = await reEncryptUsers(queryRunner, logger)

            // The fresh token survives (still on the old key, for the next sweep to re-encrypt)...
            expect(row.authToken).toEqual(refreshed)
            expect(row.refreshToken).toEqual(storedRefreshToken)
            expect(oldTransformer.from(row.authToken)).toEqual('access-refreshed')
            // ...while the untouched row is re-encrypted as usual.
            expect(decryptRow(other, newTransformer)).toEqual({ id: 2, ...TWO })
            // Both rows still count as needing re-encryption.
            expect(result).toEqual({ rowsTotal: 2, rowsReEncrypted: 2 })
        })

        it('reads and writes in batches, one UPDATE per batch', async () => {
            const rows = Array.from({ length: BATCH_SIZE * 2 + 1 }, (_, index) =>
                encryptedRow(index + 1, { ...TWO, authToken: `access-${index + 1}` }),
            )
            const { queryRunner, query } = createQueryRunner(rows)

            await reEncryptUsers(queryRunner, logger)

            const selects = query.mock.calls.filter(([sql]) =>
                String(sql).startsWith('SELECT `id`'),
            )
            expect(selects.map(([, params]) => params)).toEqual([
                [0, BATCH_SIZE],
                [BATCH_SIZE, BATCH_SIZE],
                [BATCH_SIZE * 2, BATCH_SIZE],
            ])
            expect(updateCalls(query)).toHaveLength(3)
            expect(rows.map((row) => newTransformer.from(row.authToken))).toEqual(
                rows.map((row) => `access-${row.id}`),
            )
        })

        it('writes nothing and needs no keys when there are no users', async () => {
            delete process.env.DB_ENCRYPTION_KEY
            const { queryRunner, query } = createQueryRunner([])

            await expect(reEncryptUsers(queryRunner, logger)).resolves.toEqual({
                rowsTotal: 0,
                rowsReEncrypted: 0,
            })
            expect(updateCalls(query)).toHaveLength(0)
        })

        it('names the row and column, but never the value, when a column cannot be decrypted', async () => {
            const otherKey = new EncryptionTransformer({ key: 'a'.repeat(64), ...OPTIONS })
            const row = encryptedRow(7, TWO)
            row.authToken = otherKey.to('do-not-leak') as string
            const { queryRunner, query } = createQueryRunner([row])

            const error = (await reEncryptUsers(queryRunner, logger).catch(
                (e: unknown) => e,
            )) as Error

            expect(error.message).toEqual('Could not re-encrypt user 7 column authToken')
            expect(error.message).not.toContain(row.authToken)
            expect(String(error.cause)).not.toContain('do-not-leak')
            expect(error.cause).toBeDefined()
            expect(updateCalls(query)).toHaveLength(0)
        })
    })

    describe('ReEncryptUsersWithKey21795681180350', () => {
        it('re-encrypts the users', async () => {
            const rows = [encryptedRow(1, ONE)]
            const { queryRunner } = createQueryRunner(rows)

            await new ReEncryptUsersWithKey21795681180350().up(queryRunner)

            expect(decryptRow(rows[0] as Row, newTransformer)).toEqual({ id: 1, ...ONE })
        })

        it('fails if the keys were not swapped', async () => {
            // Still the step 1 configuration: the old key is current and the new one the fallback.
            process.env.DB_ENCRYPTION_KEY = OLD_KEY
            process.env.DB_ENCRYPTION_FALLBACK_KEY = NEW_KEY
            const { queryRunner } = createQueryRunner([encryptedRow(1, ONE)])

            await expect(new ReEncryptUsersWithKey21795681180350().up(queryRunner)).rejects.toThrow(
                'No user row was encrypted with DB_ENCRYPTION_FALLBACK_KEY',
            )
        })

        it('does nothing on an empty table', async () => {
            const { queryRunner, query } = createQueryRunner([])

            await new ReEncryptUsersWithKey21795681180350().up(queryRunner)

            expect(updateCalls(query)).toHaveLength(0)
        })

        it('runs without a fallback key when no rows need it (local databases)', async () => {
            delete process.env.DB_ENCRYPTION_FALLBACK_KEY
            const row = encryptedRow(1, ONE, newTransformer)
            const { queryRunner, query } = createQueryRunner([row])

            await new ReEncryptUsersWithKey21795681180350().up(queryRunner)

            expect(updateCalls(query)).toHaveLength(0)
        })
    })

    describe('ReEncryptRemainingUsers1795681352903', () => {
        it('re-encrypts rows written with the old key during the previous rollout', async () => {
            const straggler = encryptedRow(2, TWO)
            const rows = [encryptedRow(1, ONE, newTransformer), straggler]
            const { queryRunner } = createQueryRunner(rows)

            await new ReEncryptRemainingUsers1795681352903().up(queryRunner)

            expect(rows.map((row) => decryptRow(row, newTransformer))).toEqual([
                { id: 1, ...ONE },
                { id: 2, ...TWO },
            ])
        })

        it('succeeds without writing when every row is already on the current key', async () => {
            const { queryRunner, query } = createQueryRunner([encryptedRow(1, ONE, newTransformer)])

            await new ReEncryptRemainingUsers1795681352903().up(queryRunner)

            expect(updateCalls(query)).toHaveLength(0)
        })
    })
})
