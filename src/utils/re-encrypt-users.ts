import { getEncryptionKeys, RotatingEncryptionTransformer } from './rotating-encryption-transformer'

import type { Logger } from '@nestjs/common'
import type { QueryRunner } from 'typeorm'

/**
 * The `user` columns that are encrypted.
 */
export const ENCRYPTED_USER_COLUMNS = ['authToken', 'refreshToken', 'emailAddress', 'name'] as const

type EncryptedUserColumn = (typeof ENCRYPTED_USER_COLUMNS)[number]
type UserRow = { id: number } & Record<EncryptedUserColumn, string | null>

export const BATCH_SIZE = 500

export type ReEncryptionResult = {
    rowsTotal: number
    rowsReEncrypted: number
}

/**
 * Re-encrypts, with `DB_ENCRYPTION_KEY`, every `user` row that has a column still encrypted with
 * `DB_ENCRYPTION_FALLBACK_KEY`. Rows already fully on `DB_ENCRYPTION_KEY` are left untouched, so
 * running it again is safe.
 *
 * Reads and writes in batches of `BATCH_SIZE` rows, one `UPDATE` per batch, so it stays fast
 * enough to run during startup.
 */
export async function reEncryptUsers(
    queryRunner: QueryRunner,
    logger: Logger,
): Promise<ReEncryptionResult> {
    const [{ count }] = (await queryRunner.query('SELECT COUNT(*) AS `count` FROM `user`')) as [
        { count: number | string },
    ]
    const rowsTotal = Number(count)
    if (rowsTotal === 0) {
        logger.log('No user rows to re-encrypt')
        return { rowsTotal, rowsReEncrypted: 0 }
    }

    const transformer = new RotatingEncryptionTransformer(getEncryptionKeys())
    const columnList = ENCRYPTED_USER_COLUMNS.map((column) => `\`${column}\``).join(', ')

    let lastId = 0
    let rowsReEncrypted = 0

    for (;;) {
        const rows = (await queryRunner.query(
            `SELECT \`id\`, ${columnList} FROM \`user\` WHERE \`id\` > ? ORDER BY \`id\` LIMIT ?`,
            [lastId, BATCH_SIZE],
        )) as UserRow[]

        const updates = rows.flatMap((row) => {
            const reEncrypted = reEncryptRow(row, transformer)
            return reEncrypted ? [{ original: row, updated: reEncrypted }] : []
        })
        if (updates.length > 0) {
            await updateRows(queryRunner, updates)
            rowsReEncrypted += updates.length
        }

        const lastRow = rows[rows.length - 1]
        if (rows.length < BATCH_SIZE || !lastRow) {
            break
        }
        lastId = lastRow.id
    }

    logger.log(
        `Re-encrypted ${rowsReEncrypted} of ${rowsTotal} user rows; the rest were already on DB_ENCRYPTION_KEY`,
    )
    return { rowsTotal, rowsReEncrypted }
}

/**
 * Returns the row encrypted with the current key, or nothing if it already is.
 */
function reEncryptRow(row: UserRow, transformer: RotatingEncryptionTransformer): UserRow | null {
    const decrypted = ENCRYPTED_USER_COLUMNS.map((column) => {
        const value = row[column]
        if (!value) {
            // Empty values aren't encrypted.
            return null
        }
        try {
            return transformer.decrypt(value)
        } catch (error: unknown) {
            // The message names the row and column only, never the value; the cause is a crypto
            // error, which never includes it either.
            throw new Error(`Could not re-encrypt user ${row.id} column ${column}`, {
                cause: error,
            })
        }
    })
    if (decrypted.every((value) => value === null || value.isCurrentKey)) {
        return null
    }

    const updated: UserRow = { ...row }
    ENCRYPTED_USER_COLUMNS.forEach((column, index) => {
        const value = decrypted[index]
        if (value) {
            updated[column] = transformer.to(value.plaintext) as string
        }
    })
    return updated
}

/**
 * Writes the re-encrypted rows, one `UPDATE` per batch. A row is only written if it still holds the
 * values that were read: an old task still serving during the deploy may have saved it since (a
 * token refresh or a sign-in), and its newer values must win. Those rows were saved with the old
 * key, so the sweep in the next deploy re-encrypts them.
 */
async function updateRows(
    queryRunner: QueryRunner,
    rows: { original: UserRow; updated: UserRow }[],
): Promise<void> {
    const cases = ENCRYPTED_USER_COLUMNS.map(
        (column) => `\`${column}\` = CASE \`id\` ${rows.map(() => 'WHEN ? THEN ?').join(' ')} END`,
    ).join(', ')
    // `<=>` is MySQL's null-safe equality: refreshToken, emailAddress and name can be NULL, and with
    // `=` a row with any NULL column would never match, so it would never be re-encrypted.
    const sameValues = ENCRYPTED_USER_COLUMNS.map((column) => `\`${column}\` <=> ?`).join(' AND ')
    const unchanged = `CASE \`id\` ${rows.map(() => `WHEN ? THEN ${sameValues}`).join(' ')} END`
    const params = [
        ...ENCRYPTED_USER_COLUMNS.flatMap((column) =>
            rows.flatMap(({ updated }) => [updated.id, updated[column]]),
        ),
        ...rows.map(({ original }) => original.id),
        ...rows.flatMap(({ original }) => [
            original.id,
            ...ENCRYPTED_USER_COLUMNS.map((column) => original[column]),
        ]),
    ]

    await queryRunner.query(
        `UPDATE \`user\` SET ${cases} WHERE \`id\` IN (${rows
            .map(() => '?')
            .join(', ')}) AND ${unchanged}`,
        params,
    )
}
