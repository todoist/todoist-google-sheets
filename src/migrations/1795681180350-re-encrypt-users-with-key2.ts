import { Logger } from '@nestjs/common'

import { reEncryptUsers } from '../utils/re-encrypt-users'
import { getEncryptionKeys } from '../utils/rotating-encryption-transformer'

import type { MigrationInterface, QueryRunner } from 'typeorm'

/**
 * Second of three deploys rotating the database key after the November 2026 incident exposed the
 * old one. This deploy loads `DB_ENCRYPTION_KEY2` as `DB_ENCRYPTION_KEY` and the old key as
 * `DB_ENCRYPTION_FALLBACK_KEY`, and this migration re-encrypts every user row with the new key.
 *
 * TypeORM runs it in a transaction, so if any row fails nothing is written. Every version involved
 * reads both keys, so neither old tasks still serving during the deploy nor a rollback to the
 * previous deploy lose access to any row.
 */
export class ReEncryptUsersWithKey21795681180350 implements MigrationInterface {
    name = 'ReEncryptUsersWithKey21795681180350'

    public async up(queryRunner: QueryRunner): Promise<void> {
        const logger = new Logger(ReEncryptUsersWithKey21795681180350.name)
        const { rowsTotal, rowsReEncrypted } = await reEncryptUsers(queryRunner, logger)

        // Before this deploy every row is on the old key, which is now the fallback. If none needed
        // re-encrypting, the keys most likely weren't swapped: fail rather than record this
        // migration as done.
        if (rowsTotal > 0 && rowsReEncrypted === 0 && getEncryptionKeys().length > 1) {
            throw new Error(
                'No user row was encrypted with DB_ENCRYPTION_FALLBACK_KEY; check that DB_ENCRYPTION_KEY holds the new key',
            )
        }
    }

    public async down(): Promise<void> {
        // Nothing to undo: the previous deploy reads rows encrypted with either key.
    }
}
