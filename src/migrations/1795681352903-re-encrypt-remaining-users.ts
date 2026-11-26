import { Logger } from '@nestjs/common'

import { reEncryptUsers } from '../utils/re-encrypt-users'

import type { MigrationInterface, QueryRunner } from 'typeorm'

/**
 * Third of three deploys rotating the database key after the November 2026 incident. While the
 * previous deploy rolled out, tasks of the deploy before it could still write rows with the old
 * key after its migration had run. This re-encrypts any such row with `DB_ENCRYPTION_KEY`, so
 * that afterwards `DB_ENCRYPTION_FALLBACK_KEY` and the old key can be removed.
 *
 * Usually it finds nothing to do. Safe to run any number of times.
 */
export class ReEncryptRemainingUsers1795681352903 implements MigrationInterface {
    name = 'ReEncryptRemainingUsers1795681352903'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await reEncryptUsers(queryRunner, new Logger(ReEncryptRemainingUsers1795681352903.name))
    }

    public async down(): Promise<void> {
        // Nothing to undo: the previous deploy reads rows encrypted with either key.
    }
}
