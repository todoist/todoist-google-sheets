import { Column, Entity, Index, PrimaryGeneratedColumn } from 'typeorm'

import { getUserEncryptionTransformer } from '../utils/rotating-encryption-transformer'

import type { User as UserBase } from '@doist/ui-extensions-server'

const encryptionTransformer = getUserEncryptionTransformer()

/**
 * The same table and columns as the `User` entity in `@doist/ui-extensions-server`, but the
 * encrypted columns use a transformer that can also decrypt with `DB_ENCRYPTION_FALLBACK_KEY`, so
 * the app reads rows encrypted with either key while `DB_ENCRYPTION_KEY` is rotated.
 *
 * It's a copy rather than a subclass because TypeORM keeps a parent's column over a child's
 * redeclaration of it. The library's `UserDatabaseService` still works with it: Nest looks up the
 * repository by the class name, `User`.
 */
@Entity()
export class User implements UserBase {
    @PrimaryGeneratedColumn()
    id?: number

    @Column()
    @Index()
    twistId!: number

    @Column({ type: 'longtext', transformer: encryptionTransformer })
    authToken!: string

    @Column({ type: 'longtext', transformer: encryptionTransformer, nullable: true })
    refreshToken?: string

    @Column({ nullable: true })
    tokenExpiresAt?: Date

    @Column()
    externalUserId!: string

    @Column({ transformer: encryptionTransformer, nullable: true })
    emailAddress?: string

    @Column({ transformer: encryptionTransformer, nullable: true })
    name?: string

    set(data: Parameters<UserBase['set']>[0]): void {
        const {
            authToken,
            emailAddress,
            externalUserId,
            name,
            refreshToken,
            tokenExpiresAt,
            twistId,
        } = data
        this.twistId = twistId
        this.authToken = authToken
        this.emailAddress = emailAddress
        this.refreshToken = refreshToken
        this.externalUserId = externalUserId
        this.name = name
        this.tokenExpiresAt = tokenExpiresAt
    }

    update(_data: Parameters<UserBase['update']>[0]): void {
        // Same as the library: nothing to update beyond what `set` covers.
    }
}

export function userFrom(props: {
    id?: number
    twistId: number
    authToken: string
    refreshToken?: string
    tokenExpiresAt?: Date
    externalUserId: string
    emailAddress?: string
    name?: string
}): User {
    const user = new User()
    Object.assign(user, props)
    return user
}
