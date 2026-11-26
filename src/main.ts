import { join } from 'path'

import { bootstrap } from '@doist/ui-extensions-server'

import { AppModule } from './modules/app.module'

bootstrap(AppModule, { useStaticAssets: { path: join(__dirname, '../public') } }).catch(
    (error: unknown) => {
        // If the server can't start, let the process crash so ECS starts a new task. Sentry
        // might not be initialized yet.
        throw error
    },
)
