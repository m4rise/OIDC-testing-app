declare module 'connect-pg-simple' {
  import { Store } from 'express-session';
  import { Pool } from 'pg';

  interface PgSessionStoreOptions {
    pool?: Pool;
    pgPromise?: any;
    conString?: string;
    tableName?: string;
    schemaName?: string;
    createTableIfMissing?: boolean;
    pruneSessionInterval?: number;
    errorLog?: (error: Error) => void;
  }

  function connectPgSimple(session: any): new (options?: PgSessionStoreOptions) => Store;
  export = connectPgSimple;
}
