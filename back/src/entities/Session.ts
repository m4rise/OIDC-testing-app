import {
  Entity,
  PrimaryColumn,
  Column,
  Index,
} from 'typeorm';

@Entity('session')
export class Session {
  @PrimaryColumn({ type: 'varchar', length: 255 })
  sid: string;

  @Column({ type: 'json' })
  sess: Record<string, any>;

  @Column({ type: 'timestamp' })
  @Index()
  expire: Date;
}
