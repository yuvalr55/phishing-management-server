import { Injectable } from '@nestjs/common';

/** Service providing basic application functionality. */
@Injectable()
export class AppService {
  /** Returns a simple greeting message. */
  getHello(): string {
    return 'Hello World!';
  }
}
