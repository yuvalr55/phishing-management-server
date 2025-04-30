// src/common/logger.ts
import { Logger } from '@nestjs/common';

/**
 * Global shared logger instance for use across the project.
 */
export const AppLogger = new Logger('AppLogger');
