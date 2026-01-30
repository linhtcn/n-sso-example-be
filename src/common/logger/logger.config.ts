import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';

const logLevel = process.env.LOG_LEVEL || 'info';
const isProduction = process.env.NODE_ENV === 'production';

export const winstonConfig = WinstonModule.createLogger({
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.ms(),
        isProduction
          ? winston.format.json()
          : winston.format.combine(
              winston.format.colorize(),
              winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
                return `${timestamp} [${context || 'Application'}] ${level}: ${message} ${
                  Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
                }`;
              }),
            ),
      ),
    }),
    ...(isProduction
      ? [
          new winston.transports.File({
            filename: 'logs/error.log',
            level: 'error',
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
          }),
          new winston.transports.File({
            filename: 'logs/combined.log',
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
          }),
        ]
      : []),
  ],
  level: logLevel,
});
