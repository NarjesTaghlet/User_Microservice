import { createLogger, format, transports } from 'winston';

const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`),
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/user-service.log' }),
  ],
});

export default logger;