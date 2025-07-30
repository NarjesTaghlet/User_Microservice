import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express'; // Import spécifique
import { join } from 'path';

async function bootstrap() {
  //const app = await NestFactory.create(AppModule);
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  app.useStaticAssets(join(__dirname, '..', 'uploads'), { prefix: '/uploads/' }); // Sert les fichiers

  app.enableCors({
     origin: [
    'http://localhost:4200',  // Dev local
    'https://davbjddcsuel.cloudfront.net',

  ], // Autoriser tous les sous-domaines Ngrok // ✅ Autoriser uniquement le frontend Angular
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization',
    credentials: true, // ✅ Si besoin d'authentification (JWT, Cookies)
  });

  // Express CORS Middleware
const corsMiddleware = (req, res, next) => {
  const allowedOrigins = [
    'https://davbjddcsuel.cloudfront.net',
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Amz-Date, X-Api-Key, X-Amz-Security-Token');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
};

// Use the middleware in all services
app.use(corsMiddleware);

 
  await app.listen(3030);
}
bootstrap();

// main.ts
/*import { AppModule } from './app.module';
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.RMQ,
    options: {
      urls: ['amqp://guest:guest@localhost:5672'],
      queue: 'user_queue',
    },
  });
  await app.listen();
}
bootstrap();
*/
