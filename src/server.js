import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

import { setEnvVariables } from './encrypt.js';
import authRouter from './routes/auth.route.js';

setEnvVariables(); // Ejecuta la función para configurar las variables de entorno

const app = express();

app.use(cors());
app.use(helmet());
app.use(express.json());

app.use('/api', authRouter);

export default app;