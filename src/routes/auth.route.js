import express from 'express';
import { getClaims, login, createUser, verifyToken } from '../controllers/auth.controller.js';

const router = express.Router();

router.get('/get-claims', getClaims);
router.get('/test', verifyToken, (req, res) => {
  console.log(req);
  res.json({ message: req.uid });
});
router.post('/login', login);
router.post('/create-user', createUser);

export default router;