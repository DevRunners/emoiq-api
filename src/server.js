import express from 'express';
import {
  admin,
  auth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword
} from './config/firebase.js';

const app = express();
app.use(express.json());

async function getUserRecord(uid) {
  const userRecord = await admin.auth().getUser(uid);
  return userRecord;
}

app.get('/set-admin', (req, res) => {
  admin.auth()
    .setCustomUserClaims(req.body.uid, {
      type: 'administrator',
    })
    .then(() => res.json({ message: 'done' }));
});

app.get('/set-manager', (req, res) => {
  admin.auth()
    .setCustomUserClaims(req.body.uid, {
      type: 'manager',
    })
    .then(() => res.json({ message: 'done' }));
});

app.get('/get-claims', async (req, res) => {
  const userRecord = await getUserRecord(req.body.uid);
  res.json(userRecord);
});

app.post('/login', (req, res) => {
  signInWithEmailAndPassword(auth, req.body.email, req.body.password)
    .then(() => auth.currentUser.getIdToken(true))
    .then(async idToken => {
      const user = await getUserRecord(auth.currentUser.uid);
      res.status(200).json({
        message: 'Login successfully',
        data: {
          token: idToken,
          role: user.customClaims.type || null
        }
      });
    }).catch(error => {
      res.status(500).json({ error });
    });
});

app.post('/create-user', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).json({
      email: 'Email is required',
      password: 'Password is required',
    });
  }

  createUserWithEmailAndPassword(auth, email, password)
    .then(userCredential => {
      res.status(201).json({
        message: 'Verification email sent! User created successfully!',
        data: {
          currentUser: auth.currentUser,
          userCredential
        }
      });
    })
    .catch(error => {
      const errorMessage = error.message || 'An error occurred while registering user';
      res.status(500).json({ error: errorMessage });
    });
});

export default app;