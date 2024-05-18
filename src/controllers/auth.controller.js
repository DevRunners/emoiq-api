import {
  admin,
  auth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword
} from '../config/firebase.js';

async function getUserRecord(uid) {
  const userRecord = await admin.auth().getUser(uid);
  return userRecord;
}

export const verifyToken = async (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    res.status(401).json({ error: 'Missing Authorization header' });
  }

  const idToken = authHeader.split(' ')[1];

  if (!idToken) {
    res.status(401).json({ error: 'Missing identification token' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid } = decodedToken;
    req.uid = uid;

    next();
  } catch (err) {
    res.status(401).json({ error: err });
  }
};

export const setClaimAdmin = (req, res) => {
  admin.auth()
    .setCustomUserClaims(req.body.uid, {
      type: 'administrator',
    })
    .then(() => res.json({ message: 'done' }));
};

export const setClaimManager = (req, res) => {
  admin.auth()
    .setCustomUserClaims(req.body.uid, {
      type: 'manager',
    })
    .then(() => res.json({ message: 'done' }));
};

export const getClaims = async (req, res) => {
  const userRecord = await getUserRecord(req.body.uid);
  res.json(userRecord);
};

export const login = (req, res) => {
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
};

export const createUser = (req, res) => {
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
          userCredential
        }
      });
    })
    .catch(error => {
      const errorMessage = error.message || 'An error occurred while registering user';
      res.status(500).json({ error: errorMessage });
    });
};
