const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
const axios = require("axios");

require("dotenv").config();

//Instancia de firebase
const serviceAccount = {
  type: process.env.TYPE,
  project_id: process.env.PROJECT_ID,
  private_key_id: process.env.PRIVATE_KEY_ID,
  private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.CLIENT_EMAIL,
  client_id: process.env.CLIENT_ID,
  auth_uri: process.env.AUTH_URI,
  token_uri: process.env.TOKEN_URI,
  auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.CLIENT_CERT_URL,
  universe_domain: process.env.UNIVERSE_DOMAIN,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const app = express();
const PORT = process.env.AUTH_PORT || 5000;

app.use(express.json());
app.use(cors());

//Número de rondas de salt para bcrypt
const SALT_ROUNDS = 10;

//Colecciones de Firestore
const usersCollection = db.collection("users_message_app");
const sessionTokensCollection = db.collection("session_tokens");
const verificationCodesCollection = db.collection("verification_codes");

//Función para verificar la conexión a Firestore
async function testConnection() {
  try {
    await db.collection("test").doc("connection").set({ test: 1 });
    console.log("Connected to Firestore successfully!");
  } catch (error) {
    console.error("Error connecting to Firestore:", error.message);
  }
}

testConnection();

app.get("/", (req, res) => {
  res.send("Auth service running with Firebase!");
});

//----------------LOGIN PAGE-------------------//

const generateToken = (user, expiresIn) => {
  const payload = {
    userId: user.id,
    email: user.email,
  };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
};

const saveToken = async (userId, token, expiresAt) => {
  try {
    await sessionTokensCollection.add({
      user_id: userId,
      token: token,
      expires_date: admin.firestore.Timestamp.fromDate(expiresAt),
    });
  } catch (err) {
    console.error("Error saving token to Firestore", err);
  }
};

//Verificación de credenciales sin generar token
app.post("/api/verify-credentials", async (req, res) => {
  const { email, password } = req.body;

  try {
    //Buscar usuario por email
    const userSnapshot = await usersCollection
      .where("email", "==", email)
      .limit(1)
      .get();

    if (userSnapshot.empty) {
      return res
        .status(200)
        .json({ valid: false, message: "Credenciales inválidas" });
    }

    //Datos del usuario
    const userDoc = userSnapshot.docs[0];
    const user = { id: userDoc.id, ...userDoc.data() };

    //Verificar si el usuario tiene contraseña, para los casos en que son cuentas de google
    if (!user.password) {
      console.error("Usuario sin contraseña:", email);
      return res.status(200).json({
        valid: false,
        isGoogleAccount: true,
        message: "Cuenta de Google",
      });
    }

    //Comparar la contraseña proporcionada con el hash almacenado
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      console.log("Contraseña inválida para usuario:", email);
      return res
        .status(200)
        .json({ valid: false, message: "Credenciales inválidas" });
    }

    //Si las credenciales son correctas devolvemos un true
    return res.status(200).json({ valid: true });
  } catch (err) {
    console.error("Error al verificar credenciales:", err);
    return res
      .status(200)
      .json({ valid: false, message: "Error interno del servidor" });
  }
});

//Generación de token de sesión una vez validado el correo
app.post("/api/login", async (req, res) => {
  const { email, password, rememberMe } = req.body;

  try {
    const userSnapshot = await usersCollection
      .where("email", "==", email)
      .limit(1)
      .get();

    if (userSnapshot.empty) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    //Obtener los datos del usuario
    const userDoc = userSnapshot.docs[0];
    const user = { id: userDoc.id, ...userDoc.data() };

    //Verificar si la contraseña existe en el usuario
    if (!user.password) {
      console.error("Usuario sin contraseña:", email);
      return res.status(402).json({ error: "No password, google account" });
    }

    //Comparar la contraseña proporcionada con el hash almacenado
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      console.log("Contraseña inválida para usuario:", email);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    //Generar el token JWT
    const expiresIn = rememberMe ? "30d" : "1d";
    const token = generateToken(user, expiresIn);

    const expiresAt = new Date(
      Date.now() + (rememberMe ? 30 : 1) * 24 * 60 * 60 * 1000
    );

    await saveToken(user.id, token, expiresAt);

    res.json({
      name: user.name,
      type: user.type,
      email: user.email,
      friendCode: user.friend_code,
      token: token,
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/logout", async (req, res) => {
  const { session_token } = req.body;
  try {
    const tokenSnapshot = await sessionTokensCollection
      .where("token", "==", session_token)
      .get();

    if (!tokenSnapshot.empty) {
      const tokenDoc = tokenSnapshot.docs[0];
      await tokenDoc.ref.delete();
    }

    res.status(200).json({ message: "Token eliminado exitosamente!." });
  } catch (err) {
    console.error("Error al cerrar sesión:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

const verifyGoogleToken = async (token) => {
  const response = await axios.get(
    `https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=${token}`
  );
  return response.data;
};

//Google Auth
app.post("/api/auth/google", async (req, res) => {
  const { idToken } = req.body;

  try {
    const ticket = await verifyGoogleToken(idToken);
    const { sub, name, email, picture, given_name } = ticket;

    //Buscar usuario por Google ID
    let userSnapshot = await usersCollection
      .where("google_id", "==", sub)
      .get();

    if (!userSnapshot.empty) {
      //Si ya existe un usuario con el id de google traido
      const userDoc = userSnapshot.docs[0];
      const user = { id: userDoc.id, ...userDoc.data() };

      //Generar token
      const sessionToken = generateToken(user, "30d");
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      await saveToken(user.id, sessionToken, expiresAt);

      return res.status(200).json({
        name: user.name,
        type: user.type,
        email: user.email,
        friendCode: user.friend_code,
        token: sessionToken,
      });
    } else {
      //Buscar usuario por email
      userSnapshot = await usersCollection.where("email", "==", email).get();

      if (!userSnapshot.empty) {
        const userDoc = userSnapshot.docs[0];
        const userData = userDoc.data();

        //Actualizar usuario con Google ID
        const updateData = {
          google_id: sub,
          profile_picture_url: picture || userData.profile_picture_url,
        };

        await userDoc.ref.update(updateData);

        const user = { id: userDoc.id, ...userData, ...updateData };

        //Generar token
        const sessionToken = generateToken(user, "30d");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await saveToken(user.id, sessionToken, expiresAt);

        return res.status(200).json({
          name: user.name,
          type: user.type,
          email: user.email,
          token: sessionToken,
          friendCode: user.friend_code,
        });
      } else {
        //Generar código de amigo único
        const friendCode = await generateFriendCode();

        //Crear nuevo usuario
        const newUser = {
          google_id: sub,
          name: name,
          email: email,
          email_verified: true,
          profile_picture_url: picture,
          given_name: given_name,
          friend_code: friendCode,
          contacts: [],
          pending_requests: [],
          status: 1,
          type: "mortal",
          created_at: admin.firestore.FieldValue.serverTimestamp(),
        };

        const userRef = await usersCollection.add(newUser);
        const user = { id: userRef.id, ...newUser };

        //Generar token directamente
        const sessionToken = generateToken(user, "30d");
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        await saveToken(user.id, sessionToken, expiresAt);

        return res.status(200).json({
          name: user.name,
          type: user.type,
          email: user.email,
          token: sessionToken,
          friendCode: friendCode,
        });
      }
    }
  } catch (error) {
    console.error("Token verification failed:", error);
    return res.status(200).json({ valid: false, message: "Token inválido" });
  }
});

//---------------Register Page----------------//

//Función para generar un código de amigo único
const generateFriendCode = async () => {
  //Caracteres permitidos: letras mayúsculas, minúsculas y números
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const codeLength = 8;
  let isUnique = false;
  let friendCode = "";

  //Se repite hasta encontrar un código único
  while (!isUnique) {
    //Generar un código aleatorio
    friendCode = "#";
    for (let i = 0; i < codeLength; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      friendCode += characters.charAt(randomIndex);
    }

    //Verificar si el código ya existe en la base de datos
    const codeSnapshot = await usersCollection
      .where("friend_code", "==", friendCode)
      .get();

    //Si no existe usamos este código
    if (codeSnapshot.empty) {
      isUnique = true;
    }
  }

  return friendCode;
};

app.get("/api/checkEmail", async (req, res) => {
  const { email } = req.query;

  try {
    const userSnapshot = await usersCollection
      .where("email", "==", email)
      .get();

    res.status(200).json({ exists: !userSnapshot.empty });
  } catch (err) {
    console.error("Error al verificar el correo:", err);
    res.status(500).json({ message: "Error al verificar el correo" });
  }
});

const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000);
};

//Envio de códigos de verificación
app.post("/api/sendVerificationCode", async (req, res) => {
  const { email, action } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Correo electrónico requerido" });
  }

  if (!action) {
    return res.status(400).json({ message: "Tipo de acción requerido" });
  }

  //Validar que el tipo de acción sea válido
  const validActions = ["login", "registration", "recovery"];
  if (!validActions.includes(action)) {
    return res.status(400).json({ message: "Tipo de acción inválido" });
  }

  try {
    //Para login y recovery, verificar que el usuario exista
    if (action === "login" || action === "recovery") {
      const userSnapshot = await usersCollection
        .where("email", "==", email)
        .get();
      if (userSnapshot.empty) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
    }

    //Para registro, verificar que el usuario no exista
    if (action === "registration") {
      const userSnapshot = await usersCollection
        .where("email", "==", email)
        .get();
      if (!userSnapshot.empty) {
        return res.status(400).json({
          message: "Ya existe una cuenta con este correo electrónico",
        });
      }
    }

    //Generar código de verificación
    const verificationCode = generateVerificationCode();

    //Eliminar códigos anteriores del mismo tipo para prevenir vulnerabilidades
    const oldCodesSnapshot = await verificationCodesCollection
      .where("email", "==", email)
      .where("type", "==", action)
      .get();

    const batch = db.batch();
    oldCodesSnapshot.docs.forEach((doc) => {
      batch.delete(doc.ref);
    });
    await batch.commit();

    //Guardar el código
    const expiresAt = new Date(Date.now() + 3 * 60 * 1000);
    await verificationCodesCollection.add({
      email: email,
      code: verificationCode.toString(),
      expires_at: admin.firestore.Timestamp.fromDate(expiresAt),
      type: action,
    });

    //Configurar envio de correos
    const transporter = nodemailer.createTransport({
      host: "smtp.titan.email",
      port: 465,
      secure: true,
      auth: {
        user: process.env.NODE_EMAIL,
        pass: process.env.NODE_PASSWORD,
      },
    });

    //Personalizar el asunto según el tipo de acción
    let subject = "Código de verificación";
    if (action === "login") {
      subject = "Código de verificación para iniciar sesión";
    } else if (action === "recovery") {
      subject = "Código de recuperación de contraseña";
    } else if (action === "registration") {
      subject = "Código de verificación para registro";
    }

    //Enviar correo
    const mailOptions = {
      from: `"Astro Chat" <${process.env.NODE_EMAIL}>`,
      to: email,
      subject: subject,
      text: `Tu código de verificación para Astro Chat es: ${verificationCode}. Este código expira en 3 minutos.`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({
      message: "Código de verificación enviado correctamente",
    });
  } catch (error) {
    console.error("Error en el proceso de envío de verificación:", error);
    res.status(500).json({
      message: "Hubo un error al procesar la solicitud de verificación.",
      error: error.message,
    });
  }
});

//Verificación de códigos
app.post("/api/verify-code", async (req, res) => {
  const { email, code, action } = req.body;

  if (!email || !code || !action) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  try {
    const codeSnapshot = await verificationCodesCollection
      .where("email", "==", email)
      .where("code", "==", code)
      .where("type", "==", action)
      .get();

    if (codeSnapshot.empty) {
      return res.json({ isValid: false, message: "Código inválido" });
    }

    const codeDoc = codeSnapshot.docs[0];
    const codeData = codeDoc.data();

    //Verificar si el código ha expirado
    if (codeData.expires_at.toDate() < new Date()) {
      return res.json({ isValid: false, message: "Código expirado" });
    }

    //Si el código es válido y no ha expirado
    res.json({ isValid: true });
  } catch (error) {
    console.error("Error al verificar el código:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.post("/api/register", async (req, res) => {
  const { nombre, email, password } = req.body;

  if (!nombre || !email || !password) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  try {
    //Validar si el usuario ya existe
    const userSnapshot = await usersCollection
      .where("email", "==", email)
      .get();

    if (!userSnapshot.empty) {
      return res.status(400).json({ error: "El usuario ya existe" });
    }

    //Generar el código de amigo unico
    const friendCode = await generateFriendCode();

    //Hashear contraseña
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = {
      name: nombre,
      email: email,
      password: hashedPassword,
      friend_code: friendCode,
      contacts: [],
      pending_requests: [],
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      type: "mortal",
      status: 1,
    };

    const userRef = await usersCollection.add(newUser);

    //Eliminar códigos de verificación
    const codeSnapshot = await verificationCodesCollection
      .where("email", "==", email)
      .where("type", "==", "registration")
      .get();

    const batch = db.batch();
    codeSnapshot.docs.forEach((doc) => {
      batch.delete(doc.ref);
    });
    await batch.commit();

    res.status(201).json({ success: true, userId: userRef.id, friendCode });
  } catch (error) {
    console.error("Error al registrar el usuario:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// --------------- PASSWORD RECOVERY PAGE ---------------- //

app.post("/api/update-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({
      message: "Correo electrónico y nueva contraseña son requeridos",
    });
  }

  try {
    // Buscar el usuario por correo electrónico
    const userSnapshot = await usersCollection
      .where("email", "==", email)
      .get();

    if (userSnapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // Obtener el documento del usuario
    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();

    // Verificar si es una cuenta de Google
    if (userData.isGoogleAccount) {
      return res.status(400).json({
        message:
          "No se puede cambiar la contraseña de una cuenta de Google. Por favor, utiliza el inicio de sesión con Google.",
      });
    }

    // Validar requisitos de contraseña
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        message:
          "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial",
      });
    }

    // Generar hash de la nueva contraseña
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar la contraseña en la base de datos
    await userDoc.ref.update({
      password: hashedPassword,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Eliminar todas las sesiones activas del usuario para forzar un nuevo inicio de sesión
    const sessionTokensSnapshot = await db
      .collection("session_tokens")
      .where("user_id", "==", userDoc.id)
      .get();

    const batch = db.batch();
    sessionTokensSnapshot.docs.forEach((doc) => {
      batch.delete(doc.ref);
    });
    await batch.commit();

    res.status(200).json({ message: "Contraseña actualizada correctamente" });
  } catch (error) {
    console.error("Error al actualizar la contraseña:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

//Iniciar servidor
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT} with Firebase`);
});
