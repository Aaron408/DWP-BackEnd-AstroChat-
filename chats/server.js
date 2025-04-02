const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

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
const PORT = process.env.CHATS_PORT || 5002;

// Configurar body-parser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.json());
app.use(cors());

//Colecciones de Firestore
const messagesCollection = db.collection("messages");
const sessionTokensCollection = db.collection("session_tokens");
const usersCollection = db.collection("users_message_app");

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
  res.send("Chats service running with Firebase!");
});

const verifyToken = (allowedTypes) => async (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Acceso denegado. Token no proporcionado." });
  }

  try {
    // Consultar la colección de tokens en Firestore donde el campo "token" sea igual al token proporcionado
    const tokenQuery = await sessionTokensCollection
      .where("token", "==", token)
      .get();

    // Verificar si se encontró algún documento
    if (tokenQuery.empty) {
      return res
        .status(401)
        .json({ message: "Token inválido o no encontrado." });
    }

    // Obtener el primer documento que coincida (asumiendo que los tokens son únicos)
    const tokenDoc = tokenQuery.docs[0];
    const tokenData = tokenDoc.data();

    // Verificar si el token ha expirado
    const now = new Date();
    if (tokenData.expires_date.toDate() < now) {
      return res.status(401).json({ message: "Token ha expirado." });
    }

    // Obtener el usuario asociado al token desde Firestore
    const userDoc = await usersCollection.doc(tokenData.user_id).get();

    if (!userDoc.exists) {
      return res.status(401).json({ message: "Usuario no encontrado." });
    }

    const userData = userDoc.data();

    // Verificar si el tipo de usuario está permitido
    if (!allowedTypes.includes(userData.type)) {
      return res
        .status(403)
        .json({ message: "Acceso denegado. Permisos insuficientes." });
    }

    // Adjuntar la información del usuario al objeto `req`
    req.user = { id: tokenData.user_id, type: userData.type };
    next();
  } catch (error) {
    console.error("Error al verificar el token:", error);
    res.status(500).json({ message: "Error al verificar el token." });
  }
};

//Iniciar servidor
app.listen(PORT, () => {
  console.log(`Chats service running on port ${PORT} with Firebase`);
});
