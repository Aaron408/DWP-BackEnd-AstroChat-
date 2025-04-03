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
const PORT = process.env.CONTACTS_PORT || 5003;

//Configurar body-parser
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
  res.send("Contacts service running with Firebase!");
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

// ----------------------------- MENSAJES DE CHAT ----------------------------- //

app.post("/friend-request", verifyToken(["mortal"]), async (req, res) => {
  const { friendCode } = req.body;
  const userId = req.user.id;

  try {
    // Obtener datos del usuario que envía la solicitud
    const senderDoc = await usersCollection.doc(userId).get();

    if (!senderDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const sender = { id: senderDoc.id, ...senderDoc.data() };

    // Buscar usuario por código de amigo
    const receiverSnapshot = await usersCollection
      .where("friend_code", "==", friendCode)
      .get();

    if (receiverSnapshot.empty) {
      return res.status(404).json({ message: "Código de amigo no encontrado" });
    }

    const receiverDoc = receiverSnapshot.docs[0];
    const receiver = { id: receiverDoc.id, ...receiverDoc.data() };

    // Verificar que no se esté enviando solicitud a sí mismo
    if (sender.id === receiver.id) {
      return res
        .status(400)
        .json({ message: "No puedes enviarte una solicitud a ti mismo" });
    }

    // Verificar si ya son contactos
    const senderContacts = sender.contacts || [];
    if (senderContacts.includes(receiver.id)) {
      return res
        .status(400)
        .json({ message: "Este usuario ya es tu contacto" });
    }

    // Verificar si ya hay una solicitud pendiente
    const pendingRequests = receiver.pending_requests || [];
    if (pendingRequests.some((req) => req.senderId === sender.id)) {
      return res
        .status(400)
        .json({ message: "Ya has enviado una solicitud a este usuario" });
    }

    // Añadir solicitud a las solicitudes pendientes del receptor
    const newRequest = {
      senderId: sender.id,
      senderName: sender.name,
      senderAvatar: sender.profile_picture_url || "",
      timestamp: new Date().toISOString(),
    };

    await receiverDoc.ref.update({
      pending_requests: admin.firestore.FieldValue.arrayUnion(newRequest),
    });

    res.status(200).json({ message: "Solicitud de amistad enviada" });
  } catch (error) {
    console.error("Error al enviar solicitud de amistad:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

app.post(
  "/accept-friend-request",
  verifyToken(["mortal"]),
  async (req, res) => {
    const { senderId } = req.body;
    const userId = req.user.id;

    try {
      // Obtener datos del usuario que acepta la solicitud
      const receiverDoc = await usersCollection.doc(userId).get();

      if (!receiverDoc.exists) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }

      const receiver = receiverDoc.data();

      // Verificar que la solicitud exista
      const pendingRequests = receiver.pending_requests || [];
      const requestIndex = pendingRequests.findIndex(
        (req) => req.senderId === senderId
      );

      if (requestIndex === -1) {
        return res.status(404).json({ message: "Solicitud no encontrada" });
      }

      // Obtener datos del remitente
      const senderDoc = await usersCollection.doc(senderId).get();

      if (!senderDoc.exists) {
        return res.status(404).json({ message: "Remitente no encontrado" });
      }

      // Eliminar la solicitud de las pendientes
      const updatedRequests = [...pendingRequests];
      updatedRequests.splice(requestIndex, 1);

      // Actualizar contactos de ambos usuarios
      const batch = db.batch();

      // Añadir al remitente como contacto del receptor
      batch.update(receiverDoc.ref, {
        contacts: admin.firestore.FieldValue.arrayUnion(senderId),
        pending_requests: updatedRequests,
      });

      // Añadir al receptor como contacto del remitente
      batch.update(senderDoc.ref, {
        contacts: admin.firestore.FieldValue.arrayUnion(userId),
      });

      await batch.commit();

      res.status(200).json({ message: "Solicitud aceptada" });
    } catch (error) {
      console.error("Error al aceptar solicitud de amistad:", error);
      res.status(500).json({ message: "Error interno del servidor" });
    }
  }
);

app.post(
  "/reject-friend-request",
  verifyToken(["mortal", "admin"]),
  async (req, res) => {
    const { senderId } = req.body;
    const userId = req.user.id;

    try {
      // Obtener datos del usuario
      const userDoc = await usersCollection.doc(userId).get();

      if (!userDoc.exists) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }

      const user = userDoc.data();

      // Verificar que la solicitud exista
      const pendingRequests = user.pending_requests || [];
      const requestIndex = pendingRequests.findIndex(
        (req) => req.senderId === senderId
      );

      if (requestIndex === -1) {
        return res.status(404).json({ message: "Solicitud no encontrada" });
      }

      // Eliminar la solicitud de las pendientes
      const updatedRequests = [...pendingRequests];
      updatedRequests.splice(requestIndex, 1);

      // Actualizar el documento del usuario
      await userDoc.ref.update({
        pending_requests: updatedRequests,
      });

      res.status(200).json({ message: "Solicitud rechazada" });
    } catch (error) {
      console.error("Error al rechazar solicitud de amistad:", error);
      res.status(500).json({ message: "Error interno del servidor" });
    }
  }
);

// Endpoint para obtener solicitudes de amistad pendientes
app.get("/friend-requests", verifyToken(["mortal"]), async (req, res) => {
  const userId = req.user.id;

  try {
    // Obtener datos del usuario
    const userDoc = await usersCollection.doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userDoc.data();

    // Obtener solicitudes pendientes
    const pendingRequests = user.pending_requests || [];

    res.status(200).json({ requests: pendingRequests });
  } catch (error) {
    console.error("Error al obtener solicitudes de amistad:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

app.get("/contacts", verifyToken(["mortal"]), async (req, res) => {
  const userId = req.user.id;

  try {
    // Obtener documento del usuario
    const userDoc = await usersCollection.doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userData = userDoc.data();
    const contactIds = userData.contacts || [];

    // Si el usuario no tiene contactos
    if (contactIds.length === 0) {
      return res.status(200).json({ contacts: [] });
    }

    // Obtener detalles de los contactos
    const contactsPromises = contactIds.map(async (contactId) => {
      const contactDoc = await usersCollection.doc(contactId).get();

      if (!contactDoc.exists) {
        return null;
      }

      const contactData = contactDoc.data();

      // Obtener información del último mensaje y mensajes no leídos
      let lastMessage = "";
      let timestamp = "";
      let hasUnreadMessages = false;
      let unreadCount = 0;

      // Verificar si hay información de último mensaje en el usuario
      const lastMessageData =
        userData.lastMessageWith && userData.lastMessageWith[contactId];

      if (lastMessageData) {
        lastMessage = lastMessageData.content || "";
        timestamp = lastMessageData.timestamp
          ? lastMessageData.timestamp.toDate().toISOString()
          : "";
        hasUnreadMessages = lastMessageData.unread || false;
      }

      // Contar mensajes no leídos
      if (hasUnreadMessages) {
        const unreadMessagesQuery = await messagesCollection
          .where("receiverId", "==", userId)
          .where("senderId", "==", contactId)
          .where("read", "==", false)
          .get();

        unreadCount = unreadMessagesQuery.size;
      }

      // Formatear la fecha para mostrar
      let formattedTimestamp = "";
      if (timestamp) {
        const messageDate = new Date(timestamp);
        const today = new Date();
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);

        if (messageDate.toDateString() === today.toDateString()) {
          // Si es hoy, mostrar la hora
          formattedTimestamp = messageDate.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          });
        } else if (messageDate.toDateString() === yesterday.toDateString()) {
          // Si fue ayer
          formattedTimestamp = "Ayer";
        } else {
          // Otro día
          formattedTimestamp = messageDate.toLocaleDateString();
        }
      }

      return {
        id: contactId,
        name: contactData.name,
        avatar: contactData.profile_picture_url || null,
        lastMessage: lastMessage || "No hay mensajes aún",
        timestamp: formattedTimestamp,
        rawTimestamp: timestamp, // Para ordenar
        hasUnreadMessages,
        unreadCount,
      };
    });

    const contacts = (await Promise.all(contactsPromises)).filter(
      (contact) => contact !== null
    );

    res.status(200).json({ contacts });
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

//Iniciar servidor
app.listen(PORT, () => {
  console.log(`Contacts service running on port ${PORT} with Firebase`);
});
