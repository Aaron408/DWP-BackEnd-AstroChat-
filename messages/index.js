const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const { createServer } = require("http");
const { Server } = require("socket.io");

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
const httpServer = createServer(app); // Crea un servidor HTTP
const io = new Server(httpServer, {
  // Crea el servidor Socket.io
  cors: {
    origin: "*", // Ajusta según tu frontend
    methods: ["GET", "POST"],
  },
});

const PORT = process.env.MESSAGES_PORT || 5001;

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
  res.send("Messages service running with Firebase!");
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

io.use((socket, next) => {
  const token = socket.handshake.auth.token;

  if (!token) {
    return next(new Error("Authentication error"));
  }

  // Verificación simplificada del token - deberías usar tu lógica de verifyToken
  sessionTokensCollection
    .where("token", "==", token)
    .get()
    .then((tokenQuery) => {
      if (tokenQuery.empty) {
        return next(new Error("Invalid token"));
      }

      const tokenData = tokenQuery.docs[0].data();
      const now = new Date();

      if (tokenData.expires_date.toDate() < now) {
        return next(new Error("Token expired"));
      }

      // Adjunta la información del usuario al socket
      socket.userId = tokenData.user_id;
      next();
    })
    .catch((error) => next(error));
});

// Manejo de conexiones WebSocket
io.on("connection", (socket) => {
  console.log("New WebSocket connection:", socket.userId);

  // Unirse a la sala del usuario para mensajes privados
  socket.join(socket.userId);

  // Manejar unirse a salas de chat específicas
  socket.on("joinChat", (chatId) => {
    socket.join(chatId);
    console.log(`User ${socket.userId} joined chat ${chatId}`);
  });

  socket.on("leaveChat", (chatId) => {
    socket.leave(chatId);
    console.log(`User ${socket.userId} left chat ${chatId}`);
  });

  socket.on("disconnect", () => {
    console.log(`User ${socket.userId} disconnected`);
  });
});

app.get("/messages/:contactId", verifyToken(["mortal"]), async (req, res) => {
  const userId = req.user.id;
  const { contactId } = req.params;
  const { limit = 50, before } = req.query;

  try {
    // Solución temporal: Usar una consulta más simple que no requiere índice compuesto
    // En lugar de filtrar por array-contains y ordenar por timestamp
    const messagesSnapshot = await messagesCollection
      .where("participants", "array-contains", userId)
      .get();

    if (messagesSnapshot.empty) {
      return res.status(200).json({ messages: [] });
    }

    // Filtrar mensajes para incluir solo los que son entre el usuario actual y el contacto seleccionado
    let messages = [];
    messagesSnapshot.forEach((doc) => {
      const messageData = doc.data();
      if (
        (messageData.senderId === userId &&
          messageData.receiverId === contactId) ||
        (messageData.senderId === contactId &&
          messageData.receiverId === userId)
      ) {
        messages.push({
          id: doc.id,
          ...messageData,
          timestamp: messageData.timestamp
            ? messageData.timestamp.toDate().toISOString()
            : new Date().toISOString(),
        });
      }
    });

    // Ordenar mensajes manualmente por timestamp (más antiguos primero)
    messages = messages.sort((a, b) => {
      return new Date(a.timestamp) - new Date(b.timestamp);
    });

    // Aplicar límite después de filtrar y ordenar
    if (before) {
      const beforeTimestamp = new Date(before);
      messages = messages.filter(
        (msg) => new Date(msg.timestamp) < beforeTimestamp
      );
    }

    messages = messages.slice(0, Number.parseInt(limit));

    // Marcar mensajes como leídos si el usuario actual es el receptor
    const batch = db.batch();
    messagesSnapshot.forEach((doc) => {
      const messageData = doc.data();
      if (
        messageData.receiverId === userId &&
        messageData.senderId === contactId &&
        !messageData.read
      ) {
        batch.update(doc.ref, { read: true });
      }
    });
    await batch.commit();

    console.log("Mensajes obtenidos:", messages);

    res.status(200).json({ messages });
  } catch (error) {
    console.error("Error al obtener mensajes:", error);
    res.status(500).json({
      message: "Error interno del servidor",
      error: error.message,
      indexUrl:
        error.details && error.details.includes("index") ? error.details : null,
    });
  }
});

// Endpoint para enviar un nuevo mensaje
app.post("/send-message", verifyToken(["mortal"]), async (req, res) => {
  const senderId = req.user.id;
  const { receiverId, content } = req.body;

  if (!receiverId || !content) {
    return res
      .status(400)
      .json({ message: "Destinatario y contenido son requeridos" });
  }

  try {
    // Verificar que el destinatario existe y es un contacto del remitente
    const senderDoc = await usersCollection.doc(senderId).get();
    if (!senderDoc.exists) {
      return res
        .status(404)
        .json({ message: "Usuario remitente no encontrado" });
    }

    const senderData = senderDoc.data();
    if (!senderData.contacts || !senderData.contacts.includes(receiverId)) {
      return res
        .status(403)
        .json({ message: "El destinatario no es un contacto del remitente" });
    }

    // Crear el nuevo mensaje
    const newMessage = {
      senderId,
      receiverId,
      content,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      read: false,
      participants: [senderId, receiverId],
    };

    const messageRef = await messagesCollection.add(newMessage);

    // Actualizar el último mensaje en ambos usuarios
    await usersCollection.doc(senderId).update({
      lastMessageWith: {
        [receiverId]: {
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          content,
        },
      },
    });

    await usersCollection.doc(receiverId).update({
      lastMessageWith: {
        [senderId]: {
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          content,
          unread: true,
        },
      },
    });

    res.status(201).json({
      message: "Mensaje enviado exitosamente",
      messageId: messageRef.id,
    });
  } catch (error) {
    console.error("Error al enviar mensaje:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// Endpoint para marcar mensajes como leídos
app.post("/mark-read/:contactId", verifyToken(["mortal"]), async (req, res) => {
  const userId = req.user.id;
  const { contactId } = req.params;

  try {
    // Buscar todos los mensajes no leídos enviados por el contacto al usuario
    const unreadMessagesQuery = await messagesCollection
      .where("receiverId", "==", userId)
      .where("senderId", "==", contactId)
      .where("read", "==", false)
      .get();

    if (unreadMessagesQuery.empty) {
      return res.status(200).json({ message: "No hay mensajes sin leer" });
    }

    // Marcar todos los mensajes como leídos
    const batch = db.batch();
    unreadMessagesQuery.forEach((doc) => {
      batch.update(doc.ref, { read: true });
    });

    // Actualizar el estado de lectura en el usuario
    await usersCollection.doc(userId).update({
      [`lastMessageWith.${contactId}.unread`]: false,
    });

    await batch.commit();

    res.status(200).json({ message: "Mensajes marcados como leídos" });
  } catch (error) {
    console.error("Error al marcar mensajes como leídos:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// Cambia app.listen por httpServer.listen para manejar tanto HTTP como WebSocket
httpServer.listen(PORT, () => {
  console.log(
    `Messages service running on port ${PORT} with WebSocket support`
  );
});
