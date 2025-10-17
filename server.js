const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS MEJORADO - Permitir todos los orígenes en producción
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false
}));

// Helmet con configuración menos restrictiva
app.use(
  helmet({
    contentSecurityPolicy: false, // Desactivar CSP temporalmente
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Demasiadas solicitudes, intenta más tarde",
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api/", limiter);

const cotizacionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: "Límite de cotizaciones excedido, espera un minuto",
});

app.use("/api/cotizar", cotizacionLimiter);

// Middleware para logs
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
  next();
});

// Middleware para parsear JSON - IMPORTANTE
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, "public")));

// Credenciales del API
const API_BASE_URL = "https://pagoalafija.co/api/public/";
const API_KEY = "4aeaa7cc5f23610d9a1b3bb303389262";
const SECRET_KEY = "$2y$10$TEMMkRGqvJS280rO87GSgO9eHzZ4l9IXeJhsU/8HnmSGSOyhGmg.C";
const AUTH_TOKEN = "f575bd8fc63df8e07c5ec3a5dea17026a978f51614838041a14c408f4a3a678c";
const COD_PRODUCTO = 63;

let currentToken = AUTH_TOKEN;
let tokenGeneratedAt = new Date();
let isUsingFixedToken = true;

console.log("🔧 Configuración iniciada:");
console.log("- API URL:", API_BASE_URL);
console.log("- Puerto:", PORT);

// Función para generar nuevo token
async function generateNewToken() {
  try {
    console.log("\n🔑 Generando nuevo token...");
    
    const tokenEndpoints = ["token", "auth/token", "authenticate", "login"];

    for (const endpoint of tokenEndpoints) {
      const tokenUrl = API_BASE_URL + endpoint;
      
      try {
        let response = await axios.get(tokenUrl, {
          headers: {
            secretkey: SECRET_KEY,
            apikey: API_KEY,
            "Content-Type": "application/json",
          },
          timeout: 10000,
          validateStatus: () => true,
        });

        if (response.status === 200 && response.data) {
          const token = response.data.AuthToken || response.data.authToken || response.data.token;
          if (token) {
            console.log("✅ Token generado exitosamente");
            currentToken = token;
            tokenGeneratedAt = new Date();
            isUsingFixedToken = false;
            return token;
          }
        }

        response = await axios.post(
          tokenUrl,
          { secretkey: SECRET_KEY, apikey: API_KEY },
          {
            headers: { "Content-Type": "application/json" },
            timeout: 10000,
            validateStatus: () => true,
          }
        );

        if (response.status === 200 && response.data) {
          const token = response.data.AuthToken || response.data.authToken || response.data.token;
          if (token) {
            console.log("✅ Token generado con POST");
            currentToken = token;
            tokenGeneratedAt = new Date();
            isUsingFixedToken = false;
            return token;
          }
        }
      } catch (error) {
        console.log(`Error en ${endpoint}:`, error.message);
      }
    }

    console.log("⚠️ Usando token fijo");
    return AUTH_TOKEN;
  } catch (error) {
    console.error("❌ Error generando token:", error.message);
    return AUTH_TOKEN;
  }
}

async function getValidToken() {
  if (isUsingFixedToken && new Date() - tokenGeneratedAt > 3600000) {
    return await generateNewToken();
  }
  return currentToken;
}

// ENDPOINT PRINCIPAL: Cotizar SOAT
app.post("/api/cotizar", async (req, res) => {
  try {
    console.log("\n=== 🚀 NUEVA COTIZACIÓN ===");
    console.log("Body recibido:", req.body);

    const { placa, documentType, documentNumber, nombre, email, telefono } = req.body;

    if (!placa || !documentType || !documentNumber) {
      return res.status(400).json({
        success: false,
        message: "Faltan datos requeridos: placa, documentType y documentNumber",
      });
    }

    const token = await getValidToken();
    const cotizacionUrl = `${API_BASE_URL}soat`;
    const params = {
      numPlaca: placa.toUpperCase(),
      codProducto: COD_PRODUCTO,
      codTipdoc: getDocumentTypeCode(documentType),
      numDocumento: documentNumber,
    };

    console.log("📡 URL:", cotizacionUrl);
    console.log("📡 Params:", params);

    const headerStrategies = [
      { name: "Auth-Token", headers: { "Auth-Token": token } },
      { name: "Authorization Bearer", headers: { Authorization: `Bearer ${token}` } },
      { name: "AuthToken", headers: { AuthToken: token } },
    ];

    let cotizacionResponse;
    let lastError;

    for (const strategy of headerStrategies) {
      try {
        cotizacionResponse = await axios.get(cotizacionUrl, {
          headers: {
            ...strategy.headers,
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          params: params,
          timeout: 15000,
        });

        console.log(`✅ Éxito con strategy: ${strategy.name}`);
        break;
      } catch (error) {
        console.log(`❌ Falló strategy: ${strategy.name}`);
        lastError = error;

        if (error.response?.status === 401 && isUsingFixedToken) {
          const newToken = await generateNewToken();
          strategy.headers[Object.keys(strategy.headers)[0]] = newToken;
          
          try {
            cotizacionResponse = await axios.get(cotizacionUrl, {
              headers: {
                ...strategy.headers,
                "Content-Type": "application/json",
                Accept: "application/json",
              },
              params: params,
              timeout: 15000,
            });
            console.log("✅ Éxito con nuevo token");
            break;
          } catch (retryError) {
            lastError = retryError;
          }
        }
      }
    }

    if (!cotizacionResponse) {
      throw lastError;
    }

    console.log("✅ ¡COTIZACIÓN EXITOSA!");

    const cotizacionData = cotizacionResponse.data;
    const precio = extractPrice(cotizacionData);
    const vehicleInfo = extractVehicleInfo(cotizacionData);
    const dates = extractDates(cotizacionData);

    const responseData = {
      success: true,
      placa: placa.toUpperCase(),
      precio: precio,
      tipoVehiculo: vehicleInfo.tipo,
      marca: vehicleInfo.marca,
      modelo: vehicleInfo.modelo,
      cilindraje: vehicleInfo.cilindraje,
      inicioVigencia: dates.inicio,
      finVigencia: dates.fin,
      tomador: {
        nombre: nombre || cotizacionData.nombreTomador || "N/A",
        documento: documentNumber,
        tipoDocumento: documentType,
        email: email || cotizacionData.email || "N/A",
        telefono: telefono || cotizacionData.telefono || "N/A",
      },
      cuentasBancarias: [
        {
          banco: "Bancolombia",
          numero: "30685175725",
          tipo: "Cuenta de Ahorros",
          titular: "Otto Rafael Badel",
        },
        {
          banco: "Nequi",
          numero: "3128433999",
          tipo: "Cuenta Nequi",
        },
      ],
      instruccionesPago: [
        "Realiza la transferencia por el valor exacto",
        "Envía el comprobante por WhatsApp: 3128433999",
        "Incluye la placa del vehículo",
        "Recibirás tu SOAT en 24 horas",
      ],
      metadata: {
        timestamp: new Date().toISOString(),
        numeroReferencia: `SOAT-${placa.toUpperCase()}-${Date.now()}`,
      },
      debug: {
        originalResponse: cotizacionData,
        extractedPrice: precio,
        vehicleInfo: vehicleInfo,
      },
    };

    res.json(responseData);
  } catch (error) {
    console.error("❌ ERROR:", error.message);
    
    res.status(error.response?.status || 500).json({
      success: false,
      message: error.response?.data?.message || error.message || "Error al procesar la cotización",
      error: error.response?.data,
    });
  }
});

// Test endpoint
app.get("/api/test", async (req, res) => {
  try {
    const token = await getValidToken();
    
    res.json({
      success: true,
      message: "API funcionando correctamente",
      timestamp: new Date().toISOString(),
      token: token.substring(0, 20) + "...",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Info endpoint
app.get("/api/info", (req, res) => {
  res.json({
    status: "READY",
    server: "Badelco SOAT API",
    timestamp: new Date().toISOString(),
    endpoints: {
      test: "GET /api/test",
      cotizar: "POST /api/cotizar",
      info: "GET /api/info",
    },
  });
});

// Página principal
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health check para Railway
app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK" });
});

// Funciones auxiliares
function extractPrice(data) {
  const priceFields = [
    "valor", "precio", "prima", "precioTotal", "total",
    "costo", "valorTotal", "primaNeta", "valorPrima",
  ];

  for (const field of priceFields) {
    if (data[field] !== undefined && data[field] !== null) {
      const value = parseFloat(data[field]);
      if (!isNaN(value) && value > 0) {
        return value;
      }
    }
    if (data.data && data.data[field] !== undefined) {
      const value = parseFloat(data.data[field]);
      if (!isNaN(value) && value > 0) {
        return value;
      }
    }
  }
  return 0;
}

function extractVehicleInfo(data) {
  return {
    tipo: data.tipoVehiculo || data.claseVehiculo || "AUTOMOVIL",
    marca: data.marca || data.marcaVehiculo || "N/A",
    modelo: data.modelo || data.modeloVehiculo || "N/A",
    cilindraje: data.cilindraje || data.cilindrajeVehiculo || "N/A",
  };
}

function extractDates(data) {
  const now = new Date();
  const nextYear = new Date(now);
  nextYear.setFullYear(nextYear.getFullYear() + 1);

  return {
    inicio: data.inicioVigencia || data.fechaInicio || now.toISOString(),
    fin: data.finVigencia || data.fechaFin || nextYear.toISOString(),
  };
}

function getDocumentTypeCode(documentType) {
  const codes = { CC: 1, CE: 2, NIT: 3, PA: 4 };
  return codes[documentType] || 1;
}

// CRÍTICO: Escuchar en 0.0.0.0 para Railway
app.listen(PORT, "0.0.0.0", () => {
  console.log("\n🚀 ================================");
  console.log("🌟 BADELCO SOAT API - READY");
  console.log("🚀 ================================");
  console.log(`📡 Puerto: ${PORT}`);
  console.log(`🌍 Host: 0.0.0.0`);
  console.log(`🔧 Modo: ${process.env.NODE_ENV || "production"}`);
  console.log("🚀 ================================\n");
});

// Manejo de errores no capturados
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});